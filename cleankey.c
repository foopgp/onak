/*
 * cleankey.c - Routines to look for common key problems and clean them up.
 *
 * Copyright 2004,2012 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "build-config.h"
#include "cleankey.h"
#include "decodekey.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "openpgp.h"
#include "sigcheck.h"

/**
 *	dedupuids - Merge duplicate uids on a key.
 *	@key: The key to de-dup uids on.
 *
 *	This function attempts to merge duplicate IDs on a key. It returns 0
 *	if the key is unchanged, otherwise the number of dups merged.
 */
int dedupuids(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list *curuid = NULL;
	struct openpgp_signedpacket_list *dup = NULL;
	struct openpgp_signedpacket_list *tmp = NULL;
	int                               merged = 0;

	log_assert(key != NULL);
	curuid = key->uids;
	while (curuid != NULL) {
		dup = find_signed_packet(curuid->next, curuid->packet);
		while (dup != NULL) {
			logthing(LOGTHING_INFO, "Found duplicate uid: %.*s",
					(int) curuid->packet->length,
					curuid->packet->data);
			merged++;
			merge_packet_sigs(curuid, dup);
			/*
			 * Remove the duplicate uid.
			 */
			tmp = curuid;
			while (tmp != NULL && tmp->next != dup) {
				tmp = tmp->next;
			}
			log_assert(tmp != NULL);
			tmp->next = dup->next;
			dup->next = NULL;
			free_signedpacket_list(dup);

			dup = find_signed_packet(curuid->next, curuid->packet);
		}
		curuid = curuid->next;
	}

	return merged;
}

/**
 *	dedupsubkeys - Merge duplicate subkeys on a key.
 *	@key: The key to de-dup subkeys on.
 *
 *	This function attempts to merge duplicate subkeys on a key. It returns
 *	0 if the key is unchanged, otherwise the number of dups merged.
 */
int dedupsubkeys(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list *cursubkey = NULL;
	struct openpgp_signedpacket_list *dup = NULL;
	struct openpgp_signedpacket_list *tmp = NULL;
	int                               merged = 0;
	uint64_t                          subkeyid;

	log_assert(key != NULL);
	cursubkey = key->subkeys;
	while (cursubkey != NULL) {
		dup = find_signed_packet(cursubkey->next, cursubkey->packet);
		while (dup != NULL) {
			get_packetid(cursubkey->packet, &subkeyid);
			logthing(LOGTHING_INFO,
				"Found duplicate subkey: 0x%016" PRIX64,
				subkeyid);
			merged++;
			merge_packet_sigs(cursubkey, dup);
			/*
			 * Remove the duplicate uid.
			 */
			tmp = cursubkey;
			while (tmp != NULL && tmp->next != dup) {
				tmp = tmp->next;
			}
			log_assert(tmp != NULL);
			tmp->next = dup->next;
			dup->next = NULL;
			free_signedpacket_list(dup);

			dup = find_signed_packet(cursubkey->next,
				cursubkey->packet);
		}
		cursubkey = cursubkey->next;
	}

	return merged;
}

/**
 *	check_sighashes - Check that sig hashes are correct.
 *	@key - the check to check the sig hashes of.
 *
 *	Given an OpenPGP key confirm that all of the sigs on it have the
 *	appropriate 2 octet hash beginning, as stored as part of the sig.
 *	This is a simple way to remove junk sigs and, for example, catches
 *	subkey sig corruption as produced by old pksd implementations.
 *	Any sig that has an incorrect hash is removed from the key. If the
 *	hash cannot be checked (eg we don't support that hash type) we err
 *	on the side of caution and keep it.
 */
int clean_sighashes(struct onak_dbctx *dbctx,
		struct openpgp_publickey *key,
		struct openpgp_packet *sigdata,
		struct openpgp_packet_list **sigs,
		bool fullverify,
		bool *selfsig, bool *othersig)
{
	struct openpgp_packet_list *tmpsig;
	struct openpgp_publickey *sigkeys = NULL, *curkey;
	onak_status_t ret;
	uint8_t hashtype;
	uint8_t hash[64];
	uint8_t *sighash;
	int removed = 0;
	uint64_t keyid, sigid;
	bool remove;

	get_keyid(key, &keyid);
	if (selfsig != NULL) {
		*selfsig = false;
	}
	while (*sigs != NULL) {
		remove = false;
		ret = calculate_packet_sighash(key, sigdata, (*sigs)->packet,
				&hashtype, hash, &sighash);

		if (ret == ONAK_E_UNSUPPORTED_FEATURE) {
			get_keyid(key, &keyid);
			logthing(LOGTHING_ERROR,
				"Unsupported signature hash type %d on 0x%016"
				PRIX64,
				hashtype,
				keyid);
			if (fullverify) {
				remove = true;
			}
		} else if (ret != ONAK_E_OK || (!fullverify &&
				!(hash[0] == sighash[0] &&
					hash[1] == sighash[1]))) {
			remove = true;
		}

#if HAVE_CRYPTO
		if (fullverify && !remove) {
			sig_info((*sigs)->packet, &sigid, NULL);

			/* Start by assuming it's a bad sig */

			remove = true;
			if (sigid == keyid) {
				ret = onak_check_hash_sig(key->publickey,
						(*sigs)->packet,
						hash, hashtype);

				/* We have a valid self signature */
				if (ret == ONAK_E_OK) {
					remove = false;
					if (selfsig != NULL) {
						*selfsig = true;
					}
				}
			}

			if (remove) {
				dbctx->fetch_key_id(dbctx, sigid,
						&sigkeys, false);
			}

			/*
			 * A 64 bit collision is probably a sign of something
			 * sneaky happening, but if the signature verifies we
			 * should keep it.
			 */
			for (curkey = sigkeys; curkey != NULL;
					curkey = curkey->next) {

				ret = onak_check_hash_sig(curkey->publickey,
						(*sigs)->packet,
						hash, hashtype);

				/* Got a valid signature */
				if (ret == ONAK_E_OK) {
					remove = false;
					if (othersig != NULL) {
						*othersig = true;
					}
					break;
				}
			}

			free_publickey(sigkeys);
			sigkeys = NULL;
		}
#endif

		if (remove) {
			tmpsig = *sigs;
			*sigs = (*sigs)->next;
			tmpsig->next = NULL;
			free_packet_list(tmpsig);
			removed++;
		} else {
			sigs = &(*sigs)->next;
		}
	}

	return removed;
}

int clean_list_sighashes(struct onak_dbctx *dbctx,
			struct openpgp_publickey *key,
			struct openpgp_signedpacket_list **siglist,
			bool fullverify, bool needother)
{
	struct openpgp_signedpacket_list **orig, *tmp = NULL;
	bool selfsig, othersig;
	int removed = 0;

	othersig = false;
	orig = siglist;
	while (siglist != NULL && *siglist != NULL) {
		selfsig = false;

		removed += clean_sighashes(dbctx, key, (*siglist)->packet,
			&(*siglist)->sigs, fullverify, &selfsig, &othersig);

		if (fullverify && !selfsig) {
			/* Remove the UID/subkey if there's no selfsig */
			tmp = *siglist;
			*siglist = (*siglist)->next;
			tmp->next = NULL;
			free_signedpacket_list(tmp);
		} else {
			siglist = &(*siglist)->next;
		}
	}

	/*
	 * We need at least one UID to have a signature from another key,
	 * otherwise we remove all of them if needother is set.
	 */
	if (needother && fullverify && !othersig) {
		siglist = orig;
		while (siglist != NULL && *siglist != NULL) {
			tmp = *siglist;
			*siglist = (*siglist)->next;
			tmp->next = NULL;
			free_signedpacket_list(tmp);
		}
	}

	return removed;
}

int clean_key_signatures(struct onak_dbctx *dbctx,
		struct openpgp_publickey *key, bool fullverify, bool needother)
{
	int removed;

	removed = clean_sighashes(dbctx, key, NULL, &key->sigs, fullverify,
			NULL, NULL);
	removed += clean_list_sighashes(dbctx, key, &key->uids, fullverify,
			needother);
	removed += clean_list_sighashes(dbctx, key, &key->subkeys, fullverify,
			false);

	return removed;
}

#define UAT_LIMIT	0xFFFF
#define UID_LIMIT	1024
#define PACKET_LIMIT	8383		/* Fits in 2 byte packet length */

/*
 * Cap the number of UIDs / UATs we accept on a key. Defends against
 * keys carrying an absurd number of (potentially forged) packets — the
 * 2019 SKS-style poisoning vector. Semantic is FIFO: we keep the
 * newest N and drop the oldest excess — but revoked and non-revoked
 * UIDs/UATs get *separate* FIFOs (each capped at N), so a stream of
 * revocations can never push the still-usable identities out. (The list is chronologically
 * ordered by merge.c's append-at-tail, so newest sits at the tail
 * and oldest sits at the head — but the *reason* we chose this
 * direction is temporal, not positional.)
 *
 * Since a UID/UAT packet only survives further cleaning when it
 * carries a valid self-sig, only the key holder can ever push new
 * UID/UAT anyway — FIFO lets that holder keep evolving the active
 * face of their certificate (rotate an old alias out, add a fresh
 * one in) once the cap is hit. A keep-oldest cap would ossify the
 * certificate at whatever was published first.
 */
#define MAX_UIDS_PER_KEY	32
#define MAX_UATS_PER_KEY	4

/*
 * Does this UID/UAT carry a self-signature flagging it the primary
 * User ID (RFC 9580 §5.2.3.25, hashed subpacket 25 with a non-zero
 * value)? The primary UID anchors the certificate's identity — for
 * foopgp it holds the UID:urn:eid: — and, minted once and never
 * re-issued, it is the OLDEST UID and thus the first the FIFO cap
 * below would evict. We keep it instead. The self-sig is NOT verified
 * here (that happens in a later cleaning pass); protecting a single
 * UID keeps the cap's anti-flood guarantee whole even against a
 * forged flag.
 */
static bool signedpacket_is_primary(struct openpgp_signedpacket_list *spl)
{
	struct openpgp_packet_list *s;
	unsigned char *data;
	size_t data_len, sub_len, offset, packet_len;

	for (s = spl->sigs; s != NULL; s = s->next) {
		/* v4/v5 positive certification only. */
		if (s->packet->length < 6 ||
				(s->packet->data[0] != 4 &&
					s->packet->data[0] != 5) ||
				s->packet->data[1] < 0x10 ||
				s->packet->data[1] > 0x13) {
			continue;
		}
		data = &s->packet->data[4];
		data_len = s->packet->length - 4;
		sub_len = ((size_t) data[0] << 8) + data[1] + 2;
		if (sub_len > data_len) {
			continue;
		}
		offset = 2;
		while (offset + 2 < sub_len) {
			packet_len = data[offset++];
			if (packet_len > 191 && packet_len < 255) {
				packet_len = ((packet_len - 192) << 8) +
					data[offset++] + 192;
			} else if (packet_len == 255) {
				if (offset + 4 > sub_len) {
					break;
				}
				packet_len = ((uint32_t) data[offset] << 24) +
					((uint32_t) data[offset + 1] << 16) +
					((uint32_t) data[offset + 2] << 8) +
					data[offset + 3];
				offset += 4;
			}
			if (packet_len == 0 || packet_len > sub_len - offset) {
				break;
			}
			if ((data[offset] & 0x7f) == OPENPGP_SIGSUB_PRIMARYUID &&
					packet_len >= 2 &&
					data[offset + 1] != 0) {
				return true;
			}
			offset += packet_len;
		}
	}
	return false;
}

/*
 * Does this UID hold a URN identity anchor, i.e. does its text start with
 * "UID:urn:" ? For foopgp that is the entity identifier
 * ("UID:urn:eid:u4…"), but the prefix is kept deliberately broad so other
 * URN namespaces (uuid, …) get the same protection.
 *
 * Like the primary UID, such an anchor is minted once and never re-issued:
 * it is among the OLDEST UIDs and thus the first the FIFO cap below would
 * evict. Also like the primary flag, the text is NOT authenticated here —
 * anyone can craft a UID that starts with those eight bytes. Protecting at
 * most ONE of them is therefore essential: it keeps the cap's anti-flood
 * guarantee whole, where protecting every match would let a flood of forged
 * anchors defeat the cap entirely.
 */
static bool signedpacket_is_urn_anchor(struct openpgp_signedpacket_list *spl)
{
	static const char prefix[] = "UID:urn:";
	const size_t prefix_len = sizeof(prefix) - 1;

	if (spl->packet == NULL ||
			spl->packet->tag != OPENPGP_PACKET_UID ||
			spl->packet->length < prefix_len) {
		return false;
	}

	return memcmp(spl->packet->data, prefix, prefix_len) == 0;
}

static int cap_packet_type(struct openpgp_publickey *key,
		int tag, unsigned int max_active, unsigned int max_revoked)
{
	struct openpgp_signedpacket_list **curuid;
	struct openpgp_signedpacket_list *tmp;
	unsigned int                      active = 0, revoked = 0;
	unsigned int                      drop_active, drop_revoked;
	int                               dropped = 0;
	bool                              primary_kept = false;
	bool                              anchor_kept = false;
	bool                              is_rev;

	log_assert(key != NULL);
	/* Pass 1: count matching packets, split by revocation state — two
	 * independent FIFOs so a flood of revoked UIDs/UATs can never evict
	 * the still-usable ones. */
	for (curuid = &key->uids; *curuid != NULL;
			curuid = &(*curuid)->next) {
		if ((*curuid)->packet->tag == tag) {
			if (signedpacket_is_revoked(*curuid)) {
				revoked++;
			} else {
				active++;
			}
		}
	}
	drop_active  = (active  > max_active)  ? active  - max_active  : 0;
	drop_revoked = (revoked > max_revoked) ? revoked - max_revoked : 0;
	if (drop_active == 0 && drop_revoked == 0) {
		return 0;
	}
	/* Pass 2: drop the oldest excess of each class (head = oldest under
	 * merge.c's append-at-tail), keeping the newest max of each. The
	 * primary UID and the URN anchor are each protected once — no more, so
	 * that a flood of forged anchors cannot push real UIDs out. */
	curuid = &key->uids;
	while (*curuid != NULL && (drop_active || drop_revoked)) {
		if ((*curuid)->packet->tag != tag) {
			curuid = &(*curuid)->next;
			continue;
		}
		is_rev = signedpacket_is_revoked(*curuid);
		if (is_rev) {
			if (drop_revoked == 0) {
				curuid = &(*curuid)->next;
				continue;
			}
			drop_revoked--;
		} else {
			if (drop_active == 0) {
				curuid = &(*curuid)->next;
				continue;
			}
			if (!primary_kept &&
					signedpacket_is_primary(*curuid)) {
				primary_kept = true;
				curuid = &(*curuid)->next;
				continue;
			}
			if (!anchor_kept &&
					signedpacket_is_urn_anchor(*curuid)) {
				anchor_kept = true;
				curuid = &(*curuid)->next;
				continue;
			}
			drop_active--;
		}
		logthing(LOGTHING_INFO,
			"Dropping %s packet of type %d beyond cap",
			is_rev ? "revoked" : "active", tag);
		tmp = *curuid;
		*curuid = (*curuid)->next;
		tmp->next = NULL;
		free_signedpacket_list(tmp);
		dropped++;
	}

	return dropped;
}

int cap_uids_per_key(struct openpgp_publickey *key)
{
	return cap_packet_type(key, OPENPGP_PACKET_UID,
			MAX_UIDS_PER_KEY, MAX_UIDS_PER_KEY);
}

int cap_uats_per_key(struct openpgp_publickey *key)
{
	return cap_packet_type(key, OPENPGP_PACKET_UAT,
			MAX_UATS_PER_KEY, MAX_UATS_PER_KEY);
}

int clean_large_packets(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list **curuid = NULL;
	struct openpgp_signedpacket_list *tmp = NULL;
	bool                              drop;
	int                               dropped = 0;

	log_assert(key != NULL);
	curuid = &key->uids;
	while (*curuid != NULL) {
		drop = false;
		switch ((*curuid)->packet->tag) {
		case OPENPGP_PACKET_UID:
			if ((*curuid)->packet->length > UID_LIMIT)
				drop = true;
			break;
		case OPENPGP_PACKET_UAT:
			if ((*curuid)->packet->length > UAT_LIMIT)
				drop = true;
			break;
		default:
			if ((*curuid)->packet->length > PACKET_LIMIT)
				drop = true;
			break;
		}

		if (drop) {
			logthing(LOGTHING_INFO,
					"Dropping large (%zu) packet, type %d",
					(*curuid)->packet->length,
					(*curuid)->packet->tag);
			/* Remove the entire large signed packet list */
			tmp = *curuid;
			*curuid = (*curuid)->next;
			tmp->next = NULL;
			free_signedpacket_list(tmp);
			dropped++;
		} else {
			curuid = &(*curuid)->next;
		}
	}

	return dropped;
}

/*
 * Cap the number of signatures attached to each UID/UAT-tagged packet.
 * Semantic is stack (LIFO drop): we keep the oldest N and drop the
 * newest excess. Sigs are certifications by third parties (unlike
 * UID/UAT packets, which only the key holder can produce validly),
 * so on a flood the desirable survivors are the historical WoT
 * links this server has known the longest — not the latest arrivals
 * that may include the flood itself. dedup_sigs_per_signer(), which
 * runs before this cap, has already collapsed same-signer duplicates
 * (newest cert wins, first revocation wins), so the cap only bites
 * when @max distinct signers have signed one UID/UAT.
 *
 * (The list is chronologically ordered by merge.c's append-at-tail,
 * so oldest sits at the head and newest at the tail. We walk from
 * the head keeping the first @max entries, then free the tail —
 * temporally: keep oldest, drop newest.)
 *
 * Pass @max == 0 to leave the packet untouched. Walks both UIDs and
 * UATs; pass OPENPGP_PACKET_UID or OPENPGP_PACKET_UAT in @tag to
 * restrict the action to one kind.
 */
static int cap_sigs_per_packet(struct openpgp_publickey *key,
		int tag, unsigned int max)
{
	struct openpgp_signedpacket_list *curuid;
	struct openpgp_packet_list *sig, *tail, *next;
	unsigned int kept;
	int dropped = 0;

	if (max == 0) {
		return 0;
	}
	log_assert(key != NULL);
	for (curuid = key->uids; curuid != NULL; curuid = curuid->next) {
		if (curuid->packet->tag != tag) {
			continue;
		}
		kept = 0;
		sig = curuid->sigs;
		tail = NULL;
		while (sig != NULL && kept < max) {
			tail = sig;
			sig = sig->next;
			kept++;
		}
		if (sig == NULL) {
			continue;
		}
		/* Detach the surviving prefix from the to-drop tail. */
		if (tail != NULL) {
			tail->next = NULL;
		}
		curuid->last_sig = tail;
		while (sig != NULL) {
			next = sig->next;
			sig->next = NULL;
			free_packet_list(sig);
			sig = next;
			dropped++;
		}
	}

	if (dropped > 0) {
		logthing(LOGTHING_INFO,
			"Capped sigs on type-%d packets to %u (dropped %d).",
			tag, max, dropped);
	}

	return dropped;
}

/**
 *	cleankeys - Apply all available cleaning options on a list of keys.
 *	@policies: The cleaning policies to apply.
 *
 *	Applies the requested cleaning policies to a list of keys. These are
 *	specified from the ONAK_CLEAN_* set of flags, or ONAK_CLEAN_ALL to
 *	apply all available cleaning options. Returns 0 if no changes were
 *	made, otherwise the number of keys cleaned. Note that some options
 *	may result in keys being removed entirely from the list.
 */
int cleankeys(struct onak_dbctx *dbctx, struct openpgp_publickey **keys,
		uint64_t policies)
{
	struct openpgp_publickey **curkey, *tmp;
	struct openpgp_fingerprint fp;
	int changed = 0, count = 0;
	bool needother;

	if (keys == NULL)
		return 0;

	curkey = keys;
	while (*curkey != NULL) {
		/*
		 * v3 (and older) keys are MD5/SHA-1 with deprecated
		 * algorithms; the SHA-1 collision attacks demonstrated
		 * since 2017 make them unsafe to keep certifying. No
		 * modern client emits them either. Drop them unconditionally
		 * before any further work.
		 */
		if ((*curkey)->publickey->data[0] < 4) {
			tmp = *curkey;
			*curkey = tmp->next;
			tmp->next = NULL;
			free_publickey(tmp);
			changed++;
			continue;
		}
		if (policies & ONAK_CLEAN_LARGE_PACKETS) {
			count += clean_large_packets(*curkey);
		}
		count += dedupuids(*curkey);
		count += dedupsubkeys(*curkey);
		if (policies & ONAK_CLEAN_CAP_UIDS) {
			count += cap_uids_per_key(*curkey);
		}
		if (policies & ONAK_CLEAN_CAP_UATS) {
			count += cap_uats_per_key(*curkey);
		}
		/*
		 * A freshly parsed key can already carry several signatures
		 * from the same issuer (or a forged keyid repeated many
		 * times) on the same packet. Collapse them per (version,
		 * sigtype, issuer) on every sig list of the key. The same
		 * dedupe runs at the tail of merge_packet_sigs, so this
		 * pass covers the first-import case where no merge with
		 * existing storage takes place.
		 */
		count += dedupe_sigs(&(*curkey)->sigs, &(*curkey)->last_sig);
		{
			struct openpgp_signedpacket_list *sp;

			for (sp = (*curkey)->uids; sp != NULL; sp = sp->next) {
				count += dedupe_sigs(&sp->sigs,
						&sp->last_sig);
			}
			for (sp = (*curkey)->subkeys; sp != NULL;
					sp = sp->next) {
				count += dedupe_sigs(&sp->sigs,
						&sp->last_sig);
			}
		}
		/*
		 * The per-signer dedupe just ran, so the caps below apply
		 * after the surviving signatures have been reduced to a
		 * single representative per (version, sigtype, issuer).
		 * Reading: max_sigs_per_uid is effectively
		 * "max distinct issuers per UID".
		 */
		if (config.max_sigs_per_uid > 0) {
			count += cap_sigs_per_packet(*curkey,
				OPENPGP_PACKET_UID,
				config.max_sigs_per_uid);
		}
		if (config.max_sigs_per_uat > 0) {
			count += cap_sigs_per_packet(*curkey,
				OPENPGP_PACKET_UAT,
				config.max_sigs_per_uat);
		}
		if (policies & (ONAK_CLEAN_CHECK_SIGHASH |
					ONAK_CLEAN_VERIFY_SIGNATURES)) {

			needother = policies & ONAK_CLEAN_NEED_OTHER_SIG;
			if (needother) {
				/*
				 * Check if we already have the key; if we do
				 * then we can skip the check to make sure we
				 * have signatures from other keys.
				 */
				get_fingerprint((*curkey)->publickey, &fp);
				tmp = NULL;
				needother = dbctx->fetch_key(dbctx, &fp,
						&tmp, false) == 0;
				free_publickey(tmp);
			}

			count += clean_key_signatures(dbctx, *curkey,
				policies & ONAK_CLEAN_VERIFY_SIGNATURES,
				needother);
		}
		if (count > 0) {
			changed++;
		}
		if ((*curkey)->uids == NULL) {
			/* No valid UIDS so remove the key from the list */
			tmp = *curkey;
			*curkey = tmp->next;
			tmp->next = NULL;
			free_publickey(tmp);
		} else {
			curkey = &(*curkey)->next;
		}
	}

	return changed;
}
