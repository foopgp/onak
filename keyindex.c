/*
 * keyindex.c - Routines to list an OpenPGP key.
 *
 * Copyright 2002-2008 Jonathan McDowell <noodles@earth.li>
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

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "decodekey.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "log.h"
#include "onak.h"
#include "openpgp.h"
#include "template.h"

/*
 * Convert a Public Key algorithm to its single character representation.
 */
char pkalgo2char(uint8_t algo)
{
	char typech;

	switch (algo) {
	case OPENPGP_PKALGO_DSA:
		typech = 'D';
		break;
	case OPENPGP_PKALGO_ECDSA:
	case OPENPGP_PKALGO_EDDSA:
		typech = 'E';
		break;
	case OPENPGP_PKALGO_EC:
		typech = 'e';
		break;
	case OPENPGP_PKALGO_ELGAMAL_SIGN:
		typech = 'G';
		break;
	case OPENPGP_PKALGO_ELGAMAL_ENC:
		typech = 'g';
		break;
	case OPENPGP_PKALGO_RSA:
		typech = 'R';
		break;
	case OPENPGP_PKALGO_RSA_ENC:
		typech = 'r';
		break;
	case OPENPGP_PKALGO_RSA_SIGN:
		typech = 's';
		break;
	default:
		typech = '?';
		break;
	}

	return typech;
}

/**
 *	html_escape - Takes a string and converts it to HTML.
 *	@src: The string to HTMLize.
 *	@src_len: The length of the source string
 *	@dst: A buffer to put the escaped string into
 *	@dst_len: Length of the destination buffer (including a trailing NULL)
 *
 *	Takes a string and escapes any HTML entities (<, >, &, ", '). Returns
 *	dst.
 */
const char *html_escape(const char *src, size_t src_len,
		char *dst, size_t dst_len)
{
	size_t in_pos, out_pos;

	dst_len--;

	for (in_pos = 0, out_pos = 0;
			in_pos < src_len && out_pos < (dst_len - 1);
			in_pos++, out_pos++) {
		switch (src[in_pos]) {
		case '<':
			if ((out_pos + 4) >= dst_len) {
				break;
			}
			dst[out_pos++] = '&';
			dst[out_pos++] = 'l';
			dst[out_pos++] = 't';
			dst[out_pos] = ';';
			break;
		case '>':
			if ((out_pos + 4) >= dst_len) {
				break;
			}
			dst[out_pos++] = '&';
			dst[out_pos++] = 'g';
			dst[out_pos++] = 't';
			dst[out_pos] = ';';
			break;
		case '"':
			if ((out_pos + 6) >= dst_len) {
				break;
			}
			dst[out_pos++] = '&';
			dst[out_pos++] = 'q';
			dst[out_pos++] = 'u';
			dst[out_pos++] = 'o';
			dst[out_pos++] = 't';
			dst[out_pos] = ';';
			break;
		case '\'':
			if ((out_pos + 5) >= dst_len) {
				break;
			}
			dst[out_pos++] = '&';
			dst[out_pos++] = '#';
			dst[out_pos++] = '3';
			dst[out_pos++] = '9';
			dst[out_pos] = ';';
			break;
		case '&':
			if ((out_pos + 5) >= dst_len) {
				break;
			}
			dst[out_pos++] = '&';
			dst[out_pos++] = 'a';
			dst[out_pos++] = 'm';
			dst[out_pos++] = 'p';
			dst[out_pos] = ';';
			break;
		default:
			dst[out_pos] = src[in_pos];
		}
	}
	dst[out_pos] = 0;

	return dst;
}

/*
 * Given a public key/subkey packet return the key length.
 */
unsigned int keylength(struct openpgp_packet *keydata)
{
	unsigned int length;
	uint8_t keyofs;
	enum onak_oid oid;

	switch (keydata->data[0]) {
	case 2:
	case 3:
		length = (keydata->data[8] << 8) +
				keydata->data[9];
		break;
	case 4:
	case 5:
		/* v5 has an additional 4 bytes of key length data */
		keyofs = (keydata->data[0] == 4) ? 6 : 10;
		switch (keydata->data[5]) {
		case OPENPGP_PKALGO_EC:
		case OPENPGP_PKALGO_ECDSA:
		case OPENPGP_PKALGO_EDDSA:
			/* Elliptic curve key size is based on OID */
			oid = onak_parse_oid(&keydata->data[keyofs],
					keydata->length - keyofs);
			if (oid == ONAK_OID_CURVE25519) {
				length = 255;
			} else if (oid == ONAK_OID_ED25519) {
				length = 255;
			} else if (oid == ONAK_OID_NISTP256) {
				length = 256;
			} else if (oid == ONAK_OID_NISTP384) {
				length = 384;
			} else if (oid == ONAK_OID_NISTP521) {
				length = 521;
			} else if (oid == ONAK_OID_BRAINPOOLP256R1) {
				length = 256;
			} else if (oid == ONAK_OID_BRAINPOOLP384R1) {
				length = 384;
			} else if (oid == ONAK_OID_BRAINPOOLP512R1) {
				length = 512;
			} else if (oid == ONAK_OID_SECP256K1) {
				length = 256;
			} else {
				logthing(LOGTHING_ERROR,
					"Unknown elliptic curve size");
				length = 0;
			}
			break;
		default:
			length = (keydata->data[keyofs] << 8) +
				keydata->data[keyofs + 1];
		}
		break;
	default:
		logthing(LOGTHING_ERROR, "Unknown key version: %d",
			keydata->data[0]);
		length = 0;
	}

	return length;
}

int list_sigs(struct onak_dbctx *dbctx,
		struct openpgp_packet_list *sigs, bool html)
{
	char *uid = NULL;
	uint64_t sigid = 0;
	char *sig = NULL;
	char buf[1024];

	while (sigs != NULL) {
		sigid = sig_keyid(sigs->packet);
		if (dbctx) {
			uid = dbctx->keyid2uid(dbctx, sigid);
		}
		if (sigs->packet->data[0] == 4 &&
				sigs->packet->data[1] == 0x30) {
			/* It's a Type 4 sig revocation */
			sig = "rev";
		} else {
			sig = "sig";
		}
		if (html && uid != NULL) {
			printf("%s         <a href=\"lookup?op=get&"
				"search=0x%016" PRIX64 "\">0x%016" PRIX64
				"</a>             "
				"<a href=\"lookup?op=vindex&search=0x%016"
				PRIX64 "\">%s</a>\n",
				sig,
				sigid,
				sigid,
				sigid,
				html_escape(uid, strlen(uid), buf, sizeof(buf)));
		} else if (html && uid == NULL) {
			printf("%s         0x%016" PRIX64 "             "
				"[User id not found]\n",
				sig,
				sigid);
		} else {
			printf("%s         0x%016" PRIX64
				"             %s\n",
				sig,
				sigid,
				(uid != NULL) ? uid :
				"[User id not found]");
		}
		if (uid != NULL) {
			free(uid);
			uid = NULL;
		}
		sigs = sigs->next;
	}

	return 0;
}

/*
 * Returns true if the given signed packet (a UID or a UAT) carries a
 * v4/v5 certification revocation signature (sigtype 0x30) — i.e. the
 * signed packet has been revoked. Doesn't try to authenticate which key
 * issued the revocation (the same heuristic the rest of keyindex.c
 * applies); enough for the display-time filtering done by op=index.
 */
static bool signedpacket_is_revoked(struct openpgp_signedpacket_list *sp)
{
	struct openpgp_packet_list *sigs;

	if (sp == NULL) {
		return false;
	}
	for (sigs = sp->sigs; sigs != NULL; sigs = sigs->next) {
		if (sigs->packet == NULL || sigs->packet->data == NULL ||
				sigs->packet->length < 2) {
			continue;
		}
		if ((sigs->packet->data[0] == 4 ||
				sigs->packet->data[0] == 5) &&
				sigs->packet->data[1] ==
					OPENPGP_SIGTYPE_CERT_REV) {
			return true;
		}
	}
	return false;
}

int list_uids(struct onak_dbctx *dbctx,
		uint64_t keyid, struct openpgp_signedpacket_list *uids,
		bool verbose, bool html)
{
	char buf[1024];
	int  imgindx = 0;

	while (uids != NULL) {
		if (uids->packet->tag == OPENPGP_PACKET_UID) {
			snprintf(buf, 1023, "%.*s",
				(int) uids->packet->length,
				uids->packet->data);
			if (html) {
				printf("                                %s\n",
					html_escape((char *) uids->packet->data,
						uids->packet->length,
						buf,
						sizeof(buf)));
			} else {
				printf("                                %.*s\n",
					(int) uids->packet->length,
					uids->packet->data);
			}
		} else if (uids->packet->tag == OPENPGP_PACKET_UAT) {
			/*
			 * In op=index mode (verbose=false), revoked UATs are
			 * skipped: a photo whose owner has revoked it clutters
			 * the listing and isn't part of what the user
			 * currently asserts about themselves. op=vindex
			 * (verbose=true) still shows every UAT, since its
			 * purpose is the full key state including history.
			 *
			 * imgindx is incremented for every UAT (revoked or
			 * not), because op=photo's getphoto() iterates over
			 * them all with the same stride. Leaving skipped UATs
			 * out of the count would desync the HTML idx=N we
			 * emit from the index getphoto() looks up — making
			 * the browser fetch the wrong (typically: revoked)
			 * photo blob for what is shown as the valid UAT.
			 */
			if (!verbose && signedpacket_is_revoked(uids)) {
				/* skip in op=index ; nothing to print */
			} else {
				printf("                                ");
				if (html) {
					printf("<img src=\"lookup?op=photo&"
						"search=0x%016" PRIX64
						"&idx=%d\" alt=\""
						"[photo id]\">\n",
						keyid,
						imgindx);
				} else {
					printf("[photo id]\n");
				}
			}
			imgindx++;
		}
		if (verbose) {
			list_sigs(dbctx, uids->sigs, html);
		}
		uids = uids->next;
	}

	return 0;
}

int list_subkeys(struct onak_dbctx *dbctx,
		struct openpgp_signedpacket_list *subkeys, bool verbose,
		bool html)
{
	struct tm	created;
	time_t		created_time = 0;
	int	 	type = 0;
	int	 	length = 0;
	uint64_t	keyid = 0;

	while (subkeys != NULL) {
		if (subkeys->packet->tag == OPENPGP_PACKET_PUBLICSUBKEY) {

			created_time = (subkeys->packet->data[1] << 24) +
					(subkeys->packet->data[2] << 16) +
					(subkeys->packet->data[3] << 8) +
					subkeys->packet->data[4];
			gmtime_r(&created_time, &created);

			switch (subkeys->packet->data[0]) {
			case 2:
			case 3:
				type = subkeys->packet->data[7];
				break;
			case 4:
			case 5:
				type = subkeys->packet->data[5];
				break;
			default:
				logthing(LOGTHING_ERROR,
					"Unknown key version: %d",
					subkeys->packet->data[0]);
			}
			length = keylength(subkeys->packet);

			if (get_packetid(subkeys->packet,
					&keyid) != ONAK_E_OK) {
				logthing(LOGTHING_ERROR, "Couldn't get keyid.");
			}
			printf("sub  %5d%c/0x%016" PRIX64 " %04d/%02d/%02d\n",
				length,
				pkalgo2char(type),
				keyid,
				created.tm_year + 1900,
				created.tm_mon + 1,
				created.tm_mday);

		}
		if (verbose) {
			list_sigs(dbctx, subkeys->sigs, html);
		}
		subkeys = subkeys->next;
	}

	return 0;
}

void display_fingerprint(struct openpgp_publickey *key)
{
	int		i = 0;
	struct openpgp_fingerprint fingerprint;

	get_fingerprint(key->publickey, &fingerprint);
	printf("      Key fingerprint =");
	for (i = 0; i < fingerprint.length; i++) {
		if ((fingerprint.length == 16) ||
			(i % 2 == 0)) {
			printf(" ");
		}
		if (fingerprint.length == 20 &&
				(i * 2) == fingerprint.length) {
			/* Extra space in the middle of a SHA1 fingerprint */
			printf(" ");
		}
		printf("%02X", fingerprint.fp[i]);
	}
	printf("\n");

	return;
}

void display_skshash(struct openpgp_publickey *key, bool html)
{
	int		i = 0;
	struct skshash	hash;

	get_skshash(key, &hash);
	printf("      Key hash = ");
	if (html) {
		printf("<a href=\"lookup?op=hget&search=");
		for (i = 0; i < sizeof(hash.hash); i++) {
			printf("%02X", hash.hash[i]);
		}
		printf("\">");
	}
	for (i = 0; i < sizeof(hash.hash); i++) {
		printf("%02X", hash.hash[i]);
	}
	if (html) {
		printf("</a>");
	}
	printf("\n");

	return;
}

/*
 * Helpers for the template-based renderer.
 */

static char *strdup_printf(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
static char *strdup_printf(const char *fmt, ...)
{
	char buf[128];
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0) {
		return NULL;
	}
	if ((size_t) n < sizeof(buf)) {
		return strdup(buf);
	}
	char *big = malloc((size_t) n + 1);
	if (big == NULL) {
		return NULL;
	}
	va_start(ap, fmt);
	vsnprintf(big, (size_t) n + 1, fmt, ap);
	va_end(ap);
	return big;
}

static char *format_fp_string(const struct openpgp_fingerprint *fp)
{
	/* Mirror display_fingerprint(): leading space then groups,
	 * with a double space in the middle for SHA-1. */
	size_t cap = (size_t) fp->length * 3 + 4;
	char *buf = malloc(cap);
	size_t pos = 0;
	int i;
	if (buf == NULL) {
		return NULL;
	}
	for (i = 0; i < fp->length; i++) {
		if (fp->length == 16 || (i % 2 == 0)) {
			buf[pos++] = ' ';
		}
		if (fp->length == 20 && (i * 2) == fp->length) {
			buf[pos++] = ' ';
		}
		pos += snprintf(buf + pos, cap - pos, "%02X", fp->fp[i]);
	}
	buf[pos] = '\0';
	return buf;
}

static struct tmpl_value *build_sigs_list(struct onak_dbctx *dbctx,
		struct openpgp_packet_list *sigs)
{
	struct tmpl_value *out = tmpl_list();
	struct tmpl_value *sig;
	char *resolved;
	uint64_t sigid;
	bool is_rev;

	while (sigs != NULL) {
		sigid = sig_keyid(sigs->packet);
		is_rev = (sigs->packet->data[0] == 4 &&
				sigs->packet->data[1] == 0x30);
		resolved = NULL;
		if (dbctx != NULL) {
			resolved = dbctx->keyid2uid(dbctx, sigid);
		}
		sig = tmpl_map();
		tmpl_map_set(sig, "kind",
			tmpl_string(is_rev ? "rev" : "sig"));
		tmpl_map_set(sig, "kind_is_rev", tmpl_bool(is_rev));
		tmpl_map_set(sig, "keyid_hex16",
			tmpl_string_take(
				strdup_printf("%016" PRIX64, sigid)));
		tmpl_map_set(sig, "signer_uid_known",
			tmpl_bool(resolved != NULL));
		if (resolved != NULL) {
			tmpl_map_set(sig, "signer_uid",
				tmpl_string_take(resolved));
		}
		tmpl_list_append(out, sig);
		sigs = sigs->next;
	}
	return out;
}

static struct tmpl_value *build_uid_list(struct onak_dbctx *dbctx,
		struct openpgp_signedpacket_list *uids, bool verbose)
{
	struct tmpl_value *out = tmpl_list();
	struct tmpl_value *entry;
	int this_idx;
	int imgindx = 0;

	while (uids != NULL) {
		entry = tmpl_map();
		if (uids->packet->tag == OPENPGP_PACKET_UID) {
			tmpl_map_set(entry, "is_uat", tmpl_bool(false));
			tmpl_map_set(entry, "text",
				tmpl_string_n(
					(char *) uids->packet->data,
					uids->packet->length));
		} else if (uids->packet->tag == OPENPGP_PACKET_UAT) {
			/*
			 * imgindx tracks the photo position op=photo /
			 * getphoto() will index into. It must advance for
			 * every UAT we see (revoked or not), or the idx
			 * we emit desyncs from getphoto()'s stride and the
			 * browser fetches the wrong blob.
			 */
			this_idx = imgindx++;
			if (!verbose && signedpacket_is_revoked(uids)) {
				/*
				 * op=index is the compact public listing;
				 * a revoked UAT no longer represents what
				 * its owner asserts about themselves, so we
				 * drop it. op=vindex (verbose) still shows
				 * it because that view is the full key
				 * state with history.
				 */
				tmpl_free(entry);
				uids = uids->next;
				continue;
			}
			tmpl_map_set(entry, "is_uat", tmpl_bool(true));
			tmpl_map_set(entry, "uat_index", tmpl_int(this_idx));
		} else {
			tmpl_free(entry);
			uids = uids->next;
			continue;
		}
		if (verbose) {
			tmpl_map_set(entry, "sigs",
				build_sigs_list(dbctx, uids->sigs));
		}
		tmpl_list_append(out, entry);
		uids = uids->next;
	}
	return out;
}

static struct tmpl_value *build_subkey_list(struct onak_dbctx *dbctx,
		struct openpgp_signedpacket_list *subkeys, bool verbose)
{
	struct tmpl_value *out = tmpl_list();
	struct tmpl_value *entry;
	struct tm created;
	time_t created_time;
	int type;
	int length;
	uint64_t subkeyid = 0;

	while (subkeys != NULL) {
		if (subkeys->packet->tag != OPENPGP_PACKET_PUBLICSUBKEY) {
			subkeys = subkeys->next;
			continue;
		}
		created_time = ((time_t) subkeys->packet->data[1] << 24) +
				((time_t) subkeys->packet->data[2] << 16) +
				((time_t) subkeys->packet->data[3] << 8) +
				subkeys->packet->data[4];
		gmtime_r(&created_time, &created);
		type = 0;
		if (subkeys->packet->data[0] == 2 ||
				subkeys->packet->data[0] == 3) {
			type = subkeys->packet->data[7];
		} else if (subkeys->packet->data[0] == 4 ||
				subkeys->packet->data[0] == 5) {
			type = subkeys->packet->data[5];
		}
		length = keylength(subkeys->packet);
		(void) get_packetid(subkeys->packet, &subkeyid);

		entry = tmpl_map();
		tmpl_map_set(entry, "bits_padded",
			tmpl_string_take(
				strdup_printf("%5d", length)));
		tmpl_map_set(entry, "algo_char",
			tmpl_string_take(
				strdup_printf("%c", pkalgo2char(type))));
		tmpl_map_set(entry, "subkeyid_hex16",
			tmpl_string_take(
				strdup_printf("%016" PRIX64, subkeyid)));
		tmpl_map_set(entry, "date_str",
			tmpl_string_take(
				strdup_printf("%04d/%02d/%02d",
					created.tm_year + 1900,
					created.tm_mon + 1,
					created.tm_mday)));
		if (verbose) {
			tmpl_map_set(entry, "sigs",
				build_sigs_list(dbctx, subkeys->sigs));
		}
		tmpl_list_append(out, entry);
		subkeys = subkeys->next;
	}
	return out;
}

static struct tmpl_value *build_one_key(struct onak_dbctx *dbctx,
		struct openpgp_publickey *key, bool verbose, bool fingerprint,
		bool skshash)
{
	struct tmpl_value *m = tmpl_map();
	struct openpgp_signedpacket_list *curuid;
	struct openpgp_fingerprint fp;
	struct skshash hash;
	struct tm created;
	time_t created_time;
	uint64_t keyid = 0;
	int type = 0;
	int length;
	char buf[64];
	int i;

	created_time = ((time_t) key->publickey->data[1] << 24) +
			((time_t) key->publickey->data[2] << 16) +
			((time_t) key->publickey->data[3] << 8) +
			key->publickey->data[4];
	gmtime_r(&created_time, &created);
	if (key->publickey->data[0] == 2 || key->publickey->data[0] == 3) {
		type = key->publickey->data[7];
	} else if (key->publickey->data[0] == 4 ||
			key->publickey->data[0] == 5) {
		type = key->publickey->data[5];
	}
	length = keylength(key->publickey);
	(void) get_keyid(key, &keyid);

	tmpl_map_set(m, "bits_padded",
		tmpl_string_take(strdup_printf("%5d", length)));
	tmpl_map_set(m, "algo_char",
		tmpl_string_take(strdup_printf("%c", pkalgo2char(type))));
	tmpl_map_set(m, "keyid_hex16",
		tmpl_string_take(
			strdup_printf("%016" PRIX64, keyid)));
	tmpl_map_set(m, "date_str",
		tmpl_string_take(
			strdup_printf("%04d/%02d/%02d",
				created.tm_year + 1900,
				created.tm_mon + 1,
				created.tm_mday)));
	tmpl_map_set(m, "revoked", tmpl_bool(key->revoked));

	curuid = key->uids;
	if (curuid != NULL && curuid->packet->tag == OPENPGP_PACKET_UID) {
		tmpl_map_set(m, "has_primary_uid", tmpl_bool(true));
		tmpl_map_set(m, "primary_uid",
			tmpl_string_n(
				(char *) curuid->packet->data,
				curuid->packet->length));
		if (verbose) {
			tmpl_map_set(m, "primary_sigs",
				build_sigs_list(dbctx, curuid->sigs));
		}
		curuid = curuid->next;
	} else {
		tmpl_map_set(m, "has_primary_uid", tmpl_bool(false));
	}

	tmpl_map_set(m, "other_uids",
		build_uid_list(dbctx, curuid, verbose));

	if (verbose) {
		tmpl_map_set(m, "subkeys",
			build_subkey_list(dbctx, key->subkeys, verbose));
	}

	if (fingerprint) {
		if (get_fingerprint(key->publickey, &fp) == ONAK_E_OK) {
			tmpl_map_set(m, "fingerprint_formatted",
				tmpl_string_take(format_fp_string(&fp)));
		}
	}
	if (skshash) {
		(void) get_skshash(key, &hash);
		for (i = 0; i < (int) sizeof(hash.hash); i++) {
			snprintf(buf + i * 2, sizeof(buf) - i * 2,
				"%02X", hash.hash[i]);
		}
		tmpl_map_set(m, "skshash_hex", tmpl_string(buf));
	}

	/*
	 * Extra fields that the vanilla template ignores but the foopgp
	 * template uses: a trimmed fingerprint suitable for display in a
	 * <code> block without the legacy leading space, and a count of
	 * sigs across all UIDs and UATs (excluding subkey binding sigs).
	 */
	if (get_fingerprint(key->publickey, &fp) == ONAK_E_OK) {
		char *full = format_fp_string(&fp);
		if (full != NULL) {
			char *trim = full;
			while (*trim == ' ') trim++;
			tmpl_map_set(m, "fingerprint_formatted_trimmed",
				tmpl_string(trim));
			free(full);
		}
	}
	{
		long long total = 0;
		struct openpgp_signedpacket_list *p;
		struct openpgp_packet_list *s;
		for (p = key->uids; p != NULL; p = p->next) {
			for (s = p->sigs; s != NULL; s = s->next) {
				total++;
			}
		}
		tmpl_map_set(m, "sig_count_total", tmpl_int(total));
	}

	return m;
}

static struct tmpl_value *build_key_index_data(struct onak_dbctx *dbctx,
		struct openpgp_publickey *keys, bool verbose, bool fingerprint,
		bool skshash)
{
	struct tmpl_value *root = tmpl_map();
	struct tmpl_value *opts = tmpl_map();
	struct tmpl_value *klist = tmpl_list();

	tmpl_map_set(opts, "verbose", tmpl_bool(verbose));
	tmpl_map_set(opts, "fingerprint", tmpl_bool(fingerprint));
	tmpl_map_set(opts, "skshash", tmpl_bool(skshash));
	tmpl_map_set(root, "opts", opts);

	while (keys != NULL) {
		tmpl_list_append(klist,
			build_one_key(dbctx, keys, verbose,
				fingerprint, skshash));
		keys = keys->next;
	}
	tmpl_map_set(root, "keys", klist);
	return root;
}

/**
 *	key_index - List a set of OpenPGP keys.
 *	@keys: The keys to display.
 *      @verbose: Should we list sigs as well?
 *	@fingerprint: List the fingerprint?
 *	@html: Should the output be tailored for HTML?
 *
 *	This function takes a list of OpenPGP public keys and displays an index
 *	of them. Useful for debugging or the keyserver Index function.
 */
int key_index(struct onak_dbctx *dbctx,
		struct openpgp_publickey *keys, bool verbose, bool fingerprint,
			bool skshash, bool html)
{
	const char *template_name = html
		? "key_index.html"
		: "key_index.txt";
	char *source;
	struct tmpl_value *root;
	int rc;

	source = tmpl_load_named(template_name);
	if (source != NULL) {
		root = build_key_index_data(dbctx, keys, verbose,
			fingerprint, skshash);
		rc = tmpl_render(source, root, tmpl_putc_stdout, NULL);
		tmpl_free(root);
		free(source);
		if (rc == 0) {
			return 0;
		}
		logthing(LOGTHING_ERROR,
			"template render failed, falling back");
	}

	/* Fallback to the original printf-based renderer. */
	return key_index_legacy(dbctx, keys, verbose, fingerprint,
			skshash, html);
}

int key_index_legacy(struct onak_dbctx *dbctx,
		struct openpgp_publickey *keys, bool verbose, bool fingerprint,
			bool skshash, bool html)
{
	struct openpgp_signedpacket_list	*curuid = NULL;
	struct tm				 created;
	time_t					 created_time = 0;
	int					 type = 0;
	int					 length = 0;
	char					 buf[1024];
	uint64_t				 keyid;


	if (html) {
		puts("<pre>");
	}
	puts("Type   bits/keyID    Date       User ID");
	while (keys != NULL) {
		created_time = (keys->publickey->data[1] << 24) +
					(keys->publickey->data[2] << 16) +
					(keys->publickey->data[3] << 8) +
					keys->publickey->data[4];
		gmtime_r(&created_time, &created);

		switch (keys->publickey->data[0]) {
		case 2:
		case 3:
			type = keys->publickey->data[7];
			break;
		case 4:
		case 5:
			type = keys->publickey->data[5];
			break;
		default:
			logthing(LOGTHING_ERROR, "Unknown key version: %d",
				keys->publickey->data[0]);
		}
		length = keylength(keys->publickey);

		if (get_keyid(keys, &keyid) != ONAK_E_OK) {
			logthing(LOGTHING_ERROR, "Couldn't get keyid.");
		}

		if (html) {
			printf("pub  %5d%c/<a href=\"lookup?op=get&"
				"search=0x%016" PRIX64 "\">0x%016" PRIX64
				"</a> %04d/%02d/%02d ",
				length,
				pkalgo2char(type),
				keyid,
				keyid,
				created.tm_year + 1900,
				created.tm_mon + 1,
				created.tm_mday);
		} else {
			printf("pub  %5d%c/0x%016" PRIX64 " %04d/%02d/%02d ",
				length,
				pkalgo2char(type),
				keyid,
				created.tm_year + 1900,
				created.tm_mon + 1,
				created.tm_mday);
		}

		curuid = keys->uids;
		if (curuid != NULL &&
				curuid->packet->tag == OPENPGP_PACKET_UID) {
			if (html) {
				printf("<a href=\"lookup?op=vindex&"
					"search=0x%016" PRIX64 "\">"
					"%s</a>%s\n",
					keyid,
					html_escape((char *) curuid->packet->data,
						curuid->packet->length,
						buf,
						sizeof(buf)),
					(keys->revoked) ? " *** REVOKED ***" : "");
			} else {
				printf("%.*s%s\n",
					(int) curuid->packet->length,
					curuid->packet->data,
					(keys->revoked) ? " *** REVOKED ***" : "");
			}
			if (skshash) {
				display_skshash(keys, html);
			}
			if (fingerprint) {
				display_fingerprint(keys);
			}
			if (verbose) {
				list_sigs(dbctx, curuid->sigs, html);
			}
			curuid = curuid->next;
		} else {
			printf("%s\n",
				(keys->revoked) ? "*** REVOKED ***": "");
			if (fingerprint) {
				display_fingerprint(keys);
			}
		}

		list_uids(dbctx, keyid, curuid, verbose, html);
		if (verbose) {
			list_subkeys(dbctx, keys->subkeys, verbose, html);
		}

		keys = keys->next;
	}

	if (html) {
		puts("</pre>");
	}

	return 0;
}

/**
 *	mrkey_index - List a set of OpenPGP keys in the MRHKP format.
 *	@keys: The keys to display.
 *
 *	This function takes a list of OpenPGP public keys and displays a
 *	machine readable list of them.
 */
int mrkey_index(struct openpgp_publickey *keys)
{
	struct openpgp_signedpacket_list	*curuid = NULL;
	time_t					 created_time = 0;
	int					 type = 0;
	int					 length = 0;
	int					 i = 0;
	int					 c;
	uint64_t				 keyid;
	struct openpgp_fingerprint fingerprint;

	while (keys != NULL) {
		created_time = (keys->publickey->data[1] << 24) +
					(keys->publickey->data[2] << 16) +
					(keys->publickey->data[3] << 8) +
					keys->publickey->data[4];

		printf("pub:");

		switch (keys->publickey->data[0]) {
		case 2:
		case 3:
			if (get_keyid(keys, &keyid) != ONAK_E_OK) {
				logthing(LOGTHING_ERROR, "Couldn't get keyid");
			}
			printf("%016" PRIX64, keyid);
			type = keys->publickey->data[7];
			break;
		case 4:
		case 5:
			(void) get_fingerprint(keys->publickey, &fingerprint);

			for (i = 0; i < fingerprint.length; i++) {
				printf("%02X", fingerprint.fp[i]);
			}

			type = keys->publickey->data[5];
			break;
		default:
			logthing(LOGTHING_ERROR, "Unknown key version: %d",
				keys->publickey->data[0]);
		}
		length = keylength(keys->publickey);

		printf(":%d:%d:%ld::%s\n",
			type,
			length,
			created_time,
			(keys->revoked) ? "r" : "");

		for (curuid = keys->uids; curuid != NULL;
			 curuid = curuid->next) {

			if (curuid->packet->tag == OPENPGP_PACKET_UID) {
				printf("uid:");
				for (i = 0; i < (int) curuid->packet->length;
						i++) {
					c = curuid->packet->data[i];
					if (c == '%') {
						putchar('%');
						putchar(c);
					} else if (c == ':' || c > 127) {
						printf("%%%X", c);
					} else {
						putchar(c);
					}
				}
				printf("\n");
			}
		}
		keys = keys->next;
	}
	return 0;
}
