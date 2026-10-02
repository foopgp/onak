/*
 * lookup.c - CGI to lookup keys.
 *
 * Copyright 2002-2005,2007-2009,2011 Jonathan McDowell <noodles@earth.li>
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "build-config.h"

#include "armor.h"
#include "charfuncs.h"
#include "cleankey.h"
#include "cleanup.h"
#include "getcgi.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "photoid.h"

#define OP_UNKNOWN 0
#define OP_GET     1
#define OP_INDEX   2
#define OP_VINDEX  3
#define OP_PHOTO   4
#define OP_HGET    5

/*
 * How many searches one op=get may carry: the largest round number whose
 * request line -- 74 bytes a v6 fingerprint, "&search=0x" included -- fits
 * under the 8 KB that Apache and nginx accept by default. Announced to the
 * client in X-HKP-Multi-Search on every get.
 */
#define MULTI_SEARCH_MAX 100

/*
 * The header block, once the answer is known: a status first when it is not
 * 200, then the type. Written after the lookup rather than before it,
 * because a header written first cannot say that nothing was found.
 */
static void headers(const char *status, bool html)
{
	if (status != NULL) {
		printf("Status: %s\n", status);
	}
	if (html) {
		start_html("Lookup of key");
	} else {
		puts("Content-Type: text/plain\n");
	}
}

void find_keys(struct onak_dbctx *dbctx,
		char *search, uint64_t keyid,
		struct openpgp_fingerprint *fingerprint,
		bool ishex, bool isfp, bool dispfp, bool skshash,
		__unused bool exact, bool verbose, bool mrhkp)
{
	struct openpgp_publickey *publickey = NULL;
	int count = 0;

	if (ishex) {
		count = dbctx->fetch_key_id(dbctx, keyid, &publickey,
				false);
	} else if (isfp) {
		count = dbctx->fetch_key_fp(dbctx, fingerprint, &publickey,
				false);
	} else {
		count = dbctx->fetch_key_text(dbctx, search, &publickey);
	}
	if (publickey != NULL) {
		headers(NULL, !mrhkp);
		if (mrhkp) {
			printf("info:1:%d\n", count);
			mrkey_index(publickey);
		} else {
			key_index(dbctx, publickey, verbose, dispfp,
				skshash, true);
		}
		free_publickey(publickey);
	} else if (count == 0) {
		/* The HKP draft asks the same 404 of an index as of a get. */
		headers("404 Not Found", !mrhkp);
		if (mrhkp) {
			puts("info:1:0");
		} else {
			/*
			 * Route the empty state through the template so the
			 * foopgp flavour can localise "Key not found." across
			 * the same navigator.language table it uses for the
			 * rest of the page, and both flavours can prefix an
			 * ❌ emoji that reads as "not found" regardless of
			 * the visitor's real reading language.
			 */
			key_index(dbctx, NULL, verbose, dispfp, skshash, true);
		}
	} else {
		headers(NULL, !mrhkp);
		if (mrhkp) {
			puts("info:1:0");
		} else {
			printf("Found %d keys, but maximum number to return"
				" is %d.\n",
				count,
				config.maxkeys);
			puts("Try again with a more specific search.");
		}
	}
}

static uint8_t hex2bin(char c)
{
	if (c >= '0' && c <= '9') {
		return (c - '0');
	} else if (c >= 'a' && c <= 'f') {
		return (c - 'a' + 10);
	} else if (c >= 'A' && c <= 'F') {
		return (c - 'A' + 10);
	}

	return 255;
}

/* Whether [s] is [n] hex digits and nothing else. */
static bool all_hex(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (hex2bin(s[i]) == 255) {
			return false;
		}
	}
	return s[n] == 0;
}

/* Whether [search] is written as a key ID or a fingerprint: it opens with 0x. */
static bool is_0x(const char *search)
{
	return search[0] == '0' && (search[1] == 'x' || search[1] == 'X');
}

/*
 * What a search names: a v4 or v6 fingerprint written 0x and its hex, a long
 * key ID -- 16 hex digits, with or without 0x --, or else text. A short key
 * ID of 8 is neither: 32 bits collide by design, and the HKP draft forbids
 * answering one. A 0x search that is neither is refused by the caller, not
 * read as text.
 */
static void parse_search(const char *search, uint64_t *keyid,
		struct openpgp_fingerprint *fingerprint,
		bool *ishex, bool *isfp)
{
	const char *hex = is_0x(search) ? search + 2 : search;
	size_t len = strlen(hex);
	int j;

	*ishex = false;
	*isfp = false;
	if (is_0x(search) && (len == 40 || len == 64) && all_hex(hex, len)) {
		fingerprint->length = len / 2;
		for (j = 0; j < fingerprint->length; j++) {
			fingerprint->fp[j] = (hex2bin(hex[j * 2]) << 4) +
				hex2bin(hex[j * 2 + 1]);
		}
		*isfp = true;
	} else if (len == 16 && all_hex(hex, len)) {
		*keyid = strtoull(hex, NULL, 16);
		*ishex = true;
	}
}

/* Whether [keys] already holds [key], by fingerprint. */
static bool held(struct openpgp_publickey *keys, struct openpgp_publickey *key)
{
	struct openpgp_fingerprint a, b;

	if (get_fingerprint(key->publickey, &a) != ONAK_E_OK) {
		return false;
	}
	for (; keys != NULL; keys = keys->next) {
		if (get_fingerprint(keys->publickey, &b) == ONAK_E_OK &&
				a.length == b.length &&
				!memcmp(a.fp, b.fp, a.length)) {
			return true;
		}
	}
	return false;
}

/*
 * Several searches in one get, each a key ID or a fingerprint written 0x:
 * text is left out, being the one search that can match thousands. Each is
 * fetched into a list of its own, and the keys joined once each -- two
 * searches may name one key. Returns how many keys, or -1 when a search is
 * not a 0x one, before anything is fetched.
 */
static int fetch_many(struct onak_dbctx *dbctx, char **searches, int n,
		struct openpgp_publickey **keys)
{
	struct openpgp_publickey *found, *key, *next;
	struct openpgp_publickey **tail = keys;
	struct openpgp_fingerprint fingerprint;
	uint64_t keyid = 0;
	bool ishex, isfp;
	int i, count = 0;

	for (i = 0; i < n; i++) {
		if (!is_0x(searches[i])) {
			return -1;
		}
		parse_search(searches[i], &keyid, &fingerprint, &ishex, &isfp);
		if (!ishex && !isfp) {
			return -1;
		}
	}
	for (i = 0; i < n; i++) {
		found = NULL;
		parse_search(searches[i], &keyid, &fingerprint, &ishex, &isfp);
		if (isfp) {
			dbctx->fetch_key_fp(dbctx, &fingerprint, &found, false);
		} else {
			dbctx->fetch_key_id(dbctx, keyid, &found, false);
		}
		for (key = found; key != NULL; key = next) {
			next = key->next;
			key->next = NULL;
			if (held(*keys, key)) {
				free_publickey(key);
				continue;
			}
			*tail = key;
			tail = &key->next;
			count++;
		}
	}
	return count;
}

int main(int argc, char *argv[])
{
	char **params = NULL;
	int op = OP_UNKNOWN;
	int i;
	int indx = 0;
	bool dispfp = false;
	bool skshash = false;
	bool exact = false;
	bool ishex = false;
	bool isfp = false;
	bool mrhkp = false;
	uint64_t keyid = 0;
	struct openpgp_fingerprint fingerprint;
	char *search = NULL;
	char *searches[MULTI_SEARCH_MAX];
	int nsearch = 0;
	bool toomany = false;
	char *contact_copy = NULL;
	struct openpgp_publickey *publickey = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	int result;
	struct skshash hash;
	struct onak_dbctx *dbctx;

	params = getcgivars(argc, argv);
	for (i = 0; params != NULL && params[i] != NULL; i += 2) {
		if (!strcmp(params[i], "op")) {
			if (!strcmp(params[i+1], "get")) {
				op = OP_GET;
			} else if (!strcmp(params[i+1], "hget")) {
				op = OP_HGET;
			} else if (!strcmp(params[i+1], "index")) {
				op = OP_INDEX;
			} else if (!strcmp(params[i+1], "vindex")) {
				op = OP_VINDEX;
			} else if (!strcmp(params[i+1], "photo")) {
				op = OP_PHOTO;
			}
		} else if (!strcmp(params[i], "search")) {
			/* Every one kept, for op=get; the others read the last. */
			if (params[i+1] == NULL) {
				/* nothing to keep */
			} else if (nsearch < MULTI_SEARCH_MAX) {
				searches[nsearch++] = params[i+1];
				params[i+1] = NULL;
			} else {
				toomany = true;
			}
		} else if (!strcmp(params[i], "idx")) {
			indx = atoi(params[i+1]);
		} else if (!strcmp(params[i], "fingerprint")) {
			if (!strcmp(params[i+1], "on")) {
				dispfp = true;
			}
		} else if (!strcmp(params[i], "hash")) {
			if (!strcmp(params[i+1], "on")) {
				skshash = true;
			}
		} else if (!strcmp(params[i], "exact")) {
			if (!strcmp(params[i+1], "on")) {
				exact = true;
			}
		} else if (!strcmp(params[i], "options")) {
			/*
			 * TODO: We should be smarter about this; options may
			 * have several entries. For now mr is the only valid
			 * one though.
			 */
			if (!strcmp(params[i+1], "mr")) {
				mrhkp = true;
			}
		}
		free(params[i]);
		params[i] = NULL;
		if (params[i+1] != NULL) {
			free(params[i+1]);
			params[i+1] = NULL;
		}
	}
	if (params != NULL) {
		free(params);
		params = NULL;
	}
	if (nsearch > 0) {
		search = searches[nsearch - 1];
		parse_search(search, &keyid, &fingerprint, &ishex, &isfp);
	}

	/*
	 * op=get / op=hget response is served as a downloadable .asc file
	 * (application/pgp-keys, Content-Disposition: attachment) rather
	 * than inline HTML — a mobile visitor can then hand the file off
	 * to OpenKeychain, GPG Keychain, Kleopatra, etc. via the OS'
	 * usual "open with" dance. Headers are deferred to the fetch
	 * branch below so we can put the actual key fingerprint into the
	 * filename. HKP-protocol clients (gpg --recv-keys) are unaffected
	 * — they never parsed Content-Disposition and now finally see the
	 * spec-compliant Content-Type instead of text/html.
	 */
	bool is_download = (op == OP_GET || op == OP_HGET);

	/* Let in-browser tools (e.g. the vendored html/pgp2vcard.html) read our
	 * responses cross-origin: everything served here is public key material. */
	puts("Access-Control-Allow-Origin: *");

	/*
	 * Every operation writes its own headers once it knows its answer: a
	 * download its key's type and name, a lookup that found nothing its
	 * 404, a photo its image. A header block closed up front sent those
	 * into the body instead.
	 */
	bool html = !mrhkp && !is_download && op != OP_PHOTO;

	if (op == OP_UNKNOWN) {
		headers(NULL, html);
		puts("Error: No operation supplied.");
	} else if (search == NULL) {
		headers(NULL, html);
		puts("Error: No key to search for supplied.");
	} else if (op != OP_HGET && op != OP_PHOTO && nsearch == 1 &&
			is_0x(search) && !ishex && !isfp) {
		headers("400 Bad Request", html);
		puts("Error: a 0x search is a key ID of 16 hex digits or a "
			"fingerprint of 40 or 64; short key IDs are not accepted.");
	} else {
		readconfig(NULL);
		initlogthing("lookup", config.logfile);
		catchsignals();
		dbctx = config.dbinit(config.backend, false);
		if (dbctx == NULL) {
			logthing(LOGTHING_ERROR,
				"Failed to open key database.");
			headers(NULL, html);
			if (!html) {
				puts("Key database unavailable");
			}
			goto err;
		}
		switch (op) {
		case OP_GET:
		case OP_HGET:
			if (op == OP_GET) {
				/* On every get, so a client learns it from the
				 * first answer, whatever that answer is. */
				printf("X-HKP-Multi-Search: %d\n",
					MULTI_SEARCH_MAX);
			}
			if (op == OP_GET && toomany) {
				headers("413 Content Too Large", false);
				printf("At most %d searches in one request.\n",
					MULTI_SEARCH_MAX);
				break;
			}
			if (op == OP_GET && nsearch > 1) {
				result = fetch_many(dbctx, searches, nsearch,
					&publickey);
				if (result < 0) {
					headers("400 Bad Request", false);
					puts("Several searches must each be "
						"a 0x key ID or fingerprint.");
					break;
				}
			} else if (op == OP_HGET) {
				parse_skshash(search, &hash);
				result = dbctx->fetch_key_skshash(dbctx,
					&hash, &publickey);
			} else if (ishex) {
				result = dbctx->fetch_key_id(dbctx, keyid,
					&publickey, false);
			} else if (isfp) {
				result = dbctx->fetch_key_fp(dbctx,
					&fingerprint, &publickey, false);
			} else {
				result = dbctx->fetch_key_text(dbctx,
					search,
					&publickey);
			}
			if (result) {
				struct openpgp_fingerprint got_fp;
				char fpbuf[65];
				int fi;
				logthing(LOGTHING_NOTICE,
					"Found %d key(s) for search %s",
					result,
					search);
				/*
				 * Emit the download headers now, using the
				 * fetched key's own fingerprint as filename.
				 * If get_fingerprint ever fails on an
				 * in-memory key (shouldn't happen), fall
				 * back to a plain Content-Type with no
				 * attachment name.
				 */
				if (publickey->next == NULL &&
						get_fingerprint(
							publickey->publickey,
							&got_fp) == ONAK_E_OK) {
					for (fi = 0; fi < got_fp.length;
							fi++) {
						snprintf(fpbuf + fi * 2,
							sizeof(fpbuf) -
								fi * 2,
							"%02X",
							got_fp.fp[fi]);
					}
					fpbuf[got_fp.length * 2] = '\0';
					printf("Content-Type: "
						"application/pgp-keys\n"
						"Content-Disposition: "
						"attachment; "
						"filename=\"0x%s.asc\""
						"\n\n",
						fpbuf);
				} else {
					puts("Content-Type: "
						"application/pgp-keys\n");
				}
				cleankeys(dbctx, &publickey,
						config.clean_policies);
				flatten_publickey(publickey,
							&packets,
							&list_end);
				armor_openpgp_stream(stdout_putchar,
						NULL,
						packets);
			} else {
				logthing(LOGTHING_NOTICE,
					"Failed to find key for search %s",
					search);
				/* The HKP draft's answer, and the only one a
				 * client can tell from a certificate. */
				headers("404 Not Found", false);
				puts("Key not found");
			}
			break;
		case OP_INDEX:
			find_keys(dbctx, search, keyid, &fingerprint,
					ishex, isfp, dispfp, skshash,
					exact, false, mrhkp);
			break;
		case OP_VINDEX:
			find_keys(dbctx, search, keyid, &fingerprint,
					ishex, isfp, dispfp, skshash,
					exact, true, mrhkp);
			break;
		case OP_PHOTO:
			if (isfp) {
				dbctx->fetch_key_fp(dbctx, &fingerprint,
					&publickey, false);
			} else {
				dbctx->fetch_key_id(dbctx, keyid,
					&publickey, false);
			}
			if (publickey != NULL) {
				unsigned char *photo = NULL;
				size_t         length = 0;

				if (getphoto(publickey, indx, &photo,
						&length) == ONAK_E_OK) {
					puts("Content-Type: image/jpeg\n");
					fwrite(photo,
							1,
							length,
							stdout);
				} else {
					headers("404 Not Found", false);
					puts("No photo at that index.");
				}
				free_publickey(publickey);
				publickey = NULL;
			} else {
				headers("404 Not Found", false);
				puts("No such key.");
			}
			break;
		default:
			puts("Unknown operation!");
		}
		dbctx->cleanupdb(dbctx);
err:
		cleanuplogthing();
		/*
		 * The footer below reads config.server_contact, so we
		 * stash a copy now and free it after the page is out,
		 * since cleanupconfig() frees the original.
		 */
		if (config.server_contact != NULL &&
				config.server_contact[0] != '\0') {
			contact_copy = strdup(config.server_contact);
		}
		cleanupconfig();
	}
	if (!mrhkp && !is_download && op != OP_PHOTO) {
		puts("<hr>");
		puts(" &mdash; onak " ONAK_VERSION " &mdash;");
		puts(" <a href=\"../\"> .. </a> &mdash;");
		if (contact_copy != NULL) {
			puts(" <a href=\"lookup?op=index&amp;search=");
			fputs(contact_copy, stdout);
			puts("\">contact</a>");
		}
		end_html();
	}
	if (contact_copy != NULL) {
		free(contact_copy);
		contact_copy = NULL;
	}

	for (i = 0; i < nsearch; i++) {
		free(searches[i]);
	}

	return (EXIT_SUCCESS);
}
