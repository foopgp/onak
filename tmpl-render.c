/*
 * tmpl-render.c - Standalone exerciser for the template engine.
 *
 * Reads a template from the file named on the command line and renders
 * it against a small hand-built context tree. Intended both as a smoke
 * test for the template engine and as a worked example for anyone
 * authoring a new template.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mneme (u5001777236237.945e_43.30_005.38) <mneme@foopgp.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "template.h"

static struct tmpl_value *make_context(void)
{
	struct tmpl_value *root = tmpl_map();
	struct tmpl_value *opts = tmpl_map();
	struct tmpl_value *keys = tmpl_list();
	struct tmpl_value *k;
	struct tmpl_value *uids;
	struct tmpl_value *uid;

	tmpl_map_set(opts, "html", tmpl_bool(true));
	tmpl_map_set(opts, "verbose", tmpl_bool(false));
	tmpl_map_set(opts, "fingerprint", tmpl_bool(false));
	tmpl_map_set(opts, "skshash", tmpl_bool(false));
	tmpl_map_set(root, "opts", opts);

	k = tmpl_map();
	tmpl_map_set(k, "bits_padded", tmpl_string(" 4096"));
	tmpl_map_set(k, "algo_char", tmpl_string("R"));
	tmpl_map_set(k, "keyid_hex16", tmpl_string("0E3A94C3E83002DA"));
	tmpl_map_set(k, "date_str", tmpl_string("2008/06/03"));
	tmpl_map_set(k, "revoked", tmpl_bool(false));
	tmpl_map_set(k, "has_primary_uid", tmpl_bool(true));
	tmpl_map_set(k, "primary_uid",
		tmpl_string("Jonathan McDowell <noodles@earth.li>"));
	uids = tmpl_list();
	uid = tmpl_map();
	tmpl_map_set(uid, "text", tmpl_string("Other UID with <markup>"));
	tmpl_list_append(uids, uid);
	uid = tmpl_map();
	tmpl_map_set(uid, "text", tmpl_string("More UID"));
	tmpl_list_append(uids, uid);
	tmpl_map_set(k, "other_uids", uids);
	tmpl_list_append(keys, k);

	tmpl_map_set(root, "keys", keys);
	return root;
}

int main(int argc, char *argv[])
{
	char *source;
	struct tmpl_value *root;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s TEMPLATE\n", argv[0]);
		return 2;
	}
	source = tmpl_load_file(argv[1]);
	if (source == NULL) {
		fprintf(stderr, "could not read %s\n", argv[1]);
		return 1;
	}
	root = make_context();
	rc = tmpl_render(source, root, tmpl_putc_stdout, NULL);
	tmpl_free(root);
	free(source);
	return rc < 0 ? 1 : 0;
}
