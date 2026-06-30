/*
 * template.h - Minimal Mustache-style template engine for onak.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mneme (u5=001777236237.945e_43.30_005.38) <mneme@foopgp.org>
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

#ifndef __TEMPLATE_H__
#define __TEMPLATE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/*
 * Supported syntax:
 *   {{var}}            HTML-escaped variable substitution
 *   {{{var}}}          raw substitution (no escaping)
 *   {{#section}}...{{/section}}    section: render body when value is truthy
 *                                  or once per item if value is a list
 *   {{^section}}...{{/section}}    inverted section: render body when value
 *                                  is falsy / empty list
 *   {{!comment}}       ignored. The body must not contain two
 *                      consecutive close-mustache chars: the parser
 *                      closes the comment on the first occurrence
 *                      (Mustache spec leaves this implementation-
 *                      defined; we take the naive route).
 *
 * Variable names accept dotted paths (foo.bar.baz). The lookup walks
 * the current context stack from innermost section outwards. The
 * special name "." refers to the current context value itself, which
 * is useful inside list sections of strings.
 */

enum tmpl_kind {
	TMPL_NULL = 0,
	TMPL_BOOL,
	TMPL_INT,
	TMPL_STRING,
	TMPL_LIST,
	TMPL_MAP,
};

struct tmpl_value;

struct tmpl_pair {
	char *key;
	struct tmpl_value *value;
};

struct tmpl_value {
	enum tmpl_kind kind;
	union {
		bool b;
		long long i;
		struct {
			char *p;          /* always heap-owned by the value */
			size_t len;
		} s;
		struct {
			struct tmpl_value **items;
			size_t count;
			size_t cap;
		} list;
		struct {
			struct tmpl_pair *pairs;
			size_t count;
			size_t cap;
		} map;
	} u;
};

/* Constructors. They all return a heap-owned value that the caller
 * must eventually free with tmpl_free(). */
struct tmpl_value *tmpl_null(void);
struct tmpl_value *tmpl_bool(bool b);
struct tmpl_value *tmpl_int(long long i);
struct tmpl_value *tmpl_string(const char *s);          /* strdup */
struct tmpl_value *tmpl_string_n(const char *s, size_t n);
struct tmpl_value *tmpl_string_take(char *s);           /* takes ownership */
struct tmpl_value *tmpl_list(void);
struct tmpl_value *tmpl_map(void);

/* Container mutators. tmpl_list_append() and tmpl_map_set() both take
 * ownership of @item / @value; callers should not free them. The map
 * setter replaces any existing entry for @key. */
void tmpl_list_append(struct tmpl_value *list, struct tmpl_value *item);
void tmpl_map_set(struct tmpl_value *map, const char *key,
		struct tmpl_value *value);

/* Recursively free a tmpl_value tree. NULL-safe. */
void tmpl_free(struct tmpl_value *v);

/* Output sink. tmpl_render() writes one character at a time through
 * @out. Return non-zero to abort rendering. */
typedef int (*tmpl_putc)(int c, void *ctx);

/* Stdout helper. Pass NULL as ctx. */
int tmpl_putc_stdout(int c, void *ctx);

/* Render @template (a NUL-terminated string) with @root as the
 * top-level context. Returns 0 on success, negative on parse or
 * lookup errors. */
int tmpl_render(const char *template, struct tmpl_value *root,
		tmpl_putc out, void *ctx);

/* Read a whole file into a heap-allocated NUL-terminated buffer.
 * Caller frees. Returns NULL on error. */
char *tmpl_load_file(const char *path);

/* Resolve @name (e.g. "key_index.html") against the active template
 * directory: config.template_dir if set, otherwise the compile-time
 * TEMPLATEDIR. Returns a heap-allocated NUL-terminated template
 * source, NULL on error. Caller frees. */
char *tmpl_load_named(const char *name);

#endif
