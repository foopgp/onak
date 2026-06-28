/*
 * template.c - Minimal Mustache-style template engine for onak.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "build-config.h"
#include "log.h"
#include "onak-conf.h"
#include "template.h"

#ifndef TEMPLATEDIR
#define TEMPLATEDIR "/usr/share/onak/templates"
#endif

/* ---------- value construction --------------------------------------- */

static struct tmpl_value *value_new(enum tmpl_kind k)
{
	struct tmpl_value *v = calloc(1, sizeof(*v));
	if (v != NULL) {
		v->kind = k;
	}
	return v;
}

struct tmpl_value *tmpl_null(void)
{
	return value_new(TMPL_NULL);
}

struct tmpl_value *tmpl_bool(bool b)
{
	struct tmpl_value *v = value_new(TMPL_BOOL);
	if (v != NULL) {
		v->u.b = b;
	}
	return v;
}

struct tmpl_value *tmpl_int(long long i)
{
	struct tmpl_value *v = value_new(TMPL_INT);
	if (v != NULL) {
		v->u.i = i;
	}
	return v;
}

struct tmpl_value *tmpl_string_n(const char *s, size_t n)
{
	struct tmpl_value *v;
	char *copy;

	if (s == NULL) {
		return tmpl_null();
	}
	copy = malloc(n + 1);
	if (copy == NULL) {
		return NULL;
	}
	memcpy(copy, s, n);
	copy[n] = '\0';
	v = value_new(TMPL_STRING);
	if (v == NULL) {
		free(copy);
		return NULL;
	}
	v->u.s.p = copy;
	v->u.s.len = n;
	return v;
}

struct tmpl_value *tmpl_string(const char *s)
{
	return s == NULL ? tmpl_null() : tmpl_string_n(s, strlen(s));
}

struct tmpl_value *tmpl_string_take(char *s)
{
	struct tmpl_value *v;
	if (s == NULL) {
		return tmpl_null();
	}
	v = value_new(TMPL_STRING);
	if (v == NULL) {
		free(s);
		return NULL;
	}
	v->u.s.p = s;
	v->u.s.len = strlen(s);
	return v;
}

struct tmpl_value *tmpl_list(void)
{
	return value_new(TMPL_LIST);
}

struct tmpl_value *tmpl_map(void)
{
	return value_new(TMPL_MAP);
}

void tmpl_list_append(struct tmpl_value *list, struct tmpl_value *item)
{
	if (list == NULL || list->kind != TMPL_LIST) {
		tmpl_free(item);
		return;
	}
	if (list->u.list.count == list->u.list.cap) {
		size_t newcap = list->u.list.cap ? list->u.list.cap * 2 : 4;
		struct tmpl_value **g = realloc(list->u.list.items,
			newcap * sizeof(*g));
		if (g == NULL) {
			tmpl_free(item);
			return;
		}
		list->u.list.items = g;
		list->u.list.cap = newcap;
	}
	list->u.list.items[list->u.list.count++] = item;
}

void tmpl_map_set(struct tmpl_value *map, const char *key,
		struct tmpl_value *value)
{
	size_t i;
	char *kdup;

	if (map == NULL || map->kind != TMPL_MAP || key == NULL) {
		tmpl_free(value);
		return;
	}
	for (i = 0; i < map->u.map.count; i++) {
		if (strcmp(map->u.map.pairs[i].key, key) == 0) {
			tmpl_free(map->u.map.pairs[i].value);
			map->u.map.pairs[i].value = value;
			return;
		}
	}
	if (map->u.map.count == map->u.map.cap) {
		size_t newcap = map->u.map.cap ? map->u.map.cap * 2 : 8;
		struct tmpl_pair *g = realloc(map->u.map.pairs,
			newcap * sizeof(*g));
		if (g == NULL) {
			tmpl_free(value);
			return;
		}
		map->u.map.pairs = g;
		map->u.map.cap = newcap;
	}
	kdup = strdup(key);
	if (kdup == NULL) {
		tmpl_free(value);
		return;
	}
	map->u.map.pairs[map->u.map.count].key = kdup;
	map->u.map.pairs[map->u.map.count].value = value;
	map->u.map.count++;
}

void tmpl_free(struct tmpl_value *v)
{
	size_t i;

	if (v == NULL) {
		return;
	}
	switch (v->kind) {
	case TMPL_STRING:
		free(v->u.s.p);
		break;
	case TMPL_LIST:
		for (i = 0; i < v->u.list.count; i++) {
			tmpl_free(v->u.list.items[i]);
		}
		free(v->u.list.items);
		break;
	case TMPL_MAP:
		for (i = 0; i < v->u.map.count; i++) {
			free(v->u.map.pairs[i].key);
			tmpl_free(v->u.map.pairs[i].value);
		}
		free(v->u.map.pairs);
		break;
	default:
		break;
	}
	free(v);
}

/* ---------- context stack + value lookup ----------------------------- */

struct tmpl_ctx_frame {
	struct tmpl_value *value;
	struct tmpl_ctx_frame *parent;
};

static struct tmpl_value *map_get(struct tmpl_value *map, const char *key,
		size_t klen)
{
	size_t i;
	if (map == NULL || map->kind != TMPL_MAP) {
		return NULL;
	}
	for (i = 0; i < map->u.map.count; i++) {
		if (strncmp(map->u.map.pairs[i].key, key, klen) == 0 &&
				map->u.map.pairs[i].key[klen] == '\0') {
			return map->u.map.pairs[i].value;
		}
	}
	return NULL;
}

/*
 * Resolve a dotted name like "foo.bar.baz" against the context stack.
 * The first segment is looked up in each frame from innermost to
 * outermost; subsequent segments walk down into maps. The special
 * single-character name "." returns the current frame's value.
 */
static struct tmpl_value *lookup(struct tmpl_ctx_frame *frame,
		const char *name, size_t name_len)
{
	const char *dot;
	size_t first_len;
	struct tmpl_value *cur = NULL;
	struct tmpl_ctx_frame *f;

	if (name_len == 1 && name[0] == '.') {
		return frame ? frame->value : NULL;
	}

	dot = memchr(name, '.', name_len);
	first_len = dot ? (size_t) (dot - name) : name_len;

	for (f = frame; f != NULL; f = f->parent) {
		cur = map_get(f->value, name, first_len);
		if (cur != NULL) {
			break;
		}
	}
	if (cur == NULL) {
		return NULL;
	}

	while (dot != NULL) {
		const char *seg = dot + 1;
		size_t remain = name_len - (seg - name);
		const char *next = memchr(seg, '.', remain);
		size_t seglen = next ? (size_t) (next - seg) : remain;
		cur = map_get(cur, seg, seglen);
		if (cur == NULL) {
			return NULL;
		}
		dot = next;
	}
	return cur;
}

/* ---------- truthiness + output -------------------------------------- */

static bool truthy(struct tmpl_value *v)
{
	if (v == NULL) {
		return false;
	}
	switch (v->kind) {
	case TMPL_NULL: return false;
	case TMPL_BOOL: return v->u.b;
	case TMPL_INT:  return v->u.i != 0;
	case TMPL_STRING: return v->u.s.len > 0;
	case TMPL_LIST: return v->u.list.count > 0;
	case TMPL_MAP:  return true;
	}
	return false;
}

int tmpl_putc_stdout(int c, __attribute__((unused)) void *ctx)
{
	return putchar(c);
}

static int emit_str(const char *s, size_t n, tmpl_putc out, void *ctx)
{
	size_t i;
	int rc;
	for (i = 0; i < n; i++) {
		rc = out((unsigned char) s[i], ctx);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

static int emit_escaped(const char *s, size_t n, tmpl_putc out, void *ctx)
{
	size_t i;
	int rc;
	const char *rep;
	size_t replen;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char) s[i];
		switch (c) {
		case '<':  rep = "&lt;";   replen = 4; break;
		case '>':  rep = "&gt;";   replen = 4; break;
		case '&':  rep = "&amp;";  replen = 5; break;
		case '"':  rep = "&quot;"; replen = 6; break;
		case '\'': rep = "&#39;";  replen = 5; break;
		default:
			rc = out(c, ctx);
			if (rc < 0) {
				return rc;
			}
			continue;
		}
		rc = emit_str(rep, replen, out, ctx);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

static int emit_value(struct tmpl_value *v, bool escape,
		tmpl_putc out, void *ctx)
{
	char buf[32];
	int n;

	if (v == NULL || v->kind == TMPL_NULL) {
		return 0;
	}
	switch (v->kind) {
	case TMPL_BOOL:
		return emit_str(v->u.b ? "true" : "false",
				v->u.b ? 4 : 5, out, ctx);
	case TMPL_INT:
		n = snprintf(buf, sizeof(buf), "%lld", v->u.i);
		if (n < 0) {
			return -1;
		}
		return emit_str(buf, (size_t) n, out, ctx);
	case TMPL_STRING:
		return escape
			? emit_escaped(v->u.s.p, v->u.s.len, out, ctx)
			: emit_str(v->u.s.p, v->u.s.len, out, ctx);
	case TMPL_LIST:
	case TMPL_MAP:
	case TMPL_NULL:
		return 0;
	}
	return 0;
}

/* ---------- template rendering --------------------------------------- */

/*
 * Find the matching {{/name}} or {{#name}}/{{^name}} for nesting count
 * tracking. Returns a pointer to the start of the closing tag, or NULL
 * on imbalance.
 */
static const char *find_section_end(const char *body, const char *name,
		size_t name_len)
{
	int depth = 1;
	const char *p = body;

	while (*p != '\0') {
		if (p[0] != '{' || p[1] != '{') {
			p++;
			continue;
		}
		const char *open = p;
		p += 2;
		while (*p == ' ' || *p == '\t') p++;
		char tag = *p;
		if (tag == '#' || tag == '^' || tag == '/') {
			p++;
			while (*p == ' ' || *p == '\t') p++;
			const char *tname = p;
			while (*p != '}' && *p != ' ' && *p != '\t' &&
					*p != '\0') {
				p++;
			}
			size_t tnlen = (size_t) (p - tname);
			while (*p == ' ' || *p == '\t') p++;
			if (p[0] == '}' && p[1] == '}') {
				if (tnlen == name_len &&
						memcmp(tname, name, name_len) == 0) {
					if (tag == '/') {
						depth--;
						if (depth == 0) {
							return open;
						}
					} else {
						depth++;
					}
				}
				p += 2;
			}
		} else if (tag == '!') {
			while (*p != '\0' &&
					!(p[0] == '}' && p[1] == '}')) {
				p++;
			}
			if (*p != '\0') {
				p += 2;
			}
		} else if (tag == '{') {
			/* triple-mustache {{{var}}} */
			p++;
			while (*p != '\0' &&
					!(p[0] == '}' && p[1] == '}' &&
						p[2] == '}')) {
				p++;
			}
			if (*p != '\0') {
				p += 3;
			}
		} else {
			while (*p != '\0' &&
					!(p[0] == '}' && p[1] == '}')) {
				p++;
			}
			if (*p != '\0') {
				p += 2;
			}
		}
	}
	return NULL;
}

static int render_range(const char *begin, const char *end,
		struct tmpl_ctx_frame *frame,
		tmpl_putc out, void *ctx);

static int render_section(const char *body, const char *body_end,
		struct tmpl_value *value, bool inverted,
		struct tmpl_ctx_frame *parent,
		tmpl_putc out, void *ctx)
{
	struct tmpl_ctx_frame new_frame;
	bool tval = truthy(value);
	int rc = 0;
	size_t i;

	if (inverted) {
		if (tval) {
			return 0;
		}
		new_frame.value = value;
		new_frame.parent = parent;
		return render_range(body, body_end, &new_frame, out, ctx);
	}

	if (!tval) {
		return 0;
	}

	if (value->kind == TMPL_LIST) {
		for (i = 0; i < value->u.list.count; i++) {
			new_frame.value = value->u.list.items[i];
			new_frame.parent = parent;
			rc = render_range(body, body_end, &new_frame, out, ctx);
			if (rc < 0) {
				return rc;
			}
		}
		return 0;
	}

	new_frame.value = value;
	new_frame.parent = parent;
	return render_range(body, body_end, &new_frame, out, ctx);
}

static int render_range(const char *begin, const char *end,
		struct tmpl_ctx_frame *frame,
		tmpl_putc out, void *ctx)
{
	const char *p = begin;
	int rc;

	while (p < end && *p != '\0') {
		if (p[0] != '{' || p[1] != '{') {
			rc = out((unsigned char) *p, ctx);
			if (rc < 0) {
				return rc;
			}
			p++;
			continue;
		}
		const char *tag_open = p;
		p += 2;
		while (p < end && (*p == ' ' || *p == '\t')) p++;
		if (p >= end) {
			break;
		}

		char tag_kind = *p;
		bool raw = false;
		bool is_section = false;
		bool inverted = false;

		if (tag_kind == '{') {
			raw = true;
			p++;
		} else if (tag_kind == '#') {
			is_section = true;
			p++;
		} else if (tag_kind == '^') {
			is_section = true;
			inverted = true;
			p++;
		} else if (tag_kind == '/') {
			/* Stray closing tag at this nesting level: ignored. */
			while (p < end &&
					!(p[0] == '}' && p[1] == '}')) {
				p++;
			}
			if (p < end) p += 2;
			continue;
		} else if (tag_kind == '!') {
			while (p < end &&
					!(p[0] == '}' && p[1] == '}')) {
				p++;
			}
			if (p < end) p += 2;
			continue;
		}

		while (p < end && (*p == ' ' || *p == '\t')) p++;
		const char *name = p;
		while (p < end && *p != ' ' && *p != '\t' &&
				*p != '}' && *p != '\0') {
			p++;
		}
		size_t name_len = (size_t) (p - name);
		while (p < end && (*p == ' ' || *p == '\t')) p++;
		if (raw) {
			if (p + 2 >= end || p[0] != '}' || p[1] != '}' ||
					p[2] != '}') {
				logthing(LOGTHING_ERROR,
					"template: malformed {{{...}}} tag");
				return -1;
			}
			p += 3;
		} else {
			if (p + 1 >= end || p[0] != '}' || p[1] != '}') {
				logthing(LOGTHING_ERROR,
					"template: malformed {{...}} tag");
				return -1;
			}
			p += 2;
		}

		struct tmpl_value *value = lookup(frame, name, name_len);

		if (is_section) {
			const char *body_end = find_section_end(p, name,
					name_len);
			if (body_end == NULL) {
				logthing(LOGTHING_ERROR,
					"template: unmatched section %.*s",
					(int) name_len, name);
				return -1;
			}
			const char *body_start = p;
			rc = render_section(body_start, body_end, value,
					inverted, frame, out, ctx);
			if (rc < 0) {
				return rc;
			}
			/* Skip past the {{/name}} closer. */
			p = body_end;
			while (p < end && !(p[0] == '}' && p[1] == '}')) {
				p++;
			}
			if (p < end) p += 2;
			(void) tag_open;
			continue;
		}

		rc = emit_value(value, !raw, out, ctx);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

int tmpl_render(const char *template, struct tmpl_value *root,
		tmpl_putc out, void *ctx)
{
	struct tmpl_ctx_frame frame = { root, NULL };
	size_t len;

	if (template == NULL || out == NULL) {
		return -1;
	}
	len = strlen(template);
	return render_range(template, template + len, &frame, out, ctx);
}

/* ---------- file loader ---------------------------------------------- */

char *tmpl_load_file(const char *path)
{
	FILE *f;
	long n;
	char *buf;
	size_t got;

	if (path == NULL) {
		return NULL;
	}
	f = fopen(path, "r");
	if (f == NULL) {
		logthing(LOGTHING_ERROR,
			"template: could not open %s", path);
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	n = ftell(f);
	if (n < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = malloc((size_t) n + 1);
	if (buf == NULL) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t) n, f);
	fclose(f);
	if (got != (size_t) n) {
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	return buf;
}

char *tmpl_load_named(const char *name)
{
	const char *dir;
	char *path;
	char *buf;
	int n;

	if (name == NULL || strchr(name, '/') != NULL) {
		return NULL;
	}
	dir = (config.template_dir != NULL && config.template_dir[0])
		? config.template_dir : TEMPLATEDIR;
	n = snprintf(NULL, 0, "%s/%s", dir, name);
	if (n < 0) {
		return NULL;
	}
	path = malloc((size_t) n + 1);
	if (path == NULL) {
		return NULL;
	}
	snprintf(path, (size_t) n + 1, "%s/%s", dir, name);
	buf = tmpl_load_file(path);
	free(path);
	return buf;
}
