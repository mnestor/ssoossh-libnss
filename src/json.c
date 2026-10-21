#include "json.h"

#include <string.h>

/* Static, so jsmn's own symbols cannot reach the host process even before the
 * version script hides them. The warning suppression is scoped to this
 * include: jsmn is vendored unmodified and pinned by hash (third_party/jsmn)
 * and moves freely between int and unsigned for its offsets, so it does not
 * compile clean under -Wconversion. Patching a vendored dependency would mean
 * carrying a fork; silencing it only here costs nothing, because every byte it
 * touches is bounded by the caller and the code below stays under the full
 * flag set. */
#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "../third_party/jsmn/jsmn.h"
#pragma GCC diagnostic pop

/* A userdb record is a few dozen tokens; 256 is room for a shape that grew
 * and a hard stop for one trying to make us walk a deep structure. Sized
 * modestly because each json call puts this array on the stack, and the
 * entry points run inside sshd and sudo. */
#define MAX_TOKENS 256

/* Writes one UTF-8 encoding of a code point. Only used from \uXXXX handling,
 * so the range is bounded. */
static bool put_utf8(uint32_t cp, char *out, size_t out_cap, size_t *w)
{
    size_t n = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;

    if (*w + n >= out_cap) {
        return false;
    }
    switch (n) {
    case 1:
        out[(*w)++] = (char)cp;
        break;
    case 2:
        out[(*w)++] = (char)(0xc0 | (cp >> 6));
        out[(*w)++] = (char)(0x80 | (cp & 0x3f));
        break;
    case 3:
        out[(*w)++] = (char)(0xe0 | (cp >> 12));
        out[(*w)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[(*w)++] = (char)(0x80 | (cp & 0x3f));
        break;
    default:
        out[(*w)++] = (char)(0xf0 | (cp >> 18));
        out[(*w)++] = (char)(0x80 | ((cp >> 12) & 0x3f));
        out[(*w)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[(*w)++] = (char)(0x80 | (cp & 0x3f));
        break;
    }
    return true;
}

static bool hex4(const char *p, uint32_t *out)
{
    uint32_t v = 0;

    for (int i = 0; i < 4; i++) {
        char c = p[i];
        uint32_t d;

        if (c >= '0' && c <= '9') {
            d = (uint32_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            d = (uint32_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            d = (uint32_t)(c - 'A' + 10);
        } else {
            return false;
        }
        v = v << 4 | d;
    }
    *out = v;
    return true;
}

/* JSON string unescaping. jsmn hands back the raw bytes between the quotes,
 * escapes and all. An unknown escape is rejected rather than guessed at. */
static bool unescape(const char *p, size_t len, char *out, size_t out_cap)
{
    size_t w = 0;

    for (size_t i = 0; i < len; i++) {
        if (p[i] != '\\') {
            if (w + 1 >= out_cap) {
                return false;
            }
            out[w++] = p[i];
            continue;
        }
        if (++i >= len) {
            return false;
        }
        if (p[i] != 'u' && w + 1 >= out_cap) {
            return false;
        }
        switch (p[i]) {
        case '"':
        case '\\':
        case '/':
            out[w++] = p[i];
            break;
        case 'b':
            out[w++] = '\b';
            break;
        case 'f':
            out[w++] = '\f';
            break;
        case 'n':
            out[w++] = '\n';
            break;
        case 'r':
            out[w++] = '\r';
            break;
        case 't':
            out[w++] = '\t';
            break;
        case 'u': {
            uint32_t cp;

            if (i + 4 >= len || !hex4(p + i + 1, &cp)) {
                return false;
            }
            i += 4;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                uint32_t low;

                if (i + 6 >= len || p[i + 1] != '\\' || p[i + 2] != 'u' ||
                    !hex4(p + i + 3, &low) || low < 0xdc00 || low > 0xdfff) {
                    return false;
                }
                i += 6;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                return false;
            }
            if (!put_utf8(cp, out, out_cap, &w)) {
                return false;
            }
            break;
        }
        default:
            return false;
        }
    }

    out[w] = '\0';
    return true;
}

static bool token_is(const char *body, const jsmntok_t *t, const char *name)
{
    size_t len = (size_t)(t->end - t->start);

    return t->type == JSMN_STRING && len == strlen(name) &&
           memcmp(body + t->start, name, len) == 0;
}

/* Skips a token and everything under it, returning the following index.
 * jsmn's array is a pre-order walk, so a nested object's children sit between
 * it and its next sibling. */
static int skip(const jsmntok_t *toks, int count, int i)
{
    int end = toks[i].end;
    int n = i + 1;

    while (n < count && toks[n].start < end) {
        n++;
    }
    return n;
}

/* Finds a key of the object at index obj, returning the index of its value or
 * -1. */
static int object_get(const char *body, const jsmntok_t *toks, int count,
                      int obj, const char *name)
{
    int i;

    if (obj < 0 || toks[obj].type != JSMN_OBJECT) {
        return -1;
    }
    i = obj + 1;
    for (int n = 0; n < toks[obj].size && i < count; n++) {
        int value = i + 1;

        if (value >= count) {
            return -1;
        }
        if (token_is(body, &toks[i], name)) {
            return value;
        }
        i = skip(toks, count, value);
    }
    return -1;
}

/* Parses body and returns the token index of o1.o2.field, or -1. On success
 * toks is filled and *count holds the token count. */
static int lookup(const char *body, size_t len, const char *o1, const char *o2,
                  const char *field, jsmntok_t *toks, int *count)
{
    jsmn_parser parser;
    int obj;

    if (len == 0 || len > JSON_MAX_BODY) {
        return -1;
    }
    jsmn_init(&parser);
    *count = jsmn_parse(&parser, body, len, toks, MAX_TOKENS);
    if (*count < 1 || toks[0].type != JSMN_OBJECT) {
        return -1;
    }

    obj = 0;
    if (o1 != NULL) {
        obj = object_get(body, toks, *count, obj, o1);
        if (obj < 0 || toks[obj].type != JSMN_OBJECT) {
            return -1;
        }
    }
    if (o2 != NULL) {
        obj = object_get(body, toks, *count, obj, o2);
        if (obj < 0 || toks[obj].type != JSMN_OBJECT) {
            return -1;
        }
    }
    return object_get(body, toks, *count, obj, field);
}

bool json_string(const char *body, size_t len, const char *o1, const char *o2,
                 const char *field, char *out, size_t out_cap)
{
    jsmntok_t toks[MAX_TOKENS];
    int count;
    int v = lookup(body, len, o1, o2, field, toks, &count);

    if (v < 0 || toks[v].type != JSMN_STRING) {
        return false;
    }
    return unescape(body + toks[v].start, (size_t)(toks[v].end - toks[v].start),
                    out, out_cap);
}

bool json_u32(const char *body, size_t len, const char *o1, const char *o2,
              const char *field, uint32_t *out)
{
    jsmntok_t toks[MAX_TOKENS];
    int count;
    int v = lookup(body, len, o1, o2, field, toks, &count);
    uint64_t acc = 0;
    int start, end;

    if (v < 0 || toks[v].type != JSMN_PRIMITIVE) {
        return false;
    }
    start = toks[v].start;
    end = toks[v].end;
    if (end <= start) {
        return false;
    }
    for (int i = start; i < end; i++) {
        char c = body[i];

        if (c < '0' || c > '9') {
            return false; /* a sign, a decimal point, true/false/null */
        }
        acc = acc * 10 + (uint64_t)(c - '0');
        if (acc > UINT32_MAX) {
            return false;
        }
    }
    *out = (uint32_t)acc;
    return true;
}

bool json_bool(const char *body, size_t len, const char *o1, const char *o2,
               const char *field, bool *out)
{
    jsmntok_t toks[MAX_TOKENS];
    int count;
    int v = lookup(body, len, o1, o2, field, toks, &count);
    size_t n;

    if (v < 0 || toks[v].type != JSMN_PRIMITIVE) {
        return false;
    }
    n = (size_t)(toks[v].end - toks[v].start);
    if (n == 4 && memcmp(body + toks[v].start, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (n == 5 && memcmp(body + toks[v].start, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

bool json_object_span(const char *body, size_t len, const char *o1,
                      const char *o2, const char *field, const char **obj,
                      size_t *obj_len)
{
    jsmntok_t toks[MAX_TOKENS];
    int count;
    int v = lookup(body, len, o1, o2, field, toks, &count);

    if (v < 0 || toks[v].type != JSMN_OBJECT) {
        return false;
    }
    *obj = body + toks[v].start;
    *obj_len = (size_t)(toks[v].end - toks[v].start);
    return true;
}
