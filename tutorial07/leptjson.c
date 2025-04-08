#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "leptjson.h"
#include <assert.h> /* assert() */
#include <errno.h>  /* errno, ERANGE */
#include <math.h>   /* HUGE_VAL */
#include <stdio.h>  /* sprintf() */
#include <stdlib.h> /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h> /* memcpy() */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(context, ch)             \
    do                                  \
    {                                   \
        assert(*context->json == (ch)); \
        context->json++;                \
    } while (0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')
#define PUTC(context, ch)                                         \
    do                                                            \
    {                                                             \
        *(char *)lept_context_push(context, sizeof(char)) = (ch); \
    } while (0)
#define PUTS(context, str, len) memcpy(lept_context_push(context, len), str, len)

typedef struct
{
    const char *json;
    char *stack;
    size_t size, top;
} lept_context;

/**
 * @brief 维护可变栈，重分配空间，返回首地址
 */
static void *lept_context_push(lept_context *context, size_t size)
{
    void *ret;
    assert(size > 0);
    if (context->top + size >= context->size)
    {
        if (context->size == 0)
            context->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (context->top + size >= context->size)
            context->size += context->size >> 1; /* context->size * 1.5 */
        context->stack = (char *)realloc(context->stack, context->size);
    }
    ret = context->stack + context->top;
    context->top += size;
    return ret;
}

static void *lept_context_pop(lept_context *context, size_t size)
{
    assert(context->top >= size);
    return context->stack + (context->top -= size);
}

static void lept_parse_whitespace(lept_context *context)
{
    const char *p = context->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    context->json = p;
}

static int lept_parse_literal(lept_context *context, lept_value *v, const char *literal, lept_type type)
{
    size_t i;
    EXPECT(context, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (context->json[i] != literal[i + 1])
            return LEPT_PARSE_INVALID_VALUE;
    context->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context *context, lept_value *v)
{
    const char *p = context->json;
    if (*p == '-')
        p++;
    if (*p == '0')
        p++;
    else
    {
        if (!ISDIGIT1TO9(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }
    if (*p == '.')
    {
        p++;
        if (!ISDIGIT(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }
    if (*p == 'e' || *p == 'E')
    {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        if (!ISDIGIT(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }
    errno = 0;
    v->u.number = strtod(context->json, NULL);
    if (errno == ERANGE && (v->u.number == HUGE_VAL || v->u.number == -HUGE_VAL))
        return LEPT_PARSE_NUMBER_TOO_BIG;
    v->type = LEPT_NUMBER;
    context->json = p;
    return LEPT_PARSE_OK;
}

static const char *lept_parse_hex4(const char *p, unsigned *u)
{
    int i;
    *u = 0;
    for (i = 0; i < 4; i++)
    {
        char ch = *p++;
        *u <<= 4;
        if (ch >= '0' && ch <= '9')
            *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F')
            *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f')
            *u |= ch - ('a' - 10);
        else
            return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context *context, unsigned u)
{
    if (u <= 0x7F)
        PUTC(context, u & 0xFF);
    else if (u <= 0x7FF)
    {
        PUTC(context, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(context, 0x80 | (u & 0x3F));
    }
    else if (u <= 0xFFFF)
    {
        PUTC(context, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(context, 0x80 | ((u >> 6) & 0x3F));
        PUTC(context, 0x80 | (u & 0x3F));
    }
    else
    {
        assert(u <= 0x10FFFF);
        PUTC(context, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(context, 0x80 | ((u >> 12) & 0x3F));
        PUTC(context, 0x80 | ((u >> 6) & 0x3F));
        PUTC(context, 0x80 | (u & 0x3F));
    }
}

#define STRING_ERROR(ret)    \
    do                       \
    {                        \
        context->top = head; \
        return ret;          \
    } while (0)

static int lept_parse_string_raw(lept_context *context, char **str, size_t *len)
{
    size_t head = context->top;
    unsigned u, u2;
    const char *p;
    EXPECT(context, '\"');
    p = context->json;
    for (;;)
    {
        char ch = *p++;
        switch (ch)
        {
        case '\"':
            *len = context->top - head;
            *str = lept_context_pop(context, *len);
            context->json = p;
            return LEPT_PARSE_OK;
        case '\\':
            switch (*p++)
            {
            case '\"':
                PUTC(context, '\"');
                break;
            case '\\':
                PUTC(context, '\\');
                break;
            case '/':
                PUTC(context, '/');
                break;
            case 'b':
                PUTC(context, '\b');
                break;
            case 'f':
                PUTC(context, '\f');
                break;
            case 'n':
                PUTC(context, '\n');
                break;
            case 'r':
                PUTC(context, '\r');
                break;
            case 't':
                PUTC(context, '\t');
                break;
            case 'u':
                if (!(p = lept_parse_hex4(p, &u)))
                    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                if (u >= 0xD800 && u <= 0xDBFF)
                { /* surrogate pair */
                    if (*p++ != '\\')
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    if (*p++ != 'u')
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    if (!(p = lept_parse_hex4(p, &u2)))
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                    if (u2 < 0xDC00 || u2 > 0xDFFF)
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                }
                lept_encode_utf8(context, u);
                break;
            default:
                STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
            }
            break;
        case '\0':
            STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
        default:
            if ((unsigned char)ch < 0x20)
                STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
            PUTC(context, ch);
        }
    }
}

static int lept_parse_string(lept_context *context, lept_value *v)
{
    int ret;
    char *str;
    size_t len;
    if ((ret = lept_parse_string_raw(context, &str, &len)) == LEPT_PARSE_OK)
        lept_set_string(v, str, len);
    return ret;
}

static int lept_parse_value(lept_context *context, lept_value *v);

static int lept_parse_array(lept_context *context, lept_value *v)
{
    size_t i, size = 0;
    int ret;
    EXPECT(context, '[');
    lept_parse_whitespace(context);
    if (*context->json == ']')
    {
        context->json++;
        v->type = LEPT_ARRAY;
        v->u.array.size = 0;
        v->u.array.elements = NULL;
        return LEPT_PARSE_OK;
    }
    for (;;)
    {
        lept_value elements;
        lept_init(&elements);
        if ((ret = lept_parse_value(context, &elements)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(context, sizeof(lept_value)), &elements, sizeof(lept_value));
        size++;
        lept_parse_whitespace(context);
        if (*context->json == ',')
        {
            context->json++;
            lept_parse_whitespace(context);
        }
        else if (*context->json == ']')
        {
            context->json++;
            v->type = LEPT_ARRAY;
            v->u.array.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.array.elements = (lept_value *)malloc(size), lept_context_pop(context, size), size);
            return LEPT_PARSE_OK;
        }
        else
        {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* Pop and free values on the stack */
    for (i = 0; i < size; i++)
        lept_free((lept_value *)lept_context_pop(context, sizeof(lept_value)));
    return ret;
}

static int lept_parse_object(lept_context *context, lept_value *v)
{
    size_t i, size;
    lept_member m;
    int ret;
    EXPECT(context, '{');
    lept_parse_whitespace(context);
    if (*context->json == '}')
    {
        context->json++;
        v->type = LEPT_OBJECT;
        v->u.object.members = 0;
        v->u.object.size = 0;
        return LEPT_PARSE_OK;
    }
    m.key = NULL;
    size = 0;
    for (;;)
    {
        char *str;
        lept_init(&m.val);
        /* parse key */
        if (*context->json != '"')
        {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        if ((ret = lept_parse_string_raw(context, &str, &m.klen)) != LEPT_PARSE_OK)
            break;
        memcpy(m.key = (char *)malloc(m.klen + 1), str, m.klen);
        m.key[m.klen] = '\0';
        /* parse ws colon ws */
        lept_parse_whitespace(context);
        if (*context->json != ':')
        {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        context->json++;
        lept_parse_whitespace(context);
        /* parse value */
        if ((ret = lept_parse_value(context, &m.val)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(context, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.key = NULL; /* ownership is transferred to member on stack */
        /* parse ws [comma | right-curly-brace] ws */
        lept_parse_whitespace(context);
        if (*context->json == ',')
        {
            context->json++;
            lept_parse_whitespace(context);
        }
        else if (*context->json == '}')
        {
            size_t str = sizeof(lept_member) * size;
            context->json++;
            v->type = LEPT_OBJECT;
            v->u.object.size = size;
            memcpy(v->u.object.members = (lept_member *)malloc(str), lept_context_pop(context, str), str);
            return LEPT_PARSE_OK;
        }
        else
        {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    /* Pop and free members on the stack */
    free(m.key);
    for (i = 0; i < size; i++)
    {
        lept_member *m = (lept_member *)lept_context_pop(context, sizeof(lept_member));
        free(m->key);
        lept_free(&m->val);
    }
    v->type = LEPT_NULL;
    return ret;
}

static int lept_parse_value(lept_context *context, lept_value *v)
{
    switch (*context->json)
    {
    case 't':
        return lept_parse_literal(context, v, "true", LEPT_TRUE);
    case 'f':
        return lept_parse_literal(context, v, "false", LEPT_FALSE);
    case 'n':
        return lept_parse_literal(context, v, "null", LEPT_NULL);
    default:
        return lept_parse_number(context, v);
    case '"':
        return lept_parse_string(context, v);
    case '[':
        return lept_parse_array(context, v);
    case '{':
        return lept_parse_object(context, v);
    case '\0':
        return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value *v, const char *json)
{
    lept_context context;
    int ret;
    assert(v != NULL);
    context.json = json;
    context.stack = NULL;
    context.size = context.top = 0;
    lept_init(v);
    lept_parse_whitespace(&context);
    if ((ret = lept_parse_value(&context, v)) == LEPT_PARSE_OK)
    {
        lept_parse_whitespace(&context);
        if (*context.json != '\0')
        {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(context.top == 0);
    free(context.stack);
    return ret;
}

static void lept_stringify_string(lept_context *context, const char *str, size_t len)
{
    size_t i;
    assert(str != NULL);
    PUTC(context, '"');
    for (i = 0; i < len; i++)
    {
        unsigned char ch = (unsigned char)str[i];
        switch (ch)
        {
        case '\"':
            PUTS(context, "\\\"", 2); 
            break;
        case '\\':
            PUTS(context, "\\\\", 2);
            break;
        case '\b':
            PUTS(context, "\\b", 2);
            break;
        case '\f':
            PUTS(context, "\\f", 2);
            break;
        case '\n':
            PUTS(context, "\\n", 2);
            break;
        case '\r':
            PUTS(context, "\\r", 2);
            break;
        case '\t':
            PUTS(context, "\\t", 2);
            break;
        default:
            if (ch < 0x20) {
                char buffer[7];
                sprintf(buffer,"\\u%04X",ch);
                PUTS(context,buffer,6);
            }
            else PUTC(context,str[i]);
        }
    }
    PUTC(context,'"');
}

static void lept_stringify_value(lept_context *context, const lept_value *v)
{
    size_t i;
    switch (v->type)
    {
    case LEPT_NULL:
        PUTS(context, "null", 4);
        break;
    case LEPT_FALSE:
        PUTS(context, "false", 5);
        break;
    case LEPT_TRUE:
        PUTS(context, "true", 4);
        break;
    case LEPT_NUMBER:
        context->top -= 32 - sprintf(lept_context_push(context, 32), "%.17g", v->u.number);
        break;
    case LEPT_STRING:
        lept_stringify_string(context, v->u.string.str, v->u.string.len);
        break;
    case LEPT_ARRAY:
        PUTC(context,'[');
        for(i=0;i<v->u.object.size;i++) {
            if(i>0) PUTC(context,',');
            lept_stringify_value(context,&v->u.array.elements[i]);
        }
        PUTC(context,']');
        break;
    case LEPT_OBJECT:
        PUTC(context,'{');
        for(i=0;i<v->u.object.size;i++) {
            if(i>0) PUTC(context,',');
            lept_stringify_string(context,v->u.object.members[i].key,v->u.object.members[i].klen);
            PUTC(context, ':');
            lept_stringify_value(context,&v->u.object.members[i].val);
        }
        PUTC(context,'}');
        break;
    default:
        assert(0 && "invalid type");
    }
}

char *lept_stringify(const lept_value *v, size_t *length)
{
    lept_context context;
    assert(v != NULL);
    context.stack = (char *)malloc(context.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    context.top = 0;
    lept_stringify_value(&context, v);
    if (length)
        *length = context.top;
    PUTC(&context, '\0');
    return context.stack;
}

void lept_free(lept_value *v)
{
    size_t i;
    assert(v != NULL);
    switch (v->type)
    {
    case LEPT_STRING:
        free(v->u.string.str);
        break;
    case LEPT_ARRAY:
        for (i = 0; i < v->u.array.size; i++)
            lept_free(&v->u.array.elements[i]);
        free(v->u.array.elements);
        break;
    case LEPT_OBJECT:
        for (i = 0; i < v->u.object.size; i++)
        {
            free(v->u.object.members[i].key);
            lept_free(&v->u.object.members[i].val);
        }
        free(v->u.object.members);
        break;
    default:
        break;
    }
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value *v)
{
    assert(v != NULL);
    return v->type;
}

int lept_get_boolean(const lept_value *v)
{
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value *v, int b)
{
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.number;
}

void lept_set_number(lept_value *v, double n)
{
    lept_free(v);
    v->u.number = n;
    v->type = LEPT_NUMBER;
}

const char *lept_get_string(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.string.str;
}

size_t lept_get_string_length(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.string.len;
}

void lept_set_string(lept_value *v, const char *s, size_t len)
{
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.string.str = (char *)malloc(len + 1);
    memcpy(v->u.string.str, s, len);
    v->u.string.str[len] = '\0';
    v->u.string.len = len;
    v->type = LEPT_STRING;
}

size_t lept_get_array_size(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.array.size;
}

lept_value *lept_get_array_element(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.array.size);
    return &v->u.array.elements[index];
}

size_t lept_get_object_size(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.object.size;
}

const char *lept_get_object_key(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.object.size);
    return v->u.object.members[index].key;
}

size_t lept_get_object_key_length(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.object.size);
    return v->u.object.members[index].klen;
}

lept_value *lept_get_object_value(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.object.size);
    return &v->u.object.members[index].val;
}
