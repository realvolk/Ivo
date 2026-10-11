/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_JSON_H
#define KISKA_JSON_H

#include <stddef.h>
#include <stdint.h>

enum json_type {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
};

struct json_value;

int json_parse(const char *text, size_t len, struct json_value **out);
void json_free(struct json_value *v);

enum json_type json_type(const struct json_value *v);
int json_is_null(const struct json_value *v);

int json_bool(const struct json_value *v);
double json_number(const struct json_value *v);
uint64_t json_number_u64(const struct json_value *v);
int json_get_u64(const struct json_value *v, uint64_t *out);
int json_str_to_u64(const char *s, uint64_t *out);
const char *json_string(const struct json_value *v);

struct json_value *json_object_get(const struct json_value *obj, const char *key);
size_t json_object_count(const struct json_value *obj);
const char *json_object_key_at(const struct json_value *obj, size_t idx);
struct json_value *json_object_value_at(const struct json_value *obj, size_t idx);

size_t json_array_size(const struct json_value *arr);
struct json_value *json_array_get(const struct json_value *arr, size_t idx);

int json_write(const struct json_value *v, char *buf, size_t bufsz,
               size_t *out_len);

int json_object_set(struct json_value *obj, const char *key,
                    struct json_value *val);
int json_object_remove(struct json_value *obj, const char *key);
int json_array_append(struct json_value *arr, struct json_value *val);
int json_array_remove_at(struct json_value *arr, size_t idx);

struct json_value *json_new_string(const char *s);
struct json_value *json_new_string_u64(uint64_t n);
struct json_value *json_new_number_u64(uint64_t n);
struct json_value *json_new_object(void);
struct json_value *json_new_array(void);

#endif