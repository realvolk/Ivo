#ifndef IVO_EFIVARS_H
#define IVO_EFIVARS_H

#include <stdint.h>
#include <stddef.h>

int ivo_var_get(const char *name, uint8_t *buf, size_t *len, size_t cap);
int ivo_var_set(const char *name, const uint8_t *data, size_t len);
int ivo_var_del(const char *name);

int ivo_bootcount_get(void);
int ivo_bootcount_set(int n);
void ivo_bootcount_clear(void);

#define IVO_LASTENTRY_MAX 64
int  ivo_lastentry_get(char *buf, size_t cap);
int  ivo_lastentry_set(const char *name);
void ivo_lastentry_clear(void);

int ivo_configver_get(void);
int ivo_configver_set(int v);

int ivo_fwver_get(void);
int ivo_fwver_set(int v);

#endif