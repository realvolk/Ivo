#ifndef IVO_EFIVARS_H
#define IVO_EFIVARS_H

#include <stdint.h>
#include <stddef.h>

/* Read a variable from Ivo's namespace. Returns 0 on success and
 * sets *len to the byte count. *buf must be at least cap bytes.
 * Returns -1 on any failure: not found, wrong type, too big for cap,
 * or a firmware error. */
int ivo_var_get(const char *name, uint8_t *buf, size_t *len, size_t cap);

/* Write a variable into Ivo's namespace. Returns 0 on success. */
int ivo_var_set(const char *name, const uint8_t *data, size_t len);

/* Delete a variable from Ivo's namespace. Returns 0 on success,
 * including when the variable already didn't exist. */
int ivo_var_del(const char *name);

/* Boot counter: incremented at the start of each boot, cleared on
 * successful kernel handoff. Used by the menu to detect a run of
 * failed boots and fall back to a different entry. */
int ivo_bootcount_get(void);
int ivo_bootcount_set(int n);
void ivo_bootcount_clear(void);

/* Last explicitly-chosen menu entry. Written when the user picks an
 * entry with Enter or a number key. Read on menu entry to preselect.
 * Not written on timeout or Esc, because neither is a choice. */
#define IVO_LASTENTRY_MAX 64
int  ivo_lastentry_get(char *buf, size_t cap);
int  ivo_lastentry_set(const char *name);
void ivo_lastentry_clear(void);

/* Highest config.toml version accepted so far. Returns -1 when no
 * value has ever been written; otherwise a non-negative int. Used
 * by main.c to refuse an older config than the last one seen.
 * Best-effort only: deleting the variable resets the check. */
int ivo_configver_get(void);
int ivo_configver_set(int v);

#endif