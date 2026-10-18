/* LVM2 linear logical volume reader.
 *
 * Reads the PV label, walks the PV header to find the metadata area,
 * reads the MDA header, extracts the current metadata text (handling
 * wrapped writes), parses it for the target LV, and builds a
 * LE-to-PE map. Reads through the map, dispatching to luks_read_blocks
 * or hal_read_blocks depending on whether the PV is inside LUKS.
 *
 * Linear single-area segments only. Ported from Kiska's core/lvm.c;
 * the write side, activation, and device-mapper code are not. See
 * doc/lvm.md for the on-disk format.
 */

#include "core.h"

#ifdef LVM

extern int luks_active(void);
extern int luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);

#define LVM_LABEL_SECTOR     1
#define LVM_SECTOR_SIZE      512
#define LVM_MDA_HDR_SIZE     512
#define LVM_MDA_TEXT_MAX     65536

#define LVM_INITIAL_CRC      0xF597A6CF
#define LVM_LABEL_MAGIC      "LABELONE"
#define LVM_LABEL_TYPE       "LVM2 001"
#define LVM_MDA_MAGIC        " LVM2 x[5A%r0N*>"

#define LVM_MAX_SEGMENTS     8
#define LVM_MAX_LVS          16
#define LVM_NAME_MAX         64

typedef struct {
    uint32_t start_extent;
    uint32_t extent_count;
    uint64_t pe_start;
} lvm_segment_t;

typedef struct {
    char          name[LVM_NAME_MAX];
    uint32_t      segment_count;
    lvm_segment_t segments[LVM_MAX_SEGMENTS];
} lvm_lv_t;

static lvm_lv_t  g_lvs[LVM_MAX_LVS];
static uint32_t  g_lv_count;
static int32_t   g_active_lv = -1;
static uint64_t  g_extent_bytes;
static uint64_t  g_pe_start_bytes;
static uint64_t  g_pv_base_lba;

static uint32_t lvm_crc(uint32_t crc, const uint8_t *buf, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        crc ^= buf[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
    }
    return crc;
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static int lvm_raw_read(uint64_t pv_lba, uint32_t count, uint8_t *buf)
{
    if (luks_active())
        return luks_read_blocks(pv_lba, count, buf);
    return hal_read_blocks(g_pv_base_lba + pv_lba, count, buf);
}

static int lvm_read_label(uint64_t *mda_offset_out, uint64_t *mda_size_out)
{
    uint8_t label[LVM_SECTOR_SIZE];
    if (lvm_raw_read(LVM_LABEL_SECTOR, 1, label) != 0) return -1;

    if (memcmp(label, LVM_LABEL_MAGIC, 8) != 0) return -1;

    uint32_t stored   = rd32(label + 16);
    uint32_t computed = lvm_crc(LVM_INITIAL_CRC, label + 20,
                                LVM_SECTOR_SIZE - 20);
    if (stored != computed) return -1;

    if (memcmp(label + 24, LVM_LABEL_TYPE, 8) != 0) return -1;

    uint32_t offset_xl = rd32(label + 20);
    if (offset_xl < 32 || offset_xl > 448) return -1;

    const uint8_t *pv = label + offset_xl;
    size_t remaining = LVM_SECTOR_SIZE - offset_xl;

    if (remaining < 40) return -1;
    size_t off = 40;

    for (int i = 0; i < 64; i++) {
        if (off + 16 > remaining) return -1;
        uint64_t a = rd64(pv + off);
        uint64_t b = rd64(pv + off + 8);
        off += 16;
        if (a == 0 && b == 0) break;
    }

    if (off + 16 > remaining) return -1;
    uint64_t mda_off = rd64(pv + off);
    uint64_t mda_sz  = rd64(pv + off + 8);

    if (mda_off == 0 || mda_sz < LVM_MDA_HDR_SIZE) return -1;

    *mda_offset_out = mda_off;
    *mda_size_out   = mda_sz;
    return 0;
}

static int lvm_read_bytes(uint64_t off, uint8_t *out, size_t len)
{
    uint8_t sec[LVM_SECTOR_SIZE];
    while (len > 0) {
        uint32_t in_sec = (uint32_t)(off % LVM_SECTOR_SIZE);
        size_t take = LVM_SECTOR_SIZE - in_sec;
        if (take > len) take = len;
        if (lvm_raw_read(off / LVM_SECTOR_SIZE, 1, sec) != 0) return -1;
        memcpy(out, sec + in_sec, take);
        out += take;
        off += take;
        len -= take;
    }
    return 0;
}

static int lvm_read_mda_text(uint64_t mda_offset, uint64_t mda_size,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (mda_offset % LVM_SECTOR_SIZE) return -1;
    if (mda_size <= LVM_MDA_HDR_SIZE) return -1;
    if (mda_offset + mda_size < mda_offset) return -1;

    uint8_t hdr[LVM_MDA_HDR_SIZE];
    if (lvm_raw_read(mda_offset / LVM_SECTOR_SIZE, 1, hdr) != 0) return -1;

    if (memcmp(hdr + 4, LVM_MDA_MAGIC, 16) != 0) return -1;

    uint32_t stored   = rd32(hdr);
    uint32_t computed = lvm_crc(LVM_INITIAL_CRC, hdr + 4,
                                LVM_MDA_HDR_SIZE - 4);
    if (stored != computed) return -1;

    uint64_t rl_off   = rd64(hdr + 40);
    uint64_t rl_sz    = rd64(hdr + 48);
    uint32_t rl_crc   = rd32(hdr + 56);
    uint32_t rl_flags = rd32(hdr + 60);

    if (rl_sz == 0) return -1;
    if (rl_sz > LVM_MDA_TEXT_MAX) return -1;
    if (rl_sz > out_cap) return -1;

    if (rl_flags & 1) return -1;  /* RAW_LOCN_IGNORED */

    if (rl_off < LVM_MDA_HDR_SIZE || rl_off >= mda_size) return -1;
    uint64_t head_len = mda_size - rl_off;
    if (head_len > rl_sz) head_len = rl_sz;
    uint64_t tail_len = rl_sz - head_len;
    if (tail_len > mda_size - LVM_MDA_HDR_SIZE) return -1;

    if (lvm_read_bytes(mda_offset + rl_off, out, (size_t)head_len) != 0)
        return -1;
    if (tail_len &&
        lvm_read_bytes(mda_offset + LVM_MDA_HDR_SIZE, out + head_len,
                       (size_t)tail_len) != 0)
        return -1;

    if (lvm_crc(LVM_INITIAL_CRC, out, (size_t)rl_sz) != rl_crc) return -1;

    *out_len = (size_t)rl_sz;
    return 0;
}

typedef struct {
    const char *p;
    const char *end;
} lvm_cursor_t;

static void skip_ws(lvm_cursor_t *c)
{
    for (;;) {
        while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' ||
                                 *c->p == '\n' || *c->p == '\r'))
            c->p++;
        if (c->p < c->end && *c->p == '#') {
            while (c->p < c->end && *c->p != '\n') c->p++;
            continue;
        }
        return;
    }
}

static int read_ident(lvm_cursor_t *c, char *out, size_t cap)
{
    skip_ws(c);
    size_t n = 0;
    while (c->p < c->end && n + 1 < cap) {
        char ch = *c->p;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') {
            out[n++] = ch;
            c->p++;
        } else break;
    }
    out[n] = '\0';
    return n > 0 ? 0 : -1;
}

static int read_quoted(lvm_cursor_t *c, char *out, size_t cap)
{
    skip_ws(c);
    if (c->p >= c->end || *c->p != '"') return -1;
    c->p++;
    size_t n = 0;
    while (c->p < c->end && *c->p != '"') {
        if (*c->p == '\\' && c->p + 1 < c->end) c->p++;
        char ch = *c->p++;
        if (n + 1 < cap) out[n++] = ch;
    }
    out[n] = '\0';
    if (c->p >= c->end || *c->p != '"') return -1;
    c->p++;
    return 0;
}

static uint64_t read_uint(lvm_cursor_t *c)
{
    skip_ws(c);
    uint64_t v = 0;
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        uint64_t d = (uint64_t)(*c->p - '0');
        v = (v > (UINT64_MAX - d) / 10) ? UINT64_MAX : v * 10 + d;
        c->p++;
    }
    return v;
}

static void skip_block(lvm_cursor_t *c)
{
    int depth = 1;
    while (c->p < c->end && depth > 0) {
        if (*c->p == '{') depth++;
        else if (*c->p == '}') depth--;
        else if (*c->p == '#') {
            while (c->p < c->end && *c->p != '\n') c->p++;
            continue;
        }
        c->p++;
    }
}

static int parse_segment(lvm_cursor_t *c, lvm_lv_t *lv)
{
    if (lv->segment_count >= LVM_MAX_SEGMENTS) {
        skip_block(c);
        return -1;
    }
    lvm_segment_t *seg = &lv->segments[lv->segment_count];
    seg->start_extent = 0;
    seg->extent_count = 0;
    seg->pe_start     = 0;

    char seg_type[LVM_NAME_MAX];
    seg_type[0] = '\0';
    uint64_t stripe_count = 0;

    for (;;) {
        char key[LVM_NAME_MAX];
        skip_ws(c);
        if (c->p >= c->end || *c->p == '}') {
            if (c->p < c->end) c->p++;
            break;
        }
        if (read_ident(c, key, sizeof(key)) != 0) break;

        skip_ws(c);
        if (c->p < c->end && *c->p == '{') {
            c->p++;
            skip_block(c);
            continue;
        }
        if (c->p >= c->end || *c->p != '=') break;
        c->p++;

        if (strcmp(key, "start_extent") == 0) {
            uint64_t v = read_uint(c);
            if (v > 0xFFFFFFFFu) return -1;
            seg->start_extent = (uint32_t)v;
        } else if (strcmp(key, "extent_count") == 0) {
            uint64_t v = read_uint(c);
            if (v > 0xFFFFFFFFu) return -1;
            seg->extent_count = (uint32_t)v;
        } else if (strcmp(key, "type") == 0) {
            skip_ws(c);
            if (c->p < c->end && *c->p == '"') {
                read_quoted(c, seg_type, sizeof(seg_type));
            } else {
                while (c->p < c->end && *c->p != '\n') c->p++;
            }
        } else if (strcmp(key, "stripe_count") == 0) {
            stripe_count = read_uint(c);
        } else if (strcmp(key, "stripes") == 0 || strcmp(key, "areas") == 0) {
            skip_ws(c);
            if (c->p >= c->end || *c->p != '[') return -1;
            c->p++;
            char pvname[LVM_NAME_MAX];
            if (read_quoted(c, pvname, sizeof(pvname)) != 0) return -1;
            skip_ws(c);
            if (c->p < c->end && *c->p == ',') c->p++;
            seg->pe_start = read_uint(c);
            while (c->p < c->end && *c->p != ']') c->p++;
            if (c->p < c->end) c->p++;
        } else {
            skip_ws(c);
            if (c->p < c->end && *c->p == '"') {
                char tmp[LVM_NAME_MAX];
                read_quoted(c, tmp, sizeof(tmp));
            } else if (c->p < c->end && *c->p == '[') {
                c->p++;
                while (c->p < c->end && *c->p != ']') c->p++;
                if (c->p < c->end) c->p++;
            } else {
                while (c->p < c->end && *c->p != '\n') c->p++;
            }
        }
    }

    if (strcmp(seg_type, "striped") != 0) return -1;
    if (stripe_count != 1) return -1;
    if (seg->extent_count > 0) lv->segment_count++;
    return 0;
}

static void parse_all_lvs(lvm_cursor_t *c)
{
    for (;;) {
        char name[LVM_NAME_MAX];
        skip_ws(c);
        if (c->p >= c->end || *c->p == '}') return;

        if (read_ident(c, name, sizeof(name)) != 0) return;
        skip_ws(c);
        if (c->p >= c->end || *c->p != '{') return;
        c->p++;

        if (g_lv_count >= LVM_MAX_LVS) {
            skip_block(c);
            continue;
        }
        lvm_lv_t *lv = &g_lvs[g_lv_count];
        memset(lv, 0, sizeof(*lv));
        size_t nl = strlen(name);
        if (nl >= LVM_NAME_MAX) nl = LVM_NAME_MAX - 1;
        memcpy(lv->name, name, nl);
        lv->name[nl] = '\0';
        g_lv_count++;

        for (;;) {
            char key[LVM_NAME_MAX];
            skip_ws(c);
            if (c->p >= c->end || *c->p == '}') {
                if (c->p < c->end) c->p++;
                break;
            }
            if (read_ident(c, key, sizeof(key)) != 0) break;

            skip_ws(c);
            if (c->p < c->end && *c->p == '{') {
                c->p++;
                if (strncmp(key, "segment", 7) == 0) {
                    if (parse_segment(c, lv) != 0) {
                        lv->segment_count = 0;
                        return;
                    }
                } else {
                    skip_block(c);
                }
                continue;
            }
            if (c->p >= c->end || *c->p != '=') break;
            c->p++;
            skip_ws(c);
            if (c->p < c->end && *c->p == '"') {
                char tmp[LVM_NAME_MAX];
                read_quoted(c, tmp, sizeof(tmp));
            } else if (c->p < c->end && *c->p == '[') {
                c->p++;
                while (c->p < c->end && *c->p != ']') c->p++;
                if (c->p < c->end) c->p++;
            } else {
                while (c->p < c->end && *c->p != '\n') c->p++;
            }
        }
    }
}

static int parse_metadata(const uint8_t *text, size_t text_len)
{
    lvm_cursor_t c = { (const char *)text, (const char *)text + text_len };

    char vgname[LVM_NAME_MAX];
    if (read_ident(&c, vgname, sizeof(vgname)) != 0) return -1;
    skip_ws(&c);
    if (c.p >= c.end || *c.p != '{') return -1;
    c.p++;

    uint64_t extent_size = 0;
    uint64_t pe_start    = 0;
    int found_lv = 0;

    for (;;) {
        char key[LVM_NAME_MAX];
        skip_ws(&c);
        if (c.p >= c.end) break;
        if (*c.p == '}') { c.p++; break; }
        if (read_ident(&c, key, sizeof(key)) != 0) break;

        skip_ws(&c);
        if (c.p < c.end && *c.p == '{') {
            c.p++;
            if (strcmp(key, "physical_volumes") == 0) {
                char pvname[LVM_NAME_MAX];
                skip_ws(&c);
                if (read_ident(&c, pvname, sizeof(pvname)) == 0) {
                    skip_ws(&c);
                    if (c.p < c.end && *c.p == '{') {
                        c.p++;
                        for (;;) {
                            char pk[LVM_NAME_MAX];
                            skip_ws(&c);
                            if (c.p >= c.end || *c.p == '}') {
                                if (c.p < c.end) c.p++;
                                break;
                            }
                            if (read_ident(&c, pk, sizeof(pk)) != 0) break;
                            skip_ws(&c);
                            if (c.p < c.end && *c.p == '{') {
                                c.p++;
                                skip_block(&c);
                                continue;
                            }
                            if (c.p >= c.end || *c.p != '=') break;
                            c.p++;
                            if (strcmp(pk, "pe_start") == 0) {
                                pe_start = read_uint(&c);
                            } else {
                                skip_ws(&c);
                                if (c.p < c.end && *c.p == '"') {
                                    char tmp[LVM_NAME_MAX];
                                    read_quoted(&c, tmp, sizeof(tmp));
                                } else if (c.p < c.end && *c.p == '[') {
                                    c.p++;
                                    while (c.p < c.end && *c.p != ']') c.p++;
                                    if (c.p < c.end) c.p++;
                                } else {
                                    while (c.p < c.end && *c.p != '\n') c.p++;
                                }
                            }
                        }
                    }
                }
                skip_block(&c);
            } else if (strcmp(key, "logical_volumes") == 0) {
                parse_all_lvs(&c);
                found_lv = 1;
            } else {
                skip_block(&c);
            }
            continue;
        }

        if (c.p >= c.end || *c.p != '=') break;
        c.p++;
        if (strcmp(key, "extent_size") == 0) {
            extent_size = read_uint(&c);
        } else {
            skip_ws(&c);
            if (c.p < c.end && *c.p == '"') {
                char tmp[LVM_NAME_MAX];
                read_quoted(&c, tmp, sizeof(tmp));
            } else if (c.p < c.end && *c.p == '[') {
                c.p++;
                while (c.p < c.end && *c.p != ']') c.p++;
                if (c.p < c.end) c.p++;
            } else {
                while (c.p < c.end && *c.p != '\n') c.p++;
            }
        }
    }

    if (!found_lv || extent_size == 0 || pe_start == 0) return -1;
    if (extent_size > 0xFFFFFFFFu) return -1;
    if (pe_start > UINT64_MAX / LVM_SECTOR_SIZE) return -1;
    if (g_lv_count == 0) return -1;

    uint64_t extent_bytes   = extent_size * LVM_SECTOR_SIZE;
    uint64_t pe_start_bytes = pe_start * LVM_SECTOR_SIZE;
    uint64_t max_pe         = UINT64_MAX / extent_bytes;
    for (uint32_t i = 0; i < g_lv_count; i++) {
        if (g_lvs[i].segment_count == 0) return -1;
        for (uint32_t j = 0; j < g_lvs[i].segment_count; j++) {
            const lvm_segment_t *s = &g_lvs[i].segments[j];
            if (s->pe_start > max_pe ||
                s->extent_count > max_pe - s->pe_start) return -1;
            uint64_t end = (s->pe_start + s->extent_count) * extent_bytes;
            if (end > UINT64_MAX - pe_start_bytes) return -1;
        }
    }

    g_extent_bytes   = extent_bytes;
    g_pe_start_bytes = pe_start_bytes;
    return 0;
}

int lvm_init(boot_context_t *ctx)
{
    if (g_lv_count > 0) return 0;
    if (!ctx) return -1;

    g_pv_base_lba = ctx->boot_lba;
    g_lv_count    = 0;
    g_active_lv   = -1;

    uint64_t mda_off, mda_sz;
    if (lvm_read_label(&mda_off, &mda_sz) != 0) return -1;

    static uint8_t text_buf[LVM_MDA_TEXT_MAX];
    size_t text_len = 0;
    if (lvm_read_mda_text(mda_off, mda_sz, text_buf,
                          sizeof(text_buf), &text_len) != 0)
        return -1;
    if (parse_metadata(text_buf, text_len) != 0) {
        g_lv_count = 0;
        return -1;
    }

    g_active_lv = 0;
    return 0;
}

int lvm_active(void)
{
    return g_active_lv >= 0 && g_lvs[g_active_lv].segment_count > 0;
}

int lvm_lv_count(void)
{
    return (int)g_lv_count;
}

const char *lvm_lv_name(int index)
{
    if (index < 0 || (uint32_t)index >= g_lv_count) return 0;
    return g_lvs[index].name;
}

int lvm_lv_select(int index)
{
    if (index < 0 || (uint32_t)index >= g_lv_count) return -1;
    if (g_lvs[index].segment_count == 0) return -1;
    g_active_lv = index;
    return 0;
}

int lvm_lv_select_by_name(const char *name)
{
    for (uint32_t i = 0; i < g_lv_count; i++) {
        if (strcmp(g_lvs[i].name, name) == 0) {
            g_active_lv = (int32_t)i;
            return 0;
        }
    }
    return -1;
}

static int lv_to_pv_sector(uint64_t lv_lba, uint64_t *pv_lba_out)
{
    if (g_active_lv < 0) return -1;
    const lvm_lv_t *lv = &g_lvs[g_active_lv];

    if (lv_lba > UINT64_MAX / LVM_SECTOR_SIZE) return -1;
    uint64_t byte_off = lv_lba * LVM_SECTOR_SIZE;
    uint64_t le = byte_off / g_extent_bytes;
    uint64_t within = byte_off % g_extent_bytes;

    for (uint32_t i = 0; i < lv->segment_count; i++) {
        const lvm_segment_t *s = &lv->segments[i];
        if (le >= s->start_extent &&
            le < s->start_extent + (uint64_t)s->extent_count) {
            uint64_t pe = s->pe_start + (le - s->start_extent);
            uint64_t pv_byte = g_pe_start_bytes + pe * g_extent_bytes + within;
            *pv_lba_out = pv_byte / LVM_SECTOR_SIZE;
            return 0;
        }
    }
    return -1;
}

int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf)
{
    if (!lvm_active() || !buf) return -1;
    uint32_t i = 0;
    while (i < count) {
        uint64_t pv_start;
        if (lv_to_pv_sector(lba + i, &pv_start) != 0) return -1;
        uint32_t cap = 8192;
        uint32_t j = 1;
        while (i + j < count && j < cap) {
            uint64_t next_pv;
            if (lv_to_pv_sector(lba + i + j, &next_pv) != 0) break;
            if (next_pv != pv_start + j) break;
            j++;
        }
        if (lvm_raw_read(pv_start, j, buf + (size_t)i * LVM_SECTOR_SIZE) != 0)
            return -1;
        i += j;
    }
    return 0;
}

#else  /* !LVM */

int lvm_init(boot_context_t *ctx) { (void)ctx; return -1; }
int lvm_active(void) { return 0; }
int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf)
{ (void)lba; (void)count; (void)buf; return -1; }

#endif /* LVM */