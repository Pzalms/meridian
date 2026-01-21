#ifndef MDN_INTERNAL_H
#define MDN_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "meridian.h"

/* ------------------------------------------------------------------ */
/* Capacity constants                                                   */
/* ------------------------------------------------------------------ */
#define MDN_MAX_SECTIONS        128
#define MDN_MAX_ZONES           128
#define MDN_MAX_RULES           512
#define MDN_MAX_PREFIX_PAGES    256
#define MDN_MAX_NAT_BUCKETS     256
#define MDN_MAX_QUERIES         128
#define MDN_CAP_TOKEN_LEN       32
#define MDN_AUDIT_DIR_INIT      32
#define MDN_EXPORT_FIELDS_MAX   32

/* ------------------------------------------------------------------ */
/* Section type identifiers                                             */
/* ------------------------------------------------------------------ */
#define SECT_CAP            0x01
#define SECT_ZONE           0x02
#define SECT_RULE           0x03
#define SECT_PREFIX         0x04
#define SECT_NAT            0x05
#define SECT_SESSION        0x06
#define SECT_TEMPLATE       0x07
#define SECT_AUDIT          0x08
#define SECT_EXPORT         0x09
#define SECT_POLICY_PATCH   0x0A
#define SECT_QUERY          0x0B

/* ------------------------------------------------------------------ */
/* Flag constants                                                       */
/* ------------------------------------------------------------------ */
#define MDN_FLAG_STRICT     0x0001

/* ------------------------------------------------------------------ */
/* Prefix-kind constants                                                */
/* ------------------------------------------------------------------ */
#define PREFIX_KIND_MIXED   0
#define PREFIX_KIND_V4      1
#define PREFIX_KIND_V6      2

/* Zone */
typedef struct {
    uint16_t zone_id;
    uint16_t parent_id;
    uint16_t if_count;
    uint16_t flags;
    uint32_t epoch;
} mdn_zone_t;

/* Rule node */
typedef struct {
    uint32_t key;
    uint32_t mask;
    uint16_t action;
    uint16_t next;
} mdn_rule_node_t;

/* Rule actions */
#define ACTION_ALLOW        0
#define ACTION_DROP         1
#define ACTION_MARK         2
#define ACTION_REDIRECT     3
#define ACTION_NAT_LOOKUP   4
#define ACTION_TRIE_LOOKUP  5
#define ACTION_AUDIT_EXPORT 6

/* Prefix page (with directory extension) */
typedef struct {
    uint32_t page_id;
    uint16_t kind;
    uint16_t stride;
    uint32_t item_count;
    uint8_t *items;
    uint32_t *dir;       /* per-item byte offsets into items[]; length = dir_count */
    uint32_t dir_count;
} mdn_prefix_page_t;

/* Session */
typedef struct {
    uint32_t sess_id;
    uint16_t zone_id;
    uint16_t flags;
    uint32_t last_seen;
    uint8_t  tuple[40];
} mdn_session_t;

/* NAT bucket */
typedef struct {
    uint16_t bucket_id;
    uint16_t zone_id;
    uint16_t slot_count;
    uint16_t _pad;
    uint32_t epoch;
    mdn_session_t *slots;
} mdn_nat_bucket_t;

/* Session cursor */
typedef struct {
    uint16_t cursor_id;
    uint16_t bucket_id;
    uint32_t seen_epoch;
    mdn_session_t *slot_ptr;
    uint32_t slot_index;
} mdn_session_cursor_t;

/* Template descriptor */
typedef struct {
    uint16_t field_off;
    uint16_t field_len;
    uint16_t field_type;
    uint16_t field_src;
} mdn_tmpl_desc_t;

/* Packet template (with descriptor extension) */
typedef struct {
    uint16_t tmpl_id;
    uint16_t hdr_len;
    uint16_t frag_count;
    uint16_t flags;
    uint8_t *hdr_bytes;
    uint32_t hdr_cap;
    uint16_t profile;       /* 0=base, 1=encapsulated */
    uint16_t desc_count;
    mdn_tmpl_desc_t *descs;
} mdn_packet_template_t;

/* Audit directory entry */
typedef struct {
    uint32_t off;
    uint16_t len;
    uint16_t kind;
} mdn_audit_dirent_t;

/* Audit window */
typedef struct {
    uint16_t win_id;
    uint16_t flags;
    uint32_t heap_len;
    uint32_t dir_count;
    uint8_t *heap;
    mdn_audit_dirent_t *dir;
} mdn_audit_window_t;

/* Export field */
typedef struct {
    uint16_t field_id;
    uint16_t offset;
    uint16_t width;
    uint16_t source;
} mdn_export_field_t;

/* Export profile */
typedef struct {
    uint16_t profile_id;
    uint16_t mode;
    uint16_t field_count;
    uint16_t frame_cap;
    mdn_export_field_t *fields;
    uint8_t *frame;
} mdn_export_profile_t;

/* Query */
typedef struct {
    uint16_t query_id;
    uint16_t start_rule;
    uint16_t zone_id;
    uint16_t template_id;
    uint32_t flags;
} mdn_query_t;

/* Main context */
struct mdn_ctx {
    uint16_t flags;
    uint16_t query_count;
    uint8_t  cap_token[MDN_CAP_TOKEN_LEN];
    uint64_t cap_nonce;
    int      cap_ok;

    mdn_zone_t          *zones[MDN_MAX_ZONES];
    mdn_rule_node_t     *rules;
    uint32_t             rule_count;

    mdn_prefix_page_t   *prefix_pages[MDN_MAX_PREFIX_PAGES];
    mdn_nat_bucket_t    *nat_buckets[MDN_MAX_NAT_BUCKETS];
    mdn_session_cursor_t *cursors;
    uint32_t             cursor_count;

    mdn_packet_template_t *templates;
    uint32_t               template_count;

    mdn_audit_window_t  *audit_windows;
    uint32_t             audit_count;

    mdn_export_profile_t *exports;
    uint32_t              export_count;

    mdn_query_t queries[MDN_MAX_QUERIES];

    /* parse-time counters */
    uint32_t stats_crc_miss;
    uint32_t stats_sections_loaded;
};

#endif /* MDN_INTERNAL_H */
