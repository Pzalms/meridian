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

/* ------------------------------------------------------------------ */
/* Zone: named policy domain                                            */
/* ------------------------------------------------------------------ */
typedef struct mdn_zone {
    uint32_t  id;
    uint32_t  flags;
    char      name[64];
} mdn_zone_t;

/* ------------------------------------------------------------------ */
/* Rule node: linked policy decision element                            */
/* ------------------------------------------------------------------ */
typedef struct mdn_rule_node {
    uint32_t  rule_id;
    uint32_t  zone_id;
    uint16_t  proto;
    uint16_t  port_lo;
    uint16_t  port_hi;
    uint8_t   action;        /* 0=deny 1=permit 2=redirect */
    uint8_t   _pad;
    struct mdn_rule_node *next;
} mdn_rule_node_t;

/* ------------------------------------------------------------------ */
/* Prefix page: block of address prefixes (extended)                   */
/* ------------------------------------------------------------------ */
typedef struct mdn_dir_entry {
    uint8_t   addr[16];     /* IPv4 mapped into v6 or native v6 */
    uint8_t   prefix_len;
    uint8_t   kind;         /* PREFIX_KIND_* */
    uint16_t  _pad;
} mdn_dir_entry_t;

typedef struct mdn_prefix_page {
    uint32_t        page_id;
    uint32_t        zone_id;
    uint8_t         kind;           /* PREFIX_KIND_* */
    uint8_t         _pad[3];
    uint32_t        entry_count;
    uint8_t         entries[32][17]; /* raw packed prefix entries */
    /* extended fields */
    mdn_dir_entry_t *dir;
    uint32_t         dir_count;
} mdn_prefix_page_t;

/* ------------------------------------------------------------------ */
/* Session: active tracked flow                                         */
/* ------------------------------------------------------------------ */
typedef struct mdn_session {
    uint64_t  session_id;
    uint32_t  zone_id;
    uint32_t  rule_id;
    uint8_t   src_addr[16];
    uint8_t   dst_addr[16];
    uint16_t  src_port;
    uint16_t  dst_port;
    uint8_t   proto;
    uint8_t   state;         /* 0=init 1=established 2=closing */
    uint16_t  flags;
} mdn_session_t;

/* ------------------------------------------------------------------ */
/* NAT bucket: source-address translation pool entry                   */
/* ------------------------------------------------------------------ */
typedef struct mdn_nat_bucket {
    uint32_t  bucket_id;
    uint32_t  zone_id;
    uint8_t   pool_addr[16];
    uint16_t  port_base;
    uint16_t  port_range;
    uint32_t  session_count;
    uint32_t  capacity;
} mdn_nat_bucket_t;

/* ------------------------------------------------------------------ */
/* Session cursor: iterator over the session table                      */
/* ------------------------------------------------------------------ */
typedef struct mdn_session_cursor {
    uint32_t   bucket_idx;
    uint32_t   slot_idx;
    uint64_t   last_seen_id;
    mdn_session_t *current;
} mdn_session_cursor_t;

/* ------------------------------------------------------------------ */
/* Template descriptor and packet template (extended)                  */
/* ------------------------------------------------------------------ */
typedef struct mdn_tmpl_desc {
    uint16_t  field_id;
    uint16_t  offset;
    uint16_t  length;
    uint8_t   flags;
    uint8_t   _pad;
} mdn_tmpl_desc_t;

typedef struct mdn_export_profile mdn_export_profile_t; /* forward */

typedef struct mdn_packet_template {
    uint32_t           tmpl_id;
    uint32_t           zone_id;
    uint16_t           total_length;
    uint16_t           field_count;
    uint8_t            header[64];
    /* extended fields */
    mdn_tmpl_desc_t   *descs;
    uint32_t           desc_count;
    mdn_export_profile_t *profile;
} mdn_packet_template_t;

/* ------------------------------------------------------------------ */
/* Audit directory entry and window                                     */
/* ------------------------------------------------------------------ */
typedef struct mdn_audit_dirent {
    uint64_t  timestamp;
    uint32_t  rule_id;
    uint32_t  zone_id;
    uint8_t   action;
    uint8_t   _pad[3];
} mdn_audit_dirent_t;

typedef struct mdn_audit_window {
    mdn_audit_dirent_t *entries;
    uint32_t            capacity;
    uint32_t            count;
    uint32_t            head;    /* ring-buffer write cursor */
    uint32_t            _pad;
} mdn_audit_window_t;

/* ------------------------------------------------------------------ */
/* Export field and profile                                             */
/* ------------------------------------------------------------------ */
typedef struct mdn_export_field {
    uint16_t  field_id;
    uint16_t  offset;
    uint16_t  length;
    uint8_t   encode; /* 0=raw 1=varint 2=string */
    uint8_t   _pad;
} mdn_export_field_t;

struct mdn_export_profile {
    uint32_t          profile_id;
    uint32_t          zone_id;
    mdn_export_field_t fields[MDN_EXPORT_FIELDS_MAX];
    uint32_t          field_count;
};

/* ------------------------------------------------------------------ */
/* Query: policy lookup request                                         */
/* ------------------------------------------------------------------ */
typedef struct mdn_query {
    uint32_t  query_id;
    uint32_t  zone_id;
    uint8_t   src_addr[16];
    uint8_t   dst_addr[16];
    uint16_t  src_port;
    uint16_t  dst_port;
    uint8_t   proto;
    uint8_t   _pad[3];
    uint32_t  result_rule_id;
    uint8_t   result_action;
    uint8_t   _pad2[3];
} mdn_query_t;

/* ------------------------------------------------------------------ */
/* Capability token (capability section payload)                        */
/* ------------------------------------------------------------------ */
typedef struct mdn_cap_token {
    uint8_t   token[MDN_CAP_TOKEN_LEN];
    uint32_t  level;
    uint32_t  _pad;
} mdn_cap_token_t;

/* ------------------------------------------------------------------ */
/* Main context struct                                                  */
/* ------------------------------------------------------------------ */
struct mdn_ctx {
    /* raw input */
    const uint8_t       *buf;
    size_t               len;

    /* parsed sections */
    uint32_t             section_count;
    uint8_t              section_types[MDN_MAX_SECTIONS];
    uint32_t             section_offsets[MDN_MAX_SECTIONS];
    uint32_t             section_lengths[MDN_MAX_SECTIONS];

    /* capability */
    mdn_cap_token_t      cap;
    uint16_t             flags;        /* MDN_FLAG_* */
    uint16_t             _pad0;

    /* zones */
    mdn_zone_t           zones[MDN_MAX_ZONES];
    uint32_t             zone_count;

    /* rules */
    mdn_rule_node_t      rule_store[MDN_MAX_RULES];
    uint32_t             rule_count;
    mdn_rule_node_t     *rule_head;

    /* prefixes */
    mdn_prefix_page_t    prefix_pages[MDN_MAX_PREFIX_PAGES];
    uint32_t             prefix_page_count;

    /* NAT */
    mdn_nat_bucket_t     nat_buckets[MDN_MAX_NAT_BUCKETS];
    uint32_t             nat_bucket_count;

    /* sessions */
    mdn_session_t        sessions[MDN_MAX_QUERIES]; /* active session pool */
    uint32_t             session_count;
    mdn_session_cursor_t cursor;

    /* templates */
    mdn_packet_template_t templates[MDN_MAX_SECTIONS];
    uint32_t              template_count;

    /* audit */
    mdn_audit_window_t   audit;

    /* export */
    mdn_export_profile_t export_profiles[MDN_MAX_SECTIONS];
    uint32_t             export_profile_count;

    /* queries */
    mdn_query_t          queries[MDN_MAX_QUERIES];
    uint32_t             query_count;
};

#endif /* MDN_INTERNAL_H */
