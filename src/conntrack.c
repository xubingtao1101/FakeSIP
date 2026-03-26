/*
 * conntrack.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
 *
 * Tracks per-UDP-flow packet counts so that fake SIP packets are only
 * injected for the first N packets in the direction that initiated the
 * flow (where N = g_ctx.pktlimit).
 *
 * Flow key: (src_ip, dst_ip, src_port, dst_port) normalised so that the
 * "smaller" endpoint always comes first – this makes inbound and outbound
 * packets of the same flow hash to the same bucket.
 *
 * Copyright (C) 2025  MikeWang000000
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include "conntrack.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "logging.h"

/* Number of hash-table buckets (power of two). */
#define CT_BUCKETS     1024
#define CT_BUCKET_MASK (CT_BUCKETS - 1)

/* Maximum entries per bucket (LRU eviction when full). */
#define CT_BUCKET_DEPTH 8

/* ------------------------------------------------------------------ */

/* A normalised 5-tuple (without protocol – we only see UDP here). */
struct ct_key {
    uint8_t lo_addr[16]; /* "smaller" endpoint IP (v4 stored in [0..3]) */
    uint8_t hi_addr[16];
    uint16_t lo_port; /* port belonging to lo_addr (network byte order) */
    uint16_t hi_port;
    uint8_t af; /* AF_INET or AF_INET6 */
};

struct ct_entry {
    int used;
    struct ct_key key;
    int dir;   /* CT_DIR_INBOUND or CT_DIR_OUTBOUND */
    int count; /* packets seen in the initiating direction */
};

struct ct_bucket {
    struct ct_entry entries[CT_BUCKET_DEPTH];
    int next_evict; /* round-robin eviction index */
};

static struct ct_bucket *ct_table = NULL;

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void addr_to_bytes(struct sockaddr *sa, uint8_t out[16])
{
    memset(out, 0, 16);
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *) sa;
        memcpy(out, &s4->sin_addr.s_addr, 4);
    } else {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) sa;
        memcpy(out, &s6->sin6_addr, 16);
    }
}

static void build_key(struct ct_key *k, struct sockaddr *saddr,
                      struct sockaddr *daddr, uint16_t sport_be,
                      uint16_t dport_be)
{
    uint8_t sip[16], dip[16];
    int cmp;

    k->af = (uint8_t) saddr->sa_family;
    addr_to_bytes(saddr, sip);
    addr_to_bytes(daddr, dip);

    cmp = memcmp(sip, dip, 16);
    if (cmp < 0 || (cmp == 0 && ntohs(sport_be) <= ntohs(dport_be))) {
        memcpy(k->lo_addr, sip, 16);
        memcpy(k->hi_addr, dip, 16);
        k->lo_port = sport_be;
        k->hi_port = dport_be;
    } else {
        memcpy(k->lo_addr, dip, 16);
        memcpy(k->hi_addr, sip, 16);
        k->lo_port = dport_be;
        k->hi_port = sport_be;
    }
}

static uint32_t hash_key(const struct ct_key *k)
{
    /* FNV-1a over the raw key bytes */
    const uint8_t *p = (const uint8_t *) k;
    size_t len = sizeof(*k);
    uint32_t h = 2166136261u;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h & CT_BUCKET_MASK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int fs_conntrack_setup(void)
{
    ct_table = calloc(CT_BUCKETS, sizeof(*ct_table));
    if (!ct_table) {
        E("ERROR: calloc(): %s", strerror(errno));
        return -1;
    }
    return 0;
}

void fs_conntrack_cleanup(void)
{
    free(ct_table);
    ct_table = NULL;
}

int fs_conntrack_query(struct sockaddr *saddr, struct sockaddr *daddr,
                       uint16_t sport_be, uint16_t dport_be, int is_outbound,
                       int *count_out, int *flow_dir_out)
{
    struct ct_key key;
    uint32_t idx;
    struct ct_bucket *bucket;
    struct ct_entry *ent;
    int i, dir;

    build_key(&key, saddr, daddr, sport_be, dport_be);
    idx = hash_key(&key);
    bucket = &ct_table[idx];

    /* --- Search existing entry --- */
    for (i = 0; i < CT_BUCKET_DEPTH; i++) {
        ent = &bucket->entries[i];
        if (!ent->used) {
            continue;
        }
        if (memcmp(&ent->key, &key, sizeof(key)) != 0) {
            continue;
        }

        /*
         * Found.  Only increment if this packet travels in the same
         * direction as the flow initiator.
         */
        dir = is_outbound ? CT_DIR_OUTBOUND : CT_DIR_INBOUND;
        if (dir == ent->dir) {
            ent->count++;
        }
        *count_out = (dir == ent->dir) ? ent->count : 0;
        if (flow_dir_out) {
            *flow_dir_out = ent->dir;
        }
        return 0;
    }

    /* --- Not found: create new entry --- */
    dir = is_outbound ? CT_DIR_OUTBOUND : CT_DIR_INBOUND;

    /* Pick slot: prefer an unused slot, otherwise evict round-robin. */
    ent = NULL;
    for (i = 0; i < CT_BUCKET_DEPTH; i++) {
        if (!bucket->entries[i].used) {
            ent = &bucket->entries[i];
            break;
        }
    }
    if (!ent) {
        ent = &bucket->entries[bucket->next_evict];
        bucket->next_evict = (bucket->next_evict + 1) % CT_BUCKET_DEPTH;
    }

    ent->used = 1;
    ent->key = key;
    ent->dir = dir;
    ent->count = 1;

    *count_out = 1;
    if (flow_dir_out) {
        *flow_dir_out = dir;
    }
    return 0;
}
