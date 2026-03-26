/*
 * conntrack.h - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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

#ifndef FS_CONNTRACK_H
#define FS_CONNTRACK_H

#include <stdint.h>
#include <sys/socket.h>

/*
 * Direction constants.
 * DIR_INBOUND:  the first packet of this flow was inbound (client -> us).
 * DIR_OUTBOUND: the first packet of this flow was outbound (us -> remote).
 */
#define CT_DIR_INBOUND  0
#define CT_DIR_OUTBOUND 1

int fs_conntrack_setup(void);
void fs_conntrack_cleanup(void);

/*
 * fs_conntrack_query() - look up (or create) a flow entry and increment
 *                        the per-direction counter.
 *
 * @saddr:        source address of the packet as it arrived
 * @daddr:        destination address of the packet
 * @sport_be:     source port in network byte order
 * @dport_be:     destination port in network byte order
 * @is_outbound:  1 if this packet is outgoing (PACKET_OUTGOING), 0 if inbound
 * @count_out:    set to the updated per-direction packet count for the flow
 *               (0 if this packet is NOT in the initiating direction)
 * @flow_dir_out: set to CT_DIR_INBOUND or CT_DIR_OUTBOUND indicating which
 *               direction initiated the flow (may be NULL)
 *
 * Returns 0 on success, -1 on error.
 */
int fs_conntrack_query(struct sockaddr *saddr, struct sockaddr *daddr,
                       uint16_t sport_be, uint16_t dport_be, int is_outbound,
                       int *count_out, int *flow_dir_out);

#endif /* FS_CONNTRACK_H */
