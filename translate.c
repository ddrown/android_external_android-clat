/*
 * Copyright 2011 Daniel Drown
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * translate.c - CLAT functions / partial implementation of rfc6145
 */
#include <string.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/icmp.h>

#include "checksum.h"
#include "clatd.h"
#include "config.h"
#include "logging.h"
#include "debug.h"

/* function: fill_tun_header
 * fill in the header for the tun fd
 * tun_header - tunnel header, already allocated
 * proto      - ethernet protocol id: ETH_P_IP(ipv4) or ETH_P_IPV6(ipv6)
 */
void fill_tun_header(struct tun_pi *tun_header, uint16_t proto) {
  tun_header->flags = 0;
  tun_header->proto = htons(proto);
}

/* function: ipv6_src_to_ipv4_src
 * return the corresponding ipv4 address for the given ipv6 address
 * sourceaddr - ipv6 source address
 */
uint32_t ipv6_src_to_ipv4_src(const struct in6_addr *sourceaddr) {
  // assumes a /96 plat subnet
  return sourceaddr->s6_addr32[3];
}

/* function: fill_ip_header
 * generating an ipv4 header from an ipv6 header (called by the layer 4 protocol-specific functions)
 * ip_targ     - (ipv4) target packet header, source addr: original ipv4 addr, dest addr: local subnet addr
 * payload_len - length of other data inside packet
 * protocol    - protocol number (tcp, udp, etc)
 * old_header  - (ipv6) source packet header, source addr: nat64 prefix, dest addr: local subnet prefix
 */
void fill_ip_header(struct iphdr *ip_targ, uint16_t payload_len, uint8_t protocol, const struct ip6_hdr *old_header) {
  memset(ip_targ, 0, sizeof(ip_targ));

  ip_targ->ihl = 5;
  ip_targ->version = 4;
  ip_targ->tos = 0;
  ip_targ->tot_len = htons(sizeof(struct iphdr) + payload_len);
  ip_targ->id = 0;
  ip_targ->frag_off = htons(IP_DF);
  ip_targ->ttl = old_header->ip6_hlim;
  ip_targ->protocol = protocol;
  ip_targ->check = 0;

  ip_targ->saddr = ipv6_src_to_ipv4_src(&old_header->ip6_src);
  ip_targ->daddr = Global_Clatd_Config.ipv4_local_subnet.s_addr;

  ip_targ->check = ip_checksum(ip_targ, sizeof(struct iphdr));
}

/* function: ipv4_dst_to_ipv6_dst
 * return the corresponding ipv6 address for the given ipv4 address
 * destination - ipv4 destination address (network byte order)
 */
struct in6_addr ipv4_dst_to_ipv6_dst(uint32_t destination) {
  struct in6_addr v6_destination;

  // assumes a /96 plat subnet
  v6_destination = Global_Clatd_Config.plat_subnet;
  v6_destination.s6_addr32[3] = destination;

  return v6_destination;
}

/* function: fill_ip6_header
 * generating an ipv6 header from an ipv4 header (called by the layer 4 protocol-specific functions)
 * ip6         - (ipv6) target packet header, source addr: local subnet prefix, dest addr: nat64 prefix
 * payload_len - length of other data inside packet
 * protocol    - protocol number (tcp, udp, etc)
 * old_header  - (ipv4) source packet header, source addr: local subnet addr, dest addr: internet's ipv4 addr
 */
void fill_ip6_header(struct ip6_hdr *ip6, uint16_t payload_len, uint8_t protocol, const struct iphdr *old_header) {
  memset(ip6, 0, sizeof(struct ip6_hdr));

  ip6->ip6_vfc = 6 << 4;
  ip6->ip6_plen = htons(payload_len);
  ip6->ip6_nxt = protocol;
  ip6->ip6_hlim = old_header->ttl;

  ip6->ip6_src = Global_Clatd_Config.ipv6_local_subnet;
  ip6->ip6_dst = ipv4_dst_to_ipv6_dst(old_header->daddr);
}

/* function: icmp_to_icmp6
 * translate ipv4 icmp to ipv6 icmp (only currently supports echo/echo reply)
 * fd           - tun interface fd
 * ip           - source packet ipv4 header
 * icmp         - source packet icmp header
 * payload      - icmp payload
 * payload_size - size of payload
 */
void icmp_to_icmp6(int fd, const struct iphdr *ip, const struct icmphdr *icmp, const char *payload, size_t payload_size) {
  struct ip6_hdr ip6_targ;
  struct icmp6_hdr icmp6_targ;
  struct iovec io_targ[4];
  struct tun_pi tun_header;
  uint32_t checksum_temp;

  if((icmp->type != ICMP_ECHO) && (icmp->type != ICMP_ECHOREPLY)) {
    logmsg_dbg(ANDROID_LOG_WARN,"icmp_to_icmp6/unhandled icmp type: 0x%x",icmp->type);
    return;
  }

  fill_tun_header(&tun_header,ETH_P_IPV6);

  fill_ip6_header(&ip6_targ,payload_size + sizeof(icmp6_targ),IPPROTO_ICMPV6,ip);

  memset(&icmp6_targ, 0, sizeof(icmp6_targ));
  icmp6_targ.icmp6_type = (icmp->type == ICMP_ECHO) ? ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY;
  icmp6_targ.icmp6_code = 0;
  icmp6_targ.icmp6_cksum = 0;
  icmp6_targ.icmp6_id = icmp->un.echo.id;
  icmp6_targ.icmp6_seq = icmp->un.echo.sequence;

  checksum_temp = ipv6_pseudo_header_checksum(0,&ip6_targ);
  checksum_temp = ip_checksum_add(checksum_temp, &icmp6_targ, sizeof(icmp6_targ));
  checksum_temp = ip_checksum_add(checksum_temp, payload, payload_size);
  icmp6_targ.icmp6_cksum = ip_checksum_finish(checksum_temp);

  io_targ[0].iov_base = &tun_header;
  io_targ[0].iov_len = sizeof(tun_header);
  io_targ[1].iov_base = &ip6_targ;
  io_targ[1].iov_len = sizeof(ip6_targ);
  io_targ[2].iov_base = &icmp6_targ;
  io_targ[2].iov_len = sizeof(icmp6_targ);
  io_targ[3].iov_base = (char *)payload;
  io_targ[3].iov_len = payload_size;

  writev(fd, io_targ, 4);
}

/* function: icmp6_to_icmp
 * translate ipv6 icmp to ipv4 icmp (only currently supports echo/echo reply)
 * fd           - tun interface fd
 * ip6          - source packet ipv6 header
 * icmp6        - source packet icmp6 header
 * payload      - icmp6 payload
 * payload_size - size of payload
 */
void icmp6_to_icmp(int fd, const struct ip6_hdr *ip6, const struct icmp6_hdr *icmp6, const char *payload, size_t payload_size) {
  struct iphdr ip_targ;
  struct icmphdr icmp_targ;
  struct iovec io_targ[4];
  struct tun_pi tun_header;
  uint32_t temp_icmp_checksum;

  if((icmp6->icmp6_type != ICMP6_ECHO_REQUEST) && (icmp6->icmp6_type != ICMP6_ECHO_REPLY)) {
    logmsg_dbg(ANDROID_LOG_WARN,"icmp6_to_icmp/unhandled icmp6 type: 0x%x",icmp6->icmp6_type);
    return;
  }

  memset(&icmp_targ, 0, sizeof(icmp_targ));

  fill_tun_header(&tun_header,ETH_P_IP);
  fill_ip_header(&ip_targ,sizeof(icmp_targ) + payload_size, IPPROTO_ICMP, ip6);

  icmp_targ.type = (icmp6->icmp6_type == ICMP6_ECHO_REQUEST) ? ICMP_ECHO : ICMP_ECHOREPLY;
  icmp_targ.code = 0x0;
  icmp_targ.checksum = 0;
  icmp_targ.un.echo.id = icmp6->icmp6_id;
  icmp_targ.un.echo.sequence = icmp6->icmp6_seq;

  temp_icmp_checksum = ip_checksum_add(0, &icmp_targ, sizeof(icmp_targ));
  temp_icmp_checksum = ip_checksum_add(temp_icmp_checksum, (void *)payload, payload_size);
  icmp_targ.checksum = ip_checksum_finish(temp_icmp_checksum);

  io_targ[0].iov_base = &tun_header;
  io_targ[0].iov_len = sizeof(tun_header);
  io_targ[1].iov_base = &ip_targ;
  io_targ[1].iov_len = sizeof(ip_targ);
  io_targ[2].iov_base = &icmp_targ;
  io_targ[2].iov_len = sizeof(icmp_targ);
  io_targ[3].iov_base = (char *)payload;
  io_targ[3].iov_len = payload_size;

  writev(fd, io_targ, 4);
}

/* function: udp_translate
 * common between ipv4/ipv6 - setup checksum and send udp packet
 * fd           - tun interface fd
 * udp          - source packet udp header
 * payload      - udp payload
 * payload_size - size of payload
 * io_targ      - iovec with tun and ipv4/ipv6 header (see below)
 *     array position 0 - tun header
 *     array position 1 - ipv4/ipv6 header
 *     array position 2 - empty (will be udp header)
 *     array position 3 - empty (will be payload)
 * checksum     - partial checksum covering ipv4/ipv6 header
 */
void udp_translate(int fd, const struct udphdr *udp, const char *payload, size_t payload_size, struct iovec *io_targ, uint32_t checksum) {
  struct udphdr udp_targ;

  memcpy(&udp_targ, udp, sizeof(udp_targ));
  udp_targ.check = 0; // reset checksum, to be calculated

  checksum = ip_checksum_add(checksum, &udp_targ, sizeof(struct udphdr));
  checksum = ip_checksum_add(checksum, payload, payload_size);
  udp_targ.check = ip_checksum_finish(checksum);

  io_targ[2].iov_base = &udp_targ;
  io_targ[2].iov_len = sizeof(udp_targ);
  io_targ[3].iov_base = (char *)payload;
  io_targ[3].iov_len = payload_size;

  writev(fd, io_targ, 4);
}

/* function: udp_to_udp6
 * translate ipv4 udp to ipv6 udp
 * fd           - tun interface fd
 * ip           - source packet ipv4 header
 * udp          - source packet udp header
 * payload      - udp payload
 * payload_size - size of payload
 */
void udp_to_udp6(int fd, const struct iphdr *ip, const struct udphdr *udp, const char *payload, size_t payload_size) {
  struct ip6_hdr ip6_targ;
  struct iovec io_targ[4];
  struct tun_pi tun_header;
  uint32_t checksum;

  fill_tun_header(&tun_header,ETH_P_IPV6);

  fill_ip6_header(&ip6_targ,payload_size + sizeof(struct udphdr),IPPROTO_UDP,ip);

  checksum = ipv6_pseudo_header_checksum(0, &ip6_targ);

  io_targ[0].iov_base = &tun_header;
  io_targ[0].iov_len = sizeof(tun_header);
  io_targ[1].iov_base = &ip6_targ;
  io_targ[1].iov_len = sizeof(ip6_targ);

  udp_translate(fd,udp,payload,payload_size,io_targ,checksum);
}

/* function: udp6_to_udp
 * translate ipv6 udp to ipv4 udp
 * fd           - tun interface fd
 * ip6          - source packet ipv6 header
 * udp          - source packet udp header
 * payload      - udp payload
 * payload_size - size of payload
 */
void udp6_to_udp(int fd, const struct ip6_hdr *ip6, const struct udphdr *udp, const char *payload, size_t payload_size) {
  struct iphdr ip_targ;
  struct iovec io_targ[4];
  struct tun_pi tun_header;
  uint32_t checksum;

  fill_tun_header(&tun_header,ETH_P_IP);

  fill_ip_header(&ip_targ,payload_size + sizeof(struct udphdr),IPPROTO_UDP,ip6);

  checksum = ipv4_pseudo_header_checksum(0, &ip_targ);

  io_targ[0].iov_base = &tun_header;
  io_targ[0].iov_len = sizeof(tun_header);
  io_targ[1].iov_base = &ip_targ;
  io_targ[1].iov_len = sizeof(ip_targ);

  udp_translate(fd,udp,payload,payload_size,io_targ,checksum);
}

/* function: tcp_translate
 * common between ipv4/ipv6 - setup checksum and send tcp packet
 * fd           - tun interface fd
 * tcp          - source packet tcp header
 * payload      - tcp payload
 * payload_size - size of payload
 * io_targ      - iovec with tun and ipv4/ipv6 header (see below)
 *     array position 0 - tun header
 *     array position 1 - ipv4/ipv6 header
 *     array position 2 - empty (will be tcp header)
 *     array position 3 - empty (will be tcp options or payload)
 *     array position 4 - empty (can be payload)
 * checksum     - partial checksum covering ipv4/ipv6 header
 * options      - pointer to tcp option buffer
 * options_size - size of tcp option buffer
 *
 * TODO: mss rewrite
 * TODO: hosts without pmtu discovery - non DF packets will rely on fragmentation (unimplemented)
 */
void tcp_translate(int fd, const struct tcphdr *tcp, const char *payload, size_t payload_size, struct iovec *io_targ, uint32_t checksum, const char *options, size_t options_size) {
  struct tcphdr tcp_targ;
  int targ_index = 2;

  memcpy(&tcp_targ, tcp, sizeof(tcp_targ));
  tcp_targ.check = 0;

  checksum = ip_checksum_add(checksum, &tcp_targ, sizeof(tcp_targ));
  if(options) {
    checksum = ip_checksum_add(checksum, options, options_size);
  }
  checksum = ip_checksum_add(checksum, payload, payload_size);
  tcp_targ.check = ip_checksum_finish(checksum);

  io_targ[targ_index].iov_base = &tcp_targ;
  io_targ[targ_index].iov_len = sizeof(tcp_targ);
  targ_index++;

  if(options) {
    io_targ[targ_index].iov_base = (char *)options;
    io_targ[targ_index].iov_len = options_size;
    targ_index++;
  }

  io_targ[targ_index].iov_base = (char *)payload;
  io_targ[targ_index].iov_len = payload_size;
  targ_index++;

  writev(fd, io_targ, targ_index);
}

/* function: tcp_to_tcp6
 * translate ipv4 tcp to ipv6 tcp
 * fd           - tun interface fd
 * ip           - source packet ipv4 header
 * tcp          - source packet tcp header
 * payload      - tcp payload
 * payload_size - size of payload
 * options      - tcp options
 * options_size - size of options
 */
void tcp_to_tcp6(int fd,const struct iphdr *ip, const struct tcphdr *tcp, const char *payload, size_t payload_size, const char *options, size_t options_size) {
  struct ip6_hdr ip6_targ;
  struct iovec io_targ[5];
  struct tun_pi tun_header;
  uint32_t checksum;

  fill_tun_header(&tun_header,ETH_P_IPV6);

  fill_ip6_header(&ip6_targ,payload_size+options_size+sizeof(struct tcphdr),IPPROTO_TCP,ip);

  checksum = ipv6_pseudo_header_checksum(0, &ip6_targ);

  io_targ[0].iov_base = &tun_header;
  io_targ[0].iov_len = sizeof(tun_header);
  io_targ[1].iov_base = &ip6_targ;
  io_targ[1].iov_len = sizeof(ip6_targ);

  tcp_translate(fd,tcp,payload,payload_size,io_targ,checksum,options,options_size);
}

/* function: tcp6_to_tcp
 * translate ipv6 tcp to ipv4 tcp
 * fd           - tun interface fd
 * ip6          - source packet ipv6 header
 * tcp          - source packet tcp header
 * payload      - tcp payload
 * payload_size - size of payload
 * options      - tcp options
 * options_size - size of options
 */
void tcp6_to_tcp(int fd,const struct ip6_hdr *ip6, const struct tcphdr *tcp, const char *payload, size_t payload_size, const char *options, size_t options_size) {
  struct iphdr ip_targ;
  struct iovec io_targ[5];
  struct tun_pi tun_header;
  uint32_t checksum;

  fill_tun_header(&tun_header,ETH_P_IP);

  fill_ip_header(&ip_targ,payload_size+options_size+sizeof(struct tcphdr),IPPROTO_TCP,ip6);

  checksum = ipv4_pseudo_header_checksum(0, &ip_targ);

  io_targ[0].iov_base = &tun_header;
  io_targ[0].iov_len = sizeof(tun_header);
  io_targ[1].iov_base = &ip_targ;
  io_targ[1].iov_len = sizeof(ip_targ);

  tcp_translate(fd,tcp,payload,payload_size,io_targ,checksum,options,options_size);
}
