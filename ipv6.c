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
 * ipv6.c - takes ipv6 packets, finds their headers, and then calls translation functions on them
 */
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/icmp.h>

#include "translate.h"
#include "checksum.h"
#include "ipv6.h"
#include "logging.h"
#include "dump.h"
#include "config.h"
#include "debug.h"

/* function: icmp6_packet
 * takes an icmp6 packet and sets it up for translation
 * fd     - tun interface fd
 * packet - ip payload
 * len    - size of ip payload
 * ip6    - ip6 header
 */
void icmp6_packet(int fd, const char *packet, size_t len, struct ip6_hdr *ip6) {
  struct icmp6_hdr icmp6;
  const char *payload;
  size_t payload_size;

  if(len < sizeof(icmp6)) {
    logmsg_dbg(ANDROID_LOG_ERROR,"icmp6_packet/(too small)");
    return;
  }

  memcpy(&icmp6, packet, sizeof(icmp6));
  payload = packet + sizeof(icmp6);
  payload_size = len - sizeof(icmp6);

  icmp6_to_icmp(fd, ip6, &icmp6, payload, payload_size);
}

/* function: tcp6_packet
 * takes a tcp packet and sets it up for translation
 * fd     - tun interface fd
 * packet - ip payload
 * len    - size of ip payload
 * ip6    - ip6 header
 */
void tcp6_packet(int fd, const char *packet, size_t len, struct ip6_hdr *ip6) {
  struct tcphdr tcp;
  const char *payload;
  const char *options;
  size_t payload_size, options_size;

  if(len < sizeof(tcp)) {
    logmsg_dbg(ANDROID_LOG_ERROR,"tcp6_packet/(too small)");
    return;
  }

  memcpy(&tcp, packet, sizeof(tcp));

  if(tcp.doff < 5) {
    logmsg_dbg(ANDROID_LOG_ERROR,"tcp6_packet/tcp header length set to less than 5: %x",tcp.doff);
    return;
  }

  if((size_t)tcp.doff*4 > len) {
    logmsg_dbg(ANDROID_LOG_ERROR,"tcp6_packet/tcp header length set too large: %x",tcp.doff);
    return;
  }

  if(tcp.doff > 5) {
    options = packet + sizeof(tcp);
    options_size = tcp.doff*4 - sizeof(tcp);
  } else {
    options = NULL;
    options_size = 0;
  }

  payload = packet + tcp.doff*4;
  payload_size = len - tcp.doff*4;

  tcp6_to_tcp(fd,ip6,&tcp,payload,payload_size,options,options_size);
}

/* function: udp6_packet
 * takes a udp packet and sets it up for translation
 * fd     - tun interface fd
 * packet - ip payload
 * len    - size of ip payload
 * ip6    - ip6 header
 */
void udp6_packet(int fd, const char *packet, size_t len, struct ip6_hdr *ip6) {
  struct udphdr udp;
  const char *payload;
  size_t payload_size;

  if(len < sizeof(udp)) {
    logmsg_dbg(ANDROID_LOG_ERROR,"udp6_packet/(too small)");
    return;
  }

  memcpy(&udp, packet, sizeof(udp));
  payload = packet + sizeof(udp);
  payload_size = len - sizeof(udp);

  udp6_to_udp(fd,ip6,&udp,payload,payload_size);
}

/* function: log_bad_address
 * logs a bad address to android's log buffer if debugging is turned on
 * fmt     - printf-style format, use %s to place the address
 * badaddr - the bad address in question
 */
void log_bad_address(const char *fmt, const struct in6_addr *badaddr) {
#if CLAT_DEBUG
  char badaddr_str[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET6, badaddr, badaddr_str, sizeof(badaddr_str));
  logmsg_dbg(ANDROID_LOG_ERROR,fmt,badaddr_str);
#endif
}

/* function: ipv6_packet
 * takes an ipv6 packet and hands it off to the layer 4 protocol function
 * fd     - tun interface fd
 * packet - packet data
 * len    - size of packet
 */
void ipv6_packet(int fd, const char *packet, size_t len) {
  struct ip6_hdr header;
  const char *next_header;
  size_t len_left;
  int i;

  if(len < sizeof(header)) {
    logmsg_dbg(ANDROID_LOG_ERROR,"ipv6_packet/too short for an ip6 header");
    return;
  }

  memcpy(&header, packet, sizeof(header));

  next_header = packet + sizeof(header);
  len_left = len - sizeof(header);

  if(IN6_IS_ADDR_MULTICAST(&header.ip6_dst)) {
    log_bad_address("ipv6_packet/multicast %s", &header.ip6_dst);
    return; // silently ignore
  }

  for(i = 0; i < 3; i++) {
    if(header.ip6_src.s6_addr32[i] != Global_Clatd_Config.plat_subnet.s6_addr32[i]) {
      log_bad_address("ipv6_packet/wrong source address: %s", &header.ip6_src);
      return;
    }
  }
  if(!IN6_ARE_ADDR_EQUAL(&header.ip6_dst, &Global_Clatd_Config.ipv6_local_subnet)) {
    log_bad_address("ipv6_packet/wrong destination address: %s", &header.ip6_dst);
    return;
  }

  // does not support IPv6 extension headers, this will drop any packet with them
  if(header.ip6_nxt == IPPROTO_ICMPV6) {
    icmp6_packet(fd,next_header,len_left,&header);
  } else if(header.ip6_nxt == IPPROTO_TCP) {
    tcp6_packet(fd,next_header,len_left,&header);
  } else if(header.ip6_nxt == IPPROTO_UDP) {
    udp6_packet(fd,next_header,len_left,&header);
  } else {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"ipv6_packet/unknown next header type: %x",header.ip6_nxt);
    logcat_hexdump("ipv6/nxthdr", packet, len);
#endif
  }
}
