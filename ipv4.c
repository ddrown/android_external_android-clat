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
 * ipv4.c - takes ipv4 packets, finds their headers, and then calls translation functions on them
 */
#include "system_headers.h"
#include "translate.h"
#include "checksum.h"
#include "ipv4.h"
#include "logging.h"
#include "debug.h"

/* function: icmp_packet
 * takes an icmp packet and sets it up for translation
 * fd     - tun interface fd
 * packet - ip payload
 * len    - size of ip payload
 * ip     - ip header
 */
void icmp_packet(int fd, char *packet, size_t len, struct iphdr *ip) {
  struct icmphdr icmp;
  char *payload;
  size_t payload_size;

  if(len < sizeof(icmp)) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"icmp_packet/(too small)");
#endif
    return;
  }

  memcpy(&icmp, packet, sizeof(icmp));
  payload = packet + sizeof(icmp);
  payload_size = len - sizeof(icmp);

  icmp_to_icmp6(fd,ip,&icmp,payload,payload_size);
}

/* function: tcp_packet
 * takes a tcp packet and sets it up for translation
 * fd     - tun interface fd
 * packet - ip payload
 * len    - size of ip payload
 * ip     - ip header
 */
void tcp_packet(int fd, char *packet, size_t len, struct iphdr *ip) {
  struct tcphdr tcp;
  char *payload;
  char *options;
  size_t payload_size, options_size;

  if(len < sizeof(tcp)) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"tcp_packet/(too small)");
#endif
    return;
  }

  memcpy(&tcp, packet, sizeof(tcp));

  if(tcp.doff < 5) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"tcp_packet/tcp header length set to less than 5: %x",tcp.doff);
#endif
    return;
  }

  if((size_t)tcp.doff*4 > len) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"tcp_packet/tcp header length set too large: %x",tcp.doff);
#endif
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

  tcp_to_tcp6(fd,ip,&tcp,payload,payload_size,options,options_size);
}

/* function: udp_packet
 * takes a udp packet and sets it up for translation
 * fd     - tun interface fd
 * packet - ip payload
 * len    - size of ip payload
 * ip     - ip header
 */
void udp_packet(int fd, char *packet, size_t len, const struct iphdr *ip) {
  struct udphdr udp;
  char *payload;
  size_t payload_size;

  if(len < sizeof(udp)) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"udp_packet/(too small)");
#endif
    return;
  }

  memcpy(&udp, packet, sizeof(udp));
  payload = packet + sizeof(udp);
  payload_size = len - sizeof(udp);

  udp_to_udp6(fd,ip,&udp,payload,payload_size);
}

/* function: ip_packet
 * takes an ip packet and hands it off to the layer 4 protocol function
 * fd     - tun interface fd
 * packet - packet data
 * len    - size of packet
 */
void ip_packet(int fd, char *packet, size_t len) {
  struct iphdr header;
  uint16_t frag_flags;
  char *next_header;
  size_t len_left;

  if(len < sizeof(header)) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"ip_packet/too short for an ip header");
#endif
    return;
  }

  memcpy(&header, packet, sizeof(header));

  frag_flags = ntohs(header.frag_off);
  if(frag_flags & IP_MF) { // this could theoretically be supported, but isn't
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"ip_packet/more fragments set, dropping");
#endif
    return;
  }

  if(header.ihl < 5) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"ip_packet/ip header length set to less than 5: %x",header.ihl);
#endif
    return;
  }

  if((size_t)header.ihl*4 > len) { // ip header length larger than entire packet
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"ip_packet/ip header length set too large: %x",header.ihl);
#endif
    return;
  }

  if(header.version != 4) {
#if CLAT_DEBUG
    logmsg(ANDROID_LOG_ERROR,"ip_packet/ip header version not 4: %x",header.version);
#endif
    return;
  }

  /* rfc6145 - If any IPv4 options are present in the IPv4 packet, they MUST be
   * ignored and the packet translated normally; there is no attempt to
   * translate the options.
   */

  next_header = packet + header.ihl*4;
  len_left = len - header.ihl*4;

  if(header.protocol == IPPROTO_ICMP) {
    icmp_packet(fd,next_header,len_left,&header);
  } else if(header.protocol == IPPROTO_TCP) {
    tcp_packet(fd,next_header,len_left,&header);
  } else if(header.protocol == IPPROTO_UDP) {
    udp_packet(fd,next_header,len_left,&header);
  } else {
#if CLAT_DEBUG
    logcat_hexdump("ipv4/protocol", packet, len);
    logmsg(ANDROID_LOG_ERROR,"ip_packet/unknown protocol: %x",header.protocol);
#endif
  }
}
