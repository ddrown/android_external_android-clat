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
 * translate.h - translate from one version of ip to another
 */
#ifndef __TRANSLATE_H__
#define __TRANSLATE_H__

void icmp_to_icmp6(int fd, const struct iphdr *ip, const struct icmphdr *icmp, const char *payload, size_t payload_size);
void icmp6_to_icmp(int fd, const struct ip6_hdr *ip6, const struct icmp6_hdr *icmp6, const char *payload, size_t payload_size);

void udp_to_udp6(int fd, const struct iphdr *ip, const struct udphdr *udp, const char *payload, size_t payload_size);
void udp6_to_udp(int fd, const struct ip6_hdr *ip6, const struct udphdr *udp, const char *payload, size_t payload_size);

void tcp_to_tcp6(int fd,const struct iphdr *ip, const struct tcphdr *tcp, const char *payload, size_t payload_size, const char *options, size_t options_size);
void tcp6_to_tcp(int fd,const struct ip6_hdr *ip6, const struct tcphdr *tcp, const char *payload, size_t payload_size, const char *options, size_t options_size);

#endif /* __TRANSLATE_H__ */
