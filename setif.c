/*
 * Copyright 2012 Daniel Drown <dan-android@drown.org>
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
 * setif.c - network interface configuration
 */
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>

#include <linux/rtnetlink.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>

#include "netlink_msg.h"
#include "netlink_callbacks.h"

/* function: add_address
 * adds an IP address to/from an interface, returns 0 on success and <0 on failure
 * ifname    - name of interface to change
 * family    - address family (AF_INET, AF_INET6)
 * address   - pointer to a struct in_addr or in6_addr
 * prefixlen - bitmask of network (example: 24 for AF_INET's 255.255.255.0)
 * broadcast - broadcast address (only for AF_INET, ignored for AF_INET6)
 */
int add_address(const char *ifname, int family, const void *address, int prefixlen, const void *broadcast) {
  int retval = -1;
  ssize_t addr_size;
  struct ifaddrmsg ifa;
  struct nl_msg *msg = NULL;
  struct nl_cb *callbacks = NULL;

  addr_size = inet_family_size(family);
  if(addr_size == 0) {
    retval = -EINVAL;
    goto cleanup;
  }

  callbacks = alloc_ack_callbacks(&retval);
  if(!callbacks) {
    retval = -ENOMEM;
    goto cleanup;
  }

  memset(&ifa, 0, sizeof(ifa));
  if (!(ifa.ifa_index = if_nametoindex(ifname))) {
    retval = -ENODEV;
    goto cleanup;
  }
  ifa.ifa_family = family;
  ifa.ifa_prefixlen = prefixlen;
  ifa.ifa_scope = 0;

  msg = nlmsg_alloc_ifaddr(RTM_NEWADDR, NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE, &ifa);
  if(!msg) {
    retval = -ENOMEM;
    goto cleanup;
  }

  if(nla_put(msg, IFA_LOCAL, addr_size, address) < 0) {
    retval = -ENOMEM;
    goto cleanup;
  }
  if(family == AF_INET6) {
    if(nla_put(msg, IFA_ADDRESS, addr_size, address) < 0) {
      retval = -ENOMEM;
      goto cleanup;
    }
  }
  if(family == AF_INET) { // AF_INET6 has no broadcast address
    if(nla_put(msg, IFA_BROADCAST, addr_size, broadcast) < 0) {
      retval = -ENOMEM;
      goto cleanup;
    }
  }

  send_netlink_msg(msg, callbacks);

cleanup:
  if(callbacks)
    nl_cb_put(callbacks);
  if(msg)
    nlmsg_free(msg);

  return retval;
}

/* function: if_up
 * sets interface link state to up and sets mtu, returns 0 on success and <0 on failure
 * ifname - interface name to change
 * mtu    - new mtu
 */
int if_up(const char *ifname, int mtu) {
  int retval = -1;
  struct ifinfomsg ifi;
  struct nl_msg *msg = NULL;
  struct nl_cb *callbacks = NULL;

  callbacks = alloc_ack_callbacks(&retval);
  if(!callbacks) {
    retval = -ENOMEM;
    goto cleanup;
  }

  memset(&ifi, 0, sizeof(ifi));
  if (!(ifi.ifi_index = if_nametoindex(ifname))) {
    retval = -ENODEV;
    goto cleanup;
  }
  ifi.ifi_change = IFF_UP;
  ifi.ifi_flags = IFF_UP;

  msg = nlmsg_alloc_ifinfo(RTM_SETLINK, NLM_F_ACK | NLM_F_REQUEST | NLM_F_ROOT, &ifi);
  if(!msg) {
    retval = -ENOMEM;
    goto cleanup;
  }

  if(nla_put(msg, IFLA_MTU, 4, &mtu) < 0) {
    retval = -ENOMEM;
    goto cleanup;
  }

  send_netlink_msg(msg, callbacks);

cleanup:
  if(callbacks)
    nl_cb_put(callbacks);
  if(msg)
    nlmsg_free(msg);

  return retval;
}
