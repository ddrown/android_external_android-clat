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
 * clatd.c - tun interface setup and main event loop
 */
#include "system_headers.h"
#include "ipv4.h"
#include "ipv6.h"
#include "clatd.h"
#include "config.h"
#include "logging.h"
#include "setif.h"
#include "setroute.h"
#include "mtu.h"
#include "getaddr.h"

#include <linux/capability.h>
#include <linux/prctl.h>
#include <private/android_filesystem_config.h>
#include <signal.h>
#include <time.h>
#include <sys/system_properties.h>

#define DEVICENAME "clat"

int forwarding_fd = -1;

/* function: set_forwarding
 * enables/disables ipv6 forwarding
 */
void set_forwarding(int fd, const char *setting) {
  /* we have to forward packets from the WAN to the tun interface */
  if(write(fd, setting, strlen(setting)) < 0) {
    logmsg(ANDROID_LOG_WARN,"set_forwarding failed: %s", strerror(errno));
  }
}

/* function: got_sigterm
 * signal handler: clean up and exit
 */
void got_sigterm(int signal) {
  if(forwarding_fd > 0) {
    set_forwarding(forwarding_fd, "0\n");
  }
  exit(0);
}

/* function: tun_open
 * tries to open the tunnel device
 */
int tun_open() {
  int fd;
  char *tundevpath;

  tundevpath = "/dev/tun";
  if(access(tundevpath, R_OK|W_OK) < 0) {
    tundevpath = "/dev/net/tun";
    if(access(tundevpath, R_OK|W_OK) < 0) {
      return -1;
    }
  }

  fd = open(tundevpath, O_RDWR);
  return fd;
}

/* function: tun_alloc
 * creates a tun interface and names it
 * dev - the name for the new tun device
 */
int tun_alloc(char *dev, int fd) {
  struct ifreq ifr;
  int err;

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN;
  if( *dev )
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
    close(fd);
    return err;
  }
  strcpy(dev, ifr.ifr_name);
  return fd;
}

/* function: deconfigure_tun_ipv6
 * removes the ipv6 route
 * device - the clat device name
 */
void deconfigure_tun_ipv6(const char *device) {
  int status;

  if((status = if_route(device, AF_INET6, &config.ipv6_local_subnet, 128, NULL, 1, 0, ROUTE_DELETE)) < 0) {
    logmsg(ANDROID_LOG_FATAL,"deconfigure_tun_ipv6/if_route(6) failed: %s",strerror(-status));
    exit(1);
  }
}

/* function: configure_tun_ipv6
 * configures the ipv6 route
 * note: routes a /128 out of the (assumed routed to us) /64 to the CLAT interface
 * device - the clat device name to configure
 */
void configure_tun_ipv6(const char *device) {
  struct in6_addr local_nat64_prefix_6;
  int status;

  if((status = if_route(device, AF_INET6, &config.ipv6_local_subnet, 128, NULL, 1, 0, ROUTE_CREATE)) < 0) {
    logmsg(ANDROID_LOG_FATAL,"configure_tun_ipv6/if_route(6) failed: %s",strerror(-status));
    exit(1);
  }
}

/* function: interface_poll
 * polls the uplink network interface for address changes
 */
void interface_poll() {
  union anyip *interface_ip;

  interface_ip = getinterface_ip(config.default_pdp_interface, AF_INET6);
  if(!interface_ip) {
    logmsg(ANDROID_LOG_FATAL,"unable to find an ipv6 ip on interface %s",config.default_pdp_interface);
    return;
  }

  config_generate_local_ipv6_subnet(&interface_ip->ip6);

  if(!IN6_ARE_ADDR_EQUAL(&interface_ip->ip6, &config.ipv6_local_subnet)) {
    char from_addr[INET6_ADDRSTRLEN], to_addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &config.ipv6_local_subnet, from_addr, sizeof(from_addr));
    inet_ntop(AF_INET6, &interface_ip->ip6, to_addr, sizeof(to_addr));
    logmsg(ANDROID_LOG_WARN, "clat subnet changed from %s to %s", from_addr, to_addr);

    // remove old route
    deconfigure_tun_ipv6(config.default_pdp_interface);

    // add new route, start translating packets to the new prefix
    memcpy(&config.ipv6_local_subnet, &interface_ip->ip6, sizeof(struct in6_addr));
    configure_tun_ipv6(config.default_pdp_interface);
  }

  free(interface_ip);
}

/* function: configure_tun_ip
 * configures the ipv4 and ipv6 addresses on the tunnel interface
 * device - the clat device name to configure
 */
void configure_tun_ip(const char *device) {
  struct in_addr default_4;
  int status;

  default_4.s_addr = INADDR_ANY;

  if((status = if_up(device, config.mtu)) < 0) {
    logmsg(ANDROID_LOG_FATAL,"configure_tun_ip/if_up failed: %s",strerror(-status));
    exit(1);
  }
  if((status = add_address(device, AF_INET, &config.ipv4_local_subnet, 32, &config.ipv4_local_subnet)) < 0) {
    logmsg(ANDROID_LOG_FATAL,"configure_tun_ip/if_address(4) failed: %s",strerror(-status));
    exit(1);
  }

  configure_tun_ipv6(device);

  /* setup default ipv4 route */
  if((status = if_route(device, AF_INET, &default_4, 0, NULL, 1, config.ipv4mtu, ROUTE_REPLACE)) < 0) {
    logmsg(ANDROID_LOG_FATAL,"configure_tun_ip/if_route failed: %s",strerror(-status));
    exit(1);
  }
}

/* function: drop_root
 * drops root privs but keeps the needed capability
 */
void drop_root() {
  gid_t groups[] = { AID_INET };
  setgroups(sizeof(groups)/sizeof(groups[0]), groups);

  prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

  setgid(AID_CLATD);
  setuid(AID_CLATD);

  struct __user_cap_header_struct header;
  struct __user_cap_data_struct cap;
  header.version = _LINUX_CAPABILITY_VERSION;
  header.pid = 0;
  cap.inheritable =
   cap.effective = cap.permitted = (1 << CAP_NET_ADMIN);
  capset(&header, &cap);
}

/* function: main
 * allocate and setup the tun device, then run the event loop
 */
int main() {
  int fd, starting;
  char packet[PACKETLEN];
  char device[50] = DEVICENAME;
  size_t readlen;
  time_t startup, last_forward_write, last_interface_poll;

  // make note of the time we started
  startup = last_interface_poll = time(NULL);
  starting = 1;

  // open the tunnel device before dropping privs
  fd = tun_open();
  if(fd < 0) {
    logmsg(ANDROID_LOG_FATAL,"tun_open failed: %s",strerror(errno));
    exit(1);
  }

  // open the forwarding configuration before dropping privs
  forwarding_fd = open("/proc/sys/net/ipv6/conf/all/forwarding", O_RDWR);
  if(forwarding_fd < 0) {
    logmsg(ANDROID_LOG_FATAL,"open /proc/sys/net/ipv6/conf/all/forwarding failed: %s",strerror(errno));
    exit(1);
  }

  if(signal(SIGTERM, got_sigterm) == SIG_ERR) {
    logmsg(ANDROID_LOG_FATAL, "sigterm handler failed: %s", strerror(errno));
    exit(1);
  }

  if(!read_config("/system/etc/clatd.conf")) {
    logmsg(ANDROID_LOG_FATAL,"read_config failed");
    exit(1);
  }

  if(config.mtu < 0) {
    config.mtu = getifmtu(config.default_pdp_interface);
    logmsg(ANDROID_LOG_WARN,"ifmtu=%d",config.mtu);
  }
  if(config.mtu < 1280) {
    logmsg(ANDROID_LOG_FATAL,"mtu too small = %d", config.mtu);
    config.mtu = 1280;
  }

  if(config.ipv4mtu < 0) {
    config.ipv4mtu = config.mtu-20;
    logmsg(ANDROID_LOG_WARN,"ipv4mtu=%d",config.ipv4mtu);
  }

  fd = tun_alloc(device, fd);
  if(fd < 0) {
    logmsg(ANDROID_LOG_FATAL,"tun_alloc failed: %s",strerror(errno));
    exit(1);
  }

  configure_tun_ip(device);

  if(__system_property_set("net.ipv4.compat","clat") < 0) {
    logmsg(ANDROID_LOG_WARN,"failed to set net.ipv4.compat property");
  }

  set_forwarding(forwarding_fd,"1\n");
  last_forward_write = time(NULL);

  // run under a regular user
  drop_root();

  while((readlen = read(fd,packet,PACKETLEN)) > 0) {
    uint16_t flags, proto;
    time_t now = time(NULL);

    if(starting) {
      // If we're starting up, make sure ipv6 forwarding is turned on
      // protecting from racing against a quick transition from shutdown to
      // startup
      if(last_forward_write < now) {
        set_forwarding(forwarding_fd,"1\n");
        last_forward_write = now;
      }
      if(startup < (now - 5)) {
        starting = 0;
      }
    }

    if(readlen < 4) {
      logmsg(ANDROID_LOG_WARN,"main/read short: got %ld bytes", readlen);
      continue;
    }

    flags = proto = 0;
    memcpy(&flags, packet, 2);
    memcpy(&proto, packet+2, 2);

    proto = ntohs(proto);
    flags = ntohs(flags);

    if(proto == ETH_P_IP) {
      ip_packet(fd,packet+4,readlen-4);
    } else if(proto == ETH_P_IPV6) {
      ipv6_packet(fd,packet+4,readlen-4);
    } else if(proto == 0) {
      // ignore proto 0
    } else {
      logmsg(ANDROID_LOG_WARN,"main/unknown packet type = %x",proto);
    }

    memset(packet, 0, PACKETLEN);

    if(last_interface_poll < (now - 30)) {
      interface_poll();
      last_interface_poll = now;
    }
  }

  set_forwarding(forwarding_fd,"0\n");

  return 0;
}
