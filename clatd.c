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
#include "dump.h"

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

/* function: set_accept_ra
 * accepts IPv6 RAs on all interfaces, even when forwarding is on
 */
void set_accept_ra() {
  int fd;
  fd = open("/proc/sys/net/ipv6/conf/all/accept_ra", O_RDWR);
  if(fd < 0) {
    logmsg(ANDROID_LOG_WARN,"open /proc/sys/net/ipv6/conf/all/accept_ra failed: %s",strerror(errno));
    return;
  }
  if(write(fd, "2\n", 2) < 0) {
    logmsg(ANDROID_LOG_WARN,"write to accept_ra failed: %s",strerror(errno));
  }
  close(fd);
}

/* function: got_sigterm
 * signal handler: clean up and exit
 */
void got_sigterm(int signal) {
  if(forwarding_fd > -1) {
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
  return 0;
}

/* function: deconfigure_tun_ipv6
 * removes the ipv6 route
 * device - the clat device name
 */
void deconfigure_tun_ipv6(const char *device) {
  int status;

  if((status = if_route(device, AF_INET6, &config.ipv6_local_subnet, 128, NULL, 1, 0, ROUTE_DELETE)) < 0) {
    logmsg(ANDROID_LOG_WARN,"deconfigure_tun_ipv6/if_route(6) failed: %s",strerror(-status));
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
void interface_poll(const char *tun_device) {
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
    deconfigure_tun_ipv6(tun_device);

    // add new route, start translating packets to the new prefix
    memcpy(&config.ipv6_local_subnet, &interface_ip->ip6, sizeof(struct in6_addr));
    configure_tun_ipv6(tun_device);
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
  if(setgroups(sizeof(groups)/sizeof(groups[0]), groups) < 0) {
    logmsg(ANDROID_LOG_FATAL,"drop_root/setgroups failed: %s",strerror(errno));
    exit(1);
  }

  prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

  if(setgid(AID_CLATD) < 0) {
    logmsg(ANDROID_LOG_FATAL,"drop_root/setgid failed: %s",strerror(errno));
    exit(1);
  }
  if(setuid(AID_CLATD) < 0) {
    logmsg(ANDROID_LOG_FATAL,"drop_root/setuid failed: %s",strerror(errno));
    exit(1);
  }

  struct __user_cap_header_struct header;
  struct __user_cap_data_struct cap;
  header.version = _LINUX_CAPABILITY_VERSION;
  header.pid = 0; // 0 = change myself
  cap.inheritable =
   cap.effective = cap.permitted = (1 << CAP_NET_ADMIN);

  if(capset(&header, &cap) < 0) {
    logmsg(ANDROID_LOG_FATAL,"drop_root/capset failed: %s",strerror(errno));
    exit(1);
  }
}

/* function: configure_interface
 * reads the configuration and applies it to the interface
 * uplink_interface - network interface to use to reach the ipv6 internet
 * plat_prefix      - PLAT prefix to use
 * fd               - file descriptor to tun device
 * device           - (in) requested device name (out) allocated device name
 */
void configure_interface(const char *uplink_interface, const char *plat_prefix, int fd, char *device) {
  int error;

  if(!read_config("/system/etc/clatd.conf", uplink_interface, plat_prefix)) {
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

  error = tun_alloc(device, fd);
  if(error < 0) {
    logmsg(ANDROID_LOG_FATAL,"tun_alloc failed: %s",strerror(errno));
    exit(1);
  }

  configure_tun_ip(device);
}

/* function: packet_handler
 * takes a tun header and a packet and sends it down the stack
 * tun_fd     - tun file descriptor
 * tun_header - tun header
 * packet     - packet
 * packetsize - size of packet
 */
void packet_handler(int tun_fd, struct tun_pi *tun_header, const char *packet, size_t packetsize) {
  tun_header->proto = ntohs(tun_header->proto);

  if(tun_header->flags != 0) {
    logmsg(ANDROID_LOG_WARN,"main/flags = %d", tun_header->flags);
  }

  if(tun_header->proto == ETH_P_IP) {
    ip_packet(tun_fd,packet,packetsize);
  } else if(tun_header->proto == ETH_P_IPV6) {
    ipv6_packet(tun_fd,packet,packetsize);
  } else {
    logmsg(ANDROID_LOG_WARN,"main/unknown packet type = %x",tun_header->proto);
  }
}

/* function: event_loop
 * reads packets from the tun network interface and passes them down the stack
 * tun_fd     - file descriptor for the tun network interface
 * tun_device - tun device interface name
 */
void event_loop(int tun_fd, const char *tun_device) {
  time_t last_interface_poll;
  size_t readlen;
  char packet[PACKETLEN];

  // start the poll timer
  last_interface_poll = time(NULL);

  while((readlen = read(tun_fd,packet,PACKETLEN)) > 0) {
    struct tun_pi tun_header;
    time_t now = time(NULL);
    size_t header_size = sizeof(struct tun_pi);

    if(readlen < header_size) {
      logmsg(ANDROID_LOG_WARN,"main/read short: got %ld bytes", readlen);
      continue;
    }

    memcpy(&tun_header, packet, header_size);

    packet_handler(tun_fd, &tun_header, packet+header_size, readlen-header_size);

    memset(packet, 0, PACKETLEN);

    if(last_interface_poll < (now - INTERFACE_ADDRESS_POLL_FREQUENCY)) {
      interface_poll(tun_device);
      last_interface_poll = now;
    }
  }
}

/* function: print_help
 * in case the user is running this on the command line
 */
void print_help() {
  printf("android-clat arguments:\n");
  printf("-i [uplink interface]\n");
  printf("-p [plat prefix]\n");
}

/* function: main
 * allocate and setup the tun device, then run the event loop
 */
int main(int argc, char **argv) {
  int tun_fd;
  char device[IFNAMSIZ] = DEVICENAME;
  int opt;
  char *uplink_interface = NULL, *plat_prefix = NULL;

  while((opt = getopt(argc, argv, "i:p:h")) != -1) {
    switch(opt) {
      case 'i':
        uplink_interface = optarg;
        break;
      case 'p':
        plat_prefix = optarg;
        break;
      case 'h':
      default:
        print_help();
        exit(1);
        break;
    }
  }

  if(uplink_interface == NULL) {
    printf("I need an interface\n");
    exit(1);
  }

  // open the tunnel device before dropping privs
  tun_fd = tun_open();
  if(tun_fd < 0) {
    logmsg(ANDROID_LOG_FATAL,"tun_open failed: %s",strerror(errno));
    exit(1);
  }

  // open the forwarding configuration before dropping privs
  forwarding_fd = open("/proc/sys/net/ipv6/conf/all/forwarding", O_RDWR);
  if(forwarding_fd < 0) {
    logmsg(ANDROID_LOG_FATAL,"open /proc/sys/net/ipv6/conf/all/forwarding failed: %s",strerror(errno));
    exit(1);
  }

  // forwarding slows down IPv6 config while transitioning to wifi
  set_accept_ra();

  // protect against forwarding being on when bringing up cell network
  // interface - RA is ignored when forwarding is on
  set_default_ipv6_route(uplink_interface);

  // run under a regular user
  drop_root();

  if(signal(SIGTERM, got_sigterm) == SIG_ERR) {
    logmsg(ANDROID_LOG_FATAL, "sigterm handler failed: %s", strerror(errno));
    exit(1);
  }

  configure_interface(uplink_interface, plat_prefix, tun_fd, device);

  set_forwarding(forwarding_fd,"1\n");

  event_loop(tun_fd,device); // event_loop returns if someone sets the tun interface down manually

  set_forwarding(forwarding_fd,"0\n");

  return 0;
}
