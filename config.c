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
 * config.c - configuration settings
 */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include <cutils/config_utils.h>

#include "config.h"
#include "dns64.h"
#include "logging.h"
#include "getaddr.h"
#include "nat64d.h"
#include "setroute.h"

struct clat_config config;

/* function: config_item_str
 * locates the config item and returns the pointer to a string, or NULL on failure.  Caller frees pointer
 * root       - parsed configuration
 * item_name  - name of config item to locate
 * defaultvar - value to use if config item isn't present
 */
char *config_item_str(cnode *root, const char *item_name, const char *defaultvar) {
  const char *tmp;

  if(!(tmp = config_str(root, item_name, defaultvar))) {
    logmsg(ANDROID_LOG_FATAL,"%s config item needed",item_name);
    return NULL;
  }
  return strdup(tmp);
}

/* function: config_item_long
 * locates the config item and returns the pointer to a long int, or NULL on failure.  Caller frees pointer
 * root       - parsed configuration
 * item_name  - name of config item to locate
 * defaultvar - value to use if config item isn't present
 */
long int *config_item_long(cnode *root, const char *item_name, const char *defaultvar) {
  const char *tmp;
  char *endptr;
  long int *conf_int;

  conf_int = malloc(sizeof(long int));
  if(!conf_int) {
    logmsg(ANDROID_LOG_FATAL,"out of memory");
    return NULL;
  }

  if(!(tmp = config_str(root, item_name, defaultvar))) {
    logmsg(ANDROID_LOG_FATAL,"%s config item needed",item_name);
    free(conf_int);
    return NULL;
  }
  *conf_int = strtol(tmp,&endptr,10);
  if(
      ((*conf_int == LONG_MIN || *conf_int == LONG_MAX) && (errno > 0))
      || (*conf_int == 0 && errno > 0)
      ) {
    perror("strtol");
    free(conf_int);
    return NULL;
  }
  if(endptr == tmp || *tmp == '\0') {
    logmsg(ANDROID_LOG_FATAL,"%s config item is not numeric: %s",item_name,tmp);
    free(conf_int);
    return NULL;
  }
  if(*endptr != '\0') {
    logmsg(ANDROID_LOG_FATAL,"%s config item contains non-numeric characters: %s",item_name,endptr);
    free(conf_int);
    return NULL;
  }
  return conf_int;
}

/* function: config_item_ip
 * locates the config item and returns the pointer to a parsed ip address, or NULL on failure.  Caller frees pointer
 * root       - parsed configuration
 * item_name  - name of config item to locate
 * defaultvar - value to use if config item isn't present
 */
struct in_addr *config_item_ip(cnode *root, const char *item_name, const char *defaultvar) {
  const char *tmp;
  struct in_addr *retval;
  int status;

  retval = malloc(sizeof(struct in_addr));
  if(!retval) {
    logmsg(ANDROID_LOG_FATAL,"out of memory");
    return NULL;
  }

  if(!(tmp = config_str(root, item_name, defaultvar))) {
    logmsg(ANDROID_LOG_FATAL,"%s config item needed",item_name);
    free(retval);
    return NULL;
  }

  status = inet_pton(AF_INET, tmp, retval);
  if(status <= 0) {
    logmsg(ANDROID_LOG_FATAL,"invalid IPv4 address specified for %s: %s", item_name, tmp);
    free(retval);
    return NULL;
  }

  return retval;
}

/* function: config_item_ip6
 * locates the config item and returns the pointer to a parsed ipv6 address, or NULL on failure.  Caller frees pointer
 * root       - parsed configuration
 * item_name  - name of config item to locate
 * defaultvar - value to use if config item isn't present
 */
struct in6_addr *config_item_ip6(cnode *root, const char *item_name, const char *defaultvar) {
  const char *tmp;
  struct in6_addr *retval;
  int status;

  retval = malloc(sizeof(struct in6_addr));
  if(!retval) {
    logmsg(ANDROID_LOG_FATAL,"out of memory");
    return NULL;
  }

  if(!(tmp = config_str(root, item_name, defaultvar))) {
    logmsg(ANDROID_LOG_FATAL,"%s config item needed",item_name);
    free(retval);
    return NULL;
  }

  status = inet_pton(AF_INET6, tmp, retval);
  if(status <= 0) {
    logmsg(ANDROID_LOG_FATAL,"invalid IPv6 address specified for %s: %s", item_name, tmp);
    free(retval);
    return NULL;
  }

  return retval;
}

/* function: free_config
 * frees the memory used by the global config variable
 */
void free_config() {
  if(config.plat_from_dns64_hostname) {
    free(config.plat_from_dns64_hostname);
    config.plat_from_dns64_hostname = NULL;
  }
}

/* function: dns64_detection
 * does dns lookups to set the plat subnet or exits on failure
 */
void dns64_detection() {
  int i, backoff_sleep, status;
  struct in6_addr tmp_ptr;

  backoff_sleep = 1;

  while(1) {
    status = plat_prefix(config.plat_from_dns64_hostname,&tmp_ptr);
    if(status > 0) {
      memcpy(&config.plat_subnet, &tmp_ptr, sizeof(struct in6_addr));
      return;
    }
    if(status < 0) {
      logmsg(ANDROID_LOG_FATAL, "dns64_detection/no dns64, giving up\n");
      exit(1);
    }
    logmsg(ANDROID_LOG_WARN, "dns64_detection failed, sleeping for %d seconds", backoff_sleep);
    sleep(backoff_sleep);
    if(backoff_sleep >= 120) {
      backoff_sleep = 120;
    } else {
      backoff_sleep *= 2;
    }
  }
}


/* function: config_generate_local_ipv6_subnet
 * generates the local ipv6 subnet when given the interface ip
 * requires config.ipv6_host_id
 * interface_ip - in: interface ip, out: local ipv6 host address
 */
void config_generate_local_ipv6_subnet(struct in6_addr *interface_ip) {
  int i;

  for(i = 2; i < 4; i++) {
    interface_ip->s6_addr32[i] = config.ipv6_host_id.s6_addr32[i];
  }
}

/* function: subnet_from_interface
 * finds the ipv6 subnet configured on the specified interface
 * root      - parsed configuration
 * interface - network interface name
 */
int subnet_from_interface(cnode *root, const char *interface) {
  union anyip *interface_ip;
  struct in6_addr *host_id;

  if(!(host_id = config_item_ip6(root, "ipv6_host_id", "::200:5E10:0:0"))) {
    return 0;
  }
  memcpy(&config.ipv6_host_id, host_id, sizeof(struct in6_addr));
  free(host_id);
  host_id = NULL;

  interface_ip = getinterface_ip(interface, AF_INET6);
  if(!interface_ip) {
    logmsg(ANDROID_LOG_FATAL,"unable to find an ipv6 ip on interface %s",interface);
    return 0;
  }

  memcpy(&config.ipv6_local_subnet, &interface_ip->ip6, sizeof(struct in6_addr));
  free(interface_ip);

  config_generate_local_ipv6_subnet(&config.ipv6_local_subnet);

  return 1;
}

/* function: read_config
 * reads the config file and parses it into the global variable config. returns 0 on failure, 1 on success
 * file - filename to parse
 */
int read_config(const char *file) {
  cnode *root = config_node("", "");
  long int *tmp_int = NULL;
  void *tmp_ptr = NULL;

  if(!root) {
    logmsg(ANDROID_LOG_FATAL,"out of memory");
    return 0;
  }

  memset(&config, '\0', sizeof(config));

  config_load_file(root, file);
  if(root->first_child == NULL) {
    logmsg(ANDROID_LOG_FATAL,"Could not read config file %s", file);
    goto failed;
  }

  if(!__system_property_get("gsm.defaultpdpcontext.interface",config.default_pdp_interface)) {
    logmsg(ANDROID_LOG_FATAL,"property gsm.defaultpdpcontext.interface not set");
    goto failed;
  }

  // protect against forwarding being on when bringing up cell network
  // interface - RA is ignored when forwarding is on
  set_default_ipv6_route(config.default_pdp_interface);

  if(!(tmp_int = config_item_long(root, "mtu", "-1")))
    goto failed;
  config.mtu = *tmp_int;
  free(tmp_int);

  if(config.mtu > MAXMTU) {
    logmsg(ANDROID_LOG_FATAL,"Max MTU is %d", MAXMTU);
    config.mtu = MAXMTU;
  }

  if(!(tmp_int = config_item_long(root, "ipv4mtu", "-1")))
    goto failed;
  config.ipv4mtu = *tmp_int;
  free(tmp_int);

  if(!subnet_from_interface(root,config.default_pdp_interface))
    goto failed;

  if(!(tmp_ptr = config_item_ip(root, "ipv4_local_subnet", "192.168.255.1")))
    goto failed;
  memcpy(&config.ipv4_local_subnet, tmp_ptr, sizeof(struct in_addr));
  free(tmp_ptr);

  tmp_ptr = (void *)config_str(root, "plat_from_dns64", "yes");
  if(!tmp_ptr || strcmp(tmp_ptr, "no") == 0) {
    if(!(tmp_ptr = config_item_ip6(root, "plat_subnet", NULL)))
      goto failed;
    memcpy(&config.plat_subnet, tmp_ptr, sizeof(struct in6_addr));
    free(tmp_ptr);
  } else {
    if(!config.plat_from_dns64_hostname = config_str(root, "plat_from_dns64_hostname", "ipv4.google.com"))
      goto failed;
    dns64_detection();
  }

  return 1;

failed:
  free(root);
  free_config();
  return 0;
}

/* function; dump_config
 * prints the current config
 */
void dump_config() {
  char charbuffer[INET6_ADDRSTRLEN];

  logmsg(ANDROID_LOG_DEBUG,"mtu = %d",config.mtu);
  logmsg(ANDROID_LOG_DEBUG,"ipv4mtu = %d",config.ipv4mtu);
  logmsg(ANDROID_LOG_DEBUG,"ipv6_local_subnet = %s",inet_ntop(AF_INET6, &config.ipv6_local_subnet, charbuffer, sizeof(charbuffer)));
  logmsg(ANDROID_LOG_DEBUG,"ipv4_local_subnet = %s",inet_ntop(AF_INET, &config.ipv4_local_subnet, charbuffer, sizeof(charbuffer)));
  logmsg(ANDROID_LOG_DEBUG,"plat_subnet = %s",inet_ntop(AF_INET6, &config.plat_subnet, charbuffer, sizeof(charbuffer)));
  logmsg(ANDROID_LOG_DEBUG,"default_pdp_interface = %s",config.default_pdp_interface);
}
