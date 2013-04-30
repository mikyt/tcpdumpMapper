#include<stdint.h>
#include<glib.h>
#include<stdio.h>

#ifndef TCPDUMP_MAPPER_H
#define TCPDUMP_MAPPER_H

#define true TRUE
#define false TRUE

typedef struct {
  uint8_t octet1;
  uint8_t octet2;
  uint8_t octet3;
  uint8_t octet4;
} ip_t;

typedef struct {
  ip_t ip;
  unsigned short port;
} socket_t;

typedef enum {
  aarp,
  ARP,
  AT,
  CDPv2,
  IP,
  IP6,
  LLDP,
  NBF,
  STP
} protocol_t;
  
typedef struct {
  FILE* outfile;
  ip_t* src_ip;
} to_print_t;

void ip_init(ip_t* ip);
int8_t ip_isEqual(ip_t a, ip_t b);


socket_t* socket_new();

void init_ip_hashtable(GHashTable** known_IPs);

gint list_socket_ip_compare(gconstpointer a, gconstpointer b);

void output_network_topology(GHashTable* known_IPs, const char* filename);

#endif