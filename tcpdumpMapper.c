#include<tcpdumpMapper.h>
#include<stdlib.h>
#include<glib.h>
#include<alloca.h>
#include<time.h>
#include<string.h>
void error(unsigned int line_number, char *msg) {
  fprintf(stderr, "Line %d - Error: %s\n", line_number, msg);
  abort();
}

void subnet_by_octect_to_color(char* buf, int8_t classA, int8_t classB, int8_t classC) {
  sprintf(buf, "#%2hhX%2hhX%2hhX", 255-classA, 255-classB, 255-classC);
}

void ip_to_color(ip_t ip, char *buf) {
  subnet_by_octect_to_color(buf, ip.octet1, ip.octet2, ip.octet3);
}

int32_t ip_to_hex(ip_t ip) {
  return ip.octet1 + ip.octet2*256 + ip.octet3*256*256 + ip.octet4*256*256*256;
}

int8_t ip_isEqual(ip_t a, ip_t b) {
  if(a.octet1==b.octet1 && a.octet2==b.octet2 && a.octet3==b.octet3 && a.octet4==b.octet4)
    return TRUE;
  
  return FALSE;
}

int8_t ip_by_octect_is_broadcast(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  if(d==255)
    return TRUE;
  
  return FALSE;
}

int8_t ip_is_broadcast(ip_t ip) {
  return ip_by_octect_is_broadcast(ip.octet1, ip.octet2, ip.octet3, ip.octet4);
}

void ip_init(ip_t* ip) {
  ip->octet1=0;
  ip->octet2=0;
  ip->octet3=0;
  ip->octet4=0;
}

void ip_to_string(ip_t ip, char *dest_buf) {
  sprintf(dest_buf,"%u.%u.%u.%u", ip.octet1, ip.octet2, ip.octet3, ip.octet4);
}

int8_t socket_is_equal(socket_t a, socket_t b) {
  if(ip_isEqual(a.ip, b.ip) && a.port==b.port)
    return TRUE;
  
  return FALSE;
}

socket_t* socket_new() {
  socket_t* socket=malloc(sizeof(socket_t));
  
  ip_init(&(socket->ip));
  socket->port=0;
  return socket;
}

/* The hash is the ip written in hex format */
guint hash_ip_hashfunc(gconstpointer key) {
  const ip_t* ip=key;
  
  return ip_to_hex(*ip);
}

gboolean hash_ip_isEqual(gconstpointer a, gconstpointer b){
  return ip_isEqual(*((ip_t*) a), *((ip_t*) b));
}

gint list_socket_ip_compare(gconstpointer a, gconstpointer b){
  gint res=ip_to_hex(((socket_t*)a)->ip)- ip_to_hex(((socket_t*) b)->ip);
  return res;
}

void init_ip_hashtable(GHashTable** known_IPs) {
  *known_IPs=g_hash_table_new(hash_ip_hashfunc, hash_ip_isEqual);
}


void print_network_link(gpointer data, gpointer user_data) {
  socket_t* dst_socket = data;
  to_print_t* to_print = user_data;
  
  char *src_ip_txt;
  char *dst_ip_txt;
  char attribute_buf[1024]="";
  char color_buf[8]="";
  
  src_ip_txt = alloca(3*4 + 3 + 1);
  dst_ip_txt = alloca(3*4 + 3 + 1);
  
  ip_to_string(*(to_print->src_ip), src_ip_txt);
  ip_to_string(dst_socket->ip, dst_ip_txt);

  
  
  if(ip_is_broadcast(dst_socket->ip)) {
    sprintf(color_buf, "white");
  }
  else {
    ip_to_color(dst_socket->ip, color_buf);
  }
  
  sprintf(attribute_buf, "[color=\"%s\"]", color_buf);
  
  fprintf(to_print->outfile, "  \"%s\" -> \"%s\" %s\n", src_ip_txt, dst_ip_txt, attribute_buf);
}

void print_topology_for_ip(gpointer key, gpointer value, gpointer user_data) {
  ip_t* src_ip = key;
  GList* destinations_list = value;
  FILE* outfile=user_data;
  
  to_print_t to_print;
  
  to_print.outfile=outfile;
  to_print.src_ip=src_ip;
  
  g_list_foreach(destinations_list, print_network_link, &to_print);
  
}



void put_ip_in_nework_tree(GNode* theInternet, ip_t ip) {
  GNode* classA;
  GNode* classB;
  GNode* classC;
  GNode* classD;
  
  classA = g_node_find_child(theInternet, G_TRAVERSE_ALL, GUINT_TO_POINTER(ip.octet1));
  if(classA==NULL) {
    /* No node for this A class. Create one */
    classA = g_node_append_data(theInternet, GUINT_TO_POINTER(ip.octet1));
  }
  
  classB = g_node_find_child(classA, G_TRAVERSE_ALL, GUINT_TO_POINTER(ip.octet2));
  if(classB==NULL) {
    /* No node for this B class. Create one */
    classB = g_node_append_data(classA, GUINT_TO_POINTER(ip.octet2));
  }
  
  classC = g_node_find_child(classB, G_TRAVERSE_ALL, GUINT_TO_POINTER(ip.octet3));
  if(classC==NULL) {
    /* No node for this C class. Create one */
    classC = g_node_append_data(classB, GUINT_TO_POINTER(ip.octet3));
  }
  
  classD = g_node_find_child(classC, G_TRAVERSE_ALL, GUINT_TO_POINTER(ip.octet4));
  if(classD==NULL) {
    /* No node for this D class. Create one */
    classD = g_node_append_data(classC, GUINT_TO_POINTER(ip.octet4));
  }
}


void compute_network_ip_tree_foreach_destination(gpointer data, gpointer user_data) {
  socket_t* dst_socket = data;
  GNode* theInternet = user_data;
  
  put_ip_in_nework_tree(theInternet, dst_socket->ip);
}


void compute_network_ip_tree_foreach_source(gpointer key, gpointer value, gpointer user_data) {
  ip_t* src_ip = key;
  GList* destinations_list = value;
  GNode* theInternet = user_data;
  
  put_ip_in_nework_tree(theInternet, *src_ip);
  
  g_list_foreach(destinations_list, compute_network_ip_tree_foreach_destination, theInternet);
}

GNode* compute_network_ip_tree(GHashTable* known_IPs) {
  GNode* theInternet = g_node_new("TheInternet");
  
  g_hash_table_foreach(known_IPs, compute_network_ip_tree_foreach_source, theInternet);
  
  return theInternet;
}

void print_network_ip_tree_classD(GNode *classD, gpointer user_data) {
  uint8_t classA_octet = GPOINTER_TO_INT(classD->parent->parent->parent->data);
  uint8_t classB_octet = GPOINTER_TO_INT(classD->parent->parent->data);
  uint8_t classC_octet = GPOINTER_TO_INT(classD->parent->data);
  uint8_t classD_octet = GPOINTER_TO_INT(classD->data);
  FILE* outfile = user_data;
  char attribute_buf[1024]="";
  char color_buf[8]="";
  
  subnet_by_octect_to_color(color_buf, classA_octet, classB_octet, classC_octet);
  sprintf(attribute_buf, "[style=filled,fillcolor=\"%s\"]", color_buf);
  
  if(ip_by_octect_is_broadcast(classA_octet, classB_octet, classC_octet, classD_octet)) {
    /* Note: this will completely override the color as defined above! */
    sprintf(attribute_buf, "[style=filled,fillcolor=lightgray]");
  }
  
  fprintf(outfile, "\"%u.%u.%u.%u\" %s;\n", classA_octet, classB_octet, classC_octet, classD_octet, attribute_buf);
}

void print_network_ip_tree_classC(GNode *classC, gpointer user_data) {
  uint8_t classA_octet = GPOINTER_TO_INT(classC->parent->parent->data);
  uint8_t classB_octet = GPOINTER_TO_INT(classC->parent->data);
  uint8_t classC_octet = GPOINTER_TO_INT(classC->data);
  FILE* outfile = user_data;
  
  fprintf(outfile, "subgraph cluster_%u_%u_%u {\n", classA_octet, classB_octet, classC_octet);
  fprintf(outfile, "label=\"%u.%u.%u.0\"\n", classA_octet, classB_octet, classC_octet);
  
  g_node_children_foreach(classC, G_TRAVERSE_ALL, print_network_ip_tree_classD, outfile);
  
  fprintf(outfile, "}\n");
}

void print_network_ip_tree_classB(GNode *classB, gpointer user_data) {
  uint8_t classA_octet = GPOINTER_TO_INT(classB->parent->data);
  uint8_t classB_octet = GPOINTER_TO_INT(classB->data);
  FILE* outfile = user_data;
  
  fprintf(outfile, "subgraph cluster_%u_%u {\n", classA_octet, classB_octet);
  fprintf(outfile, "label=\"%u.%u.0.0\"\n", classA_octet, classB_octet);
  
  g_node_children_foreach(classB, G_TRAVERSE_ALL, print_network_ip_tree_classC, outfile);
  
  fprintf(outfile, "}\n");
}

void print_network_ip_tree_classA(GNode *classA, gpointer user_data) {
  uint8_t classA_octet = GPOINTER_TO_INT(classA->data);
  FILE* outfile = user_data;
  
  fprintf(outfile, "subgraph cluster_%u {\n", classA_octet);
  fprintf(outfile, "label=\"%u.0.0.0\"\n", classA_octet);
  g_node_children_foreach(classA, G_TRAVERSE_ALL, print_network_ip_tree_classB, outfile);
  
  fprintf(outfile, "}\n");
}

void print_network_ip_tree(GNode* theInternet, FILE *outfile) {
  g_node_children_foreach(theInternet, G_TRAVERSE_ALL, print_network_ip_tree_classA, outfile);
}



void output_network_ip_tree(GHashTable* known_IPs, FILE* outfile) {
  GNode* theInternet = compute_network_ip_tree(known_IPs);
  print_network_ip_tree(theInternet, outfile);
  g_node_destroy(theInternet);
}

void output_network_topology(GHashTable* known_IPs, const char* filename){
  FILE* outfile;
  char buf[26];
  
  outfile = fopen(filename, "w");
  if(outfile == NULL) {
    fprintf(stderr, "Unable to open the output file: %s\n", filename);
    abort();
  }
  
  /* Output dot header */
  fprintf(outfile, "digraph network_topology {\n");
  
  /* Output subnet structure */
  output_network_ip_tree(known_IPs, outfile);
  
  /* Output the links between IPs */
  g_hash_table_foreach(known_IPs, print_topology_for_ip, outfile);
  
  /* Output dot footer */
  fprintf(outfile, "}\n");
  
  fclose(outfile);
  
  /* Inform the user that a new topology is ready */
  time_t t = time(NULL);
  ctime_r(&t, buf);
  buf[strlen(buf)-1]='\0';
  fprintf(stderr, "%s: New network topology\n", buf);
  
}

