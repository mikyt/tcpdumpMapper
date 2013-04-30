/* Scanner for "tcpdump -n" */
%option noyywrap
%{

#include<tcpdumpMapper.h>
#include<assert.h>
  socket_t* current_socket;
  socket_t* src_socket;
  socket_t* dst_socket;

  protocol_t current_protocol;

  GHashTable* known_ips;

  int8_t network_modified;
%}

%s PROTOCOL
%s IP_ADDR
%s IP_ADDR2
%s IP_ADDR3
%s IP_ADDR4
%s IP_ADDR_PORT
%s IGNORE_MAC_LINE
%s IGNORE_USELESS_LINE
%s HEXDUMP
%s END_OF_INTEREST

DIGIT [0-9]
NUMBER {DIGIT}+
OCTET [0-2]?{NUMBER}{1,2}
HOUR [0-2]?{DIGIT}
MINUTE [0-5]?{DIGIT}

DOT 	"."
TO	">"
COLON	":"
WHITESPACE [ \t\f\v]+

%%
"tcpdump:" {BEGIN(END_OF_INTEREST);}
"listening on" {BEGIN(END_OF_INTEREST);}
{HOUR}":"{MINUTE}":"{MINUTE}{DOT}{NUMBER}		{ /* New log line. Initialization*/
                                              src_socket=NULL;
                                              dst_socket=NULL;
                                             /*TODO: really parse timestamp */
                                              BEGIN(PROTOCOL);
                                            }
"0x"{NUMBER}       { BEGIN(IGNORE_USELESS_LINE); }
"["                { /* Very unusual start of lines with no useful info */
                     BEGIN(IGNORE_USELESS_LINE);
                   }

<PROTOCOL>"ARP"   { current_protocol=ARP;
          //TODO: implement!! It can be really useful
          BEGIN(END_OF_INTEREST);
        }
<PROTOCOL>"AT"    { current_protocol=AT;
                    src_socket = current_socket = socket_new();
                    BEGIN(IP_ADDR);
                  }
<PROTOCOL>"CDPv2" { current_protocol=CDPv2;
                    BEGIN(END_OF_INTEREST);
                  }
<PROTOCOL>"IP"	  { current_protocol = IP;
                    src_socket = current_socket = socket_new();
                    BEGIN(IP_ADDR); 
                  }
<PROTOCOL>"IP6"   { current_protocol = IP6;
                    BEGIN(END_OF_INTEREST);
                  }
<PROTOCOL>"LLDP"  { current_protocol = LLDP;
                    BEGIN(END_OF_INTEREST);
                  }
<PROTOCOL>"NBF"   { current_protocol=NBF;
                    BEGIN(END_OF_INTEREST);
                  }
<PROTOCOL>"STP"	  { current_protocol=STP;
                    BEGIN(END_OF_INTEREST);
                  }
<PROTOCOL>"aarp"  { current_protocol=aarp;
                    BEGIN(END_OF_INTEREST);
                  }
<PROTOCOL>{NUMBER}":" {  /* maybe MAC address? */
                        BEGIN(IGNORE_MAC_LINE);
                      }
<PROTOCOL>"\n"        { /* Some lines contain just the timestamp
                         * This is weird...
                         * Just ignore them */ 
                         BEGIN(INITIAL);
                      }

<IGNORE_MAC_LINE>.*"\n"   { BEGIN(HEXDUMP); }

<IGNORE_USELESS_LINE>.*"\n"   { BEGIN(INITIAL); }

<IP_ADDR>{OCTET}	{current_socket->ip.octet1= atoi(yytext);}
<IP_ADDR>{DOT}		{BEGIN(IP_ADDR2);}

<IP_ADDR2>{OCTET}	{current_socket->ip.octet2= atoi(yytext);}
<IP_ADDR2>{DOT}		{BEGIN(IP_ADDR3);}

<IP_ADDR3>{OCTET}	{current_socket->ip.octet3= atoi(yytext);}
<IP_ADDR3>{DOT}		{BEGIN(IP_ADDR4);}

<IP_ADDR4>{OCTET}	{current_socket->ip.octet4= atoi(yytext);}
<IP_ADDR4>{DOT}		{BEGIN(IP_ADDR_PORT);}

<IP_ADDR4>{TO}		{ /* IP address without port */
                    if(current_protocol==IP) {
                      dst_socket = current_socket = socket_new();
                      BEGIN(IP_ADDR);
                    }
                    if(current_protocol==AT) {
                      BEGIN(END_OF_INTEREST);
                    }
                    
                  }

<IP_ADDR4>{COLON}	{BEGIN(END_OF_INTEREST);}

<IP_ADDR_PORT>{NUMBER}		{current_socket->port=atoi(yytext);}

<IP_ADDR_PORT>{TO}		{dst_socket = current_socket = socket_new();
				 BEGIN(IP_ADDR);}

<IP_ADDR_PORT>{COLON}		{BEGIN(END_OF_INTEREST);}

<END_OF_INTEREST>.*"\n"		{ /* No more parsing for this entry: use acquired data */
                            network_modified=FALSE;
                            if(src_socket != NULL && dst_socket!=NULL) { //TODO: handle other cases!! This is IP only!
                              GList* destinations_list=NULL;

                              destinations_list=g_hash_table_lookup(known_ips, &(src_socket->ip));
                              
                              if(destinations_list == NULL) {
                                /* No source ip in the hashtable: add it, and the destination */
                                destinations_list = g_list_prepend(destinations_list, dst_socket);
                                assert(&(src_socket->ip) != NULL);
                                g_hash_table_insert(known_ips, &(src_socket->ip), destinations_list);
                                network_modified=TRUE;
                              }
                              else {
                                /* Source ip is in the hash table: what about destination socket? */
                                //Add based on destination address only or on port too
                                //GList* dest_socket_in_list = g_list_find_custom(destinations_list, dst_socket, list_socket_compare);
                                GList* dest_socket_in_list = g_list_find_custom(destinations_list, dst_socket, list_socket_ip_compare);
                                
                                if(!dest_socket_in_list){
                                  /* New destination socket found! Add it to the list */
                                  destinations_list = g_list_prepend(destinations_list, dst_socket);
                                  g_hash_table_insert(known_ips, &(src_socket->ip), destinations_list);
                                  network_modified=TRUE;
                                }
                              }
                              
                              if(network_modified)
                                output_network_topology(known_ips, "network_topology.dot");
                            }
                            BEGIN(INITIAL);
                          }

{WHITESPACE}	{}

 /* .		{error(__LINE__, yytext);} */
%%

int main (int argc, char* argv[]) {

  init_ip_hashtable(&known_ips);

	return yylex();
}

