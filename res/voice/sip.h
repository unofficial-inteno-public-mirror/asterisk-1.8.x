/*
 * sip.h
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#ifndef SIP_H_
#define SIP_H_

#include "ip.h"
#include <sys/types.h>

typedef enum SIP_ACCOUNT_ID
{
	SIP_ACCOUNT_0 = 0,
	SIP_ACCOUNT_1,
	SIP_ACCOUNT_2,
	SIP_ACCOUNT_3,
	SIP_ACCOUNT_4,
	SIP_ACCOUNT_5,
	SIP_ACCOUNT_6,
	SIP_ACCOUNT_7,
	SIP_ACCOUNT_UNKNOWN
} SIP_ACCOUNT_ID;

#define SIP_MAX_ACCOUNT_NAME	10
typedef struct SIP_ACCOUNT
{
	SIP_ACCOUNT_ID id;
	char name[SIP_MAX_ACCOUNT_NAME];
} SIP_ACCOUNT;

#define SIP_MAX_PEERS 10
#define SIP_MAX_PEER_NAME 10
#define SIP_MAX_PEER_USERNAME 128
#define SIP_MAX_PEER_DOMAIN 128
#define SIP_MAX_PEER_STATE 128
#define	SIP_MAX_IP_LIST_LENGTH	20
typedef struct SIP_PEER
{
	SIP_ACCOUNT	account;
	int		sip_registry_request_sent;		//Bool indicating if we have sent a registration request
	int		sip_registry_registered;		//Bool indicating if we are registered or not
	time_t	sip_registry_time;				//The time when we received the registry event
	IP		ip_list[SIP_MAX_IP_LIST_LENGTH];//IP addresses of the sip registrar
	int		ip_list_length;					//Number of addresses

	//Info from sip show registry
	int port;								//The port we are connected to
	char username[SIP_MAX_PEER_USERNAME];	//Our username
	char domain[SIP_MAX_PEER_DOMAIN];		//The domain we are registered on
	int domain_port;						//The domain port
	int refresh;							//Refresh interval for this registration
	char state[SIP_MAX_PEER_STATE];			//Registration state e.g. Registered
	time_t registration_time;				//Registration timestamp, 1401282865

	struct ubus_object *ubus_object;
} SIP_PEER;

void sip_peer_init_all(SIP_PEER *sip_peers);
void sip_peer_add_ip(SIP_PEER *peer, char *addr, int family);
void sip_peer_log_all(const SIP_PEER const *sip_peers);
IP* sip_peer_ip_set_create(SIP_PEER *sip_peers, int family, int *ip_list_length);
int sip_peer_ip_set_compare(IP* ip_list1, int ip_list_length1, IP* ip_list2, int ip_list_length2);

#endif /* SIP_H_ */
