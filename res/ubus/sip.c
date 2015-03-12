/*
 * sip.c
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#include "sip.h"
#include <asterisk.h>
#include <asterisk/logger.h>

static const SIP_ACCOUNT sip_accounts[] = {
	{SIP_ACCOUNT_0,		"sip0"},
	{SIP_ACCOUNT_1,		"sip1"},
	{SIP_ACCOUNT_2,		"sip2"},
	{SIP_ACCOUNT_3,		"sip3"},
	{SIP_ACCOUNT_4,		"sip4"},
	{SIP_ACCOUNT_5,		"sip5"},
	{SIP_ACCOUNT_6,		"sip6"},
	{SIP_ACCOUNT_7,		"sip7"},
	{SIP_ACCOUNT_UNKNOWN,	"-"}
};

void sip_peer_init_all(SIP_PEER *sip_peers)
{
	const SIP_ACCOUNT *accounts;

	accounts = sip_accounts;
	for (;;) {
		sip_peers[accounts->id].account.id = accounts->id;
		strcpy(sip_peers[accounts->id].account.name, accounts->name);
		sip_peers[accounts->id].sip_registry_registered = 0;
		sip_peers[accounts->id].sip_registry_request_sent = 0;
		sip_peers[accounts->id].sip_registry_time = 0;
		sip_peers[accounts->id].ip_list_length = 0;

		/* Init sip show registry data */
		strcpy(sip_peers[accounts->id].username, "Unknown");
		strcpy(sip_peers[accounts->id].domain, "Unknown");
		strcpy(sip_peers[accounts->id].state, "Unknown");
		sip_peers[accounts->id].port = 0;
		sip_peers[accounts->id].domain_port = 0;
		sip_peers[accounts->id].refresh = 0;
		sip_peers[accounts->id].registration_time = 0;

		/* No need to (re)initialize ubus_object (created once at startup) */

		if (accounts->id == SIP_ACCOUNT_UNKNOWN) {
			break;
		}

		accounts++;
	}
}

/* Add IP to list for SIP peer */
void sip_peer_add_ip(SIP_PEER *peer, char *addr, int family) {
	int i;

	if (peer->ip_list_length >= SIP_MAX_IP_LIST_LENGTH) {
		ast_log(LOG_WARNING, "Could not add IP %s to peer %s, ip list is full\n", addr, peer->account.name);
		return;
	}

	for (i=0; i < peer->ip_list_length; i++) {
		IP ip = peer->ip_list[i];
		if (family == ip.family && strcmp(addr, ip.addr) == 0) {
			return;
		}
	}
	strcpy(peer->ip_list[peer->ip_list_length].addr, addr);
	peer->ip_list[peer->ip_list_length].family = family;
	peer->ip_list_length++;
}

void sip_peer_log_all(const SIP_PEER const *peers)
{
	while (peers->account.id != SIP_ACCOUNT_UNKNOWN) {
		ast_log(LOG_DEBUG, "sip_peer %d:\n", peers->account.id);
		ast_log(LOG_DEBUG, "\tname %s:\n", peers->account.name);
		ast_log(LOG_DEBUG, "\tsip_registry_request_sent: %d\n", peers->sip_registry_request_sent);
		ast_log(LOG_DEBUG, "\tsip_registry_registered: %d\n", peers->sip_registry_registered);
		ast_log(LOG_DEBUG, "\n");
		peers++;
	}
}

/* Create a set of all resolved IPs for all peers */
IP* sip_peer_ip_set_create(SIP_PEER *sip_peers, int family, int *ip_list_length)
{
	SIP_PEER *peer;
	IP *ip_list;

	*ip_list_length = 0;
	ip_list = (IP *) malloc(SIP_MAX_IP_LIST_LENGTH * sizeof(struct IP));

	/* This is O(n^3) but the lists are small... */
	peer = sip_peers;
	while (peer->account.id != SIP_ACCOUNT_UNKNOWN) {
		int i;
		for (i=0; i<peer->ip_list_length; i++) {
			int add = 1;
			int j;

			if (peer->ip_list[i].family != family) {
				continue;
			}

			for (j=0; j<*ip_list_length; j++) {
				if (ip_list[j].family == peer->ip_list[i].family &&
					strcmp(ip_list[j].addr, peer->ip_list[i].addr) == 0) {
					/* IP already in set */
					add = 0;
					break;
				}
			}

			if (add) {
				/* IP not found in set */
				strcpy(ip_list[*ip_list_length].addr, peer->ip_list[i].addr);
				ip_list[*ip_list_length].family = peer->ip_list[i].family;
				(*ip_list_length)++;
				if (*ip_list_length == SIP_MAX_IP_LIST_LENGTH) {
					/* ip_list is full */
					return ip_list;
				}
			}
		}
		peer++;
	}

	return ip_list;
}

/* Compare two IP sets */
int sip_peer_ip_set_compare(IP* ip_list1, int ip_list_length1, IP* ip_list2, int ip_list_length2)
{
	if (ip_list1 == NULL && ip_list2 == NULL) {
		return 0;
	}

	if (ip_list1 == NULL) {
		return -1;
	}

	if (ip_list2 == NULL) {
		return 1;
	}

	if (ip_list_length1 < ip_list_length2) {
		return -1;
	}

	if (ip_list_length2 < ip_list_length1) {
		return 1;
	}

	int i;
	for(i=0; i<ip_list_length1; i++) {
		int rv = strcmp(ip_list1[i].addr, ip_list2[i].addr);
		if (rv) {
			return rv;
		}
	}
	return 0;
}
