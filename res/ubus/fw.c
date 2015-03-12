/*
 * fw.c
 *
 *  Dynamic firewall functions
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#include "fw.h"
#include "sip.h"
#include "ip.h"
#include "list.h"
#include "uci.h"
#include "ucix.h"

#include <asterisk.h>
#include <asterisk/logger.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>

#define IPTABLES_CHAIN "zone_wan_input"
#define IPTABLES_BIN "iptables"
#define IPTABLES_FILE "/etc/firewall.sip"
#ifdef USE_IPV6
#define IP6TABLES_BIN "ip6tables"
#define IP6TABLES_FILE "/etc/firewall6.sip"
#endif
#define BUFLEN 512
#define ECHO_BIN "echo"

#define RTP_RANGE_START_DEFAULT	10000
#define RTP_RANGE_END_DEFAULT	20000

static int resolv(SIP_PEER *peer, const char *domain);
static void write_firewall(struct fw *fw, SIP_PEER *peer, int family);

struct fw
{
	int rtpstart;
	int rtpend;
	IP* ip_list;
	int ip_list_length;
};

/* Create firewall structure */
struct fw* fw_create()
{
	struct fw* fw = malloc(sizeof(struct fw));
	memset(fw, 0, sizeof(struct fw));

	return fw;
}

/* Resolv host and add IPs to iptables */
int fw_manage(struct fw* fw, SIP_PEER *peer, int doResolv)
{
	/* Clear old IP list */
	peer->ip_list_length = 0;

	if (doResolv) {
		/* Get domain to resolv */
		const char* domain = uci_get_peer_domain(peer);
		if (domain) {
			resolv(peer, domain);
		}
		else {
			ast_log(LOG_WARNING, "Failed to get sip domain\n");
			return 1;
		}

		const char* host = uci_get_peer_host(peer);
		if (host) {
			resolv(peer, host);
		}

		/* Get sip proxies and resolv if configured */
		struct ucilist proxies;
		INIT_LIST_HEAD(&proxies.list);
		if (!uci_get_sip_proxy(&proxies.list)) {
			struct list_head *i;
			struct list_head *tmp;
			list_for_each_safe(i, tmp, &proxies.list)
			{
				struct ucilist *proxy = list_entry(i, struct ucilist, list);
				resolv(peer, proxy->val);
				free(proxy->val);
				free(proxy);
			}
		}
	}

	/* Write new config to firewall.sip and reload firewall */
	write_firewall(fw, peer, AF_INET);
#ifdef USE_IPV6
	write_firewall(fw, peer, AF_INET6);
#endif

	return 0;
}

void write_firewall(struct fw *fw, SIP_PEER *peer, int family)
{
	char *tables_file;
	char *iptables_bin;
	char buf[BUFLEN];
	int ip_list_length;
	IP* ip_list;

	/* Is there a change in IP or RTP port range? */
	ip_list = sip_peer_ip_set_create(peer, family, &ip_list_length);
	int rtpstart = uci_get_rtp_port_start();
	if (rtpstart <= 0) {
		rtpstart = RTP_RANGE_START_DEFAULT;
	}
	int rtpend = uci_get_rtp_port_end();
	if (rtpend <= 0) {
		rtpend = RTP_RANGE_END_DEFAULT;
	}

	if (sip_peer_ip_set_compare(fw->ip_list, fw->ip_list_length, ip_list, ip_list_length) == 0 &&
			fw->rtpstart == rtpstart &&	fw->rtpend == rtpend) {
		ast_log(LOG_DEBUG, "No changes in IP or RTP port range\n");
		free(ip_list);
		return;
	}

	/* Clear old firewall settings, write timestamp */
	time_t rawtime;
	struct tm * timeinfo;
	char timebuf[BUFLEN];
	time(&rawtime);
	timeinfo = (struct tm*) localtime(&rawtime);
	strftime(timebuf, BUFLEN, "%Y-%m-%d %H:%M:%S", timeinfo);

	tables_file = IPTABLES_FILE;
	iptables_bin = IPTABLES_BIN;
#ifdef USE_IPV6
	if (family == AF_INET6) {
		iptables_bin = IP6TABLES_BIN;
		tables_file = IP6TABLES_FILE;
	}
#endif
	snprintf((char *)&buf, BUFLEN, "%s \"# Created by %s %s\" > %s",
		ECHO_BIN,
		__FILE__,
		timebuf,
		tables_file);
	ast_log(LOG_DEBUG, "%s\n", buf);
	system(buf);

	/* Create an iptables rule for each IP in set */
	int i;
	for (i=0; i<ip_list_length; i++) {
		snprintf((char *)&buf, BUFLEN, "%s \"%s -I %s -s %s -j ACCEPT\" >> %s",
			ECHO_BIN,
			iptables_bin,
			IPTABLES_CHAIN,
			ip_list[i].addr,
			tables_file);
		ast_log(LOG_DEBUG, "%s\n", buf);
		system(buf);
	}
	if (ip_list) {
		free(ip_list);
	}
	fw->ip_list = ip_list;
	fw->ip_list_length = ip_list_length;

	/* Open up for RTP traffic */
	snprintf((char *)&buf, BUFLEN, "%s \"%s -I %s -p udp --dport %d:%d -j ACCEPT\" >> %s",
		ECHO_BIN,
		iptables_bin,
		IPTABLES_CHAIN,
		rtpstart,
		rtpend,
		tables_file);
	ast_log(LOG_DEBUG, "%s\n", buf);
	system(buf);
	fw->rtpstart = rtpstart;
	fw->rtpend = rtpend;

	snprintf((char *)&buf, BUFLEN, "/etc/init.d/firewall reload");
	ast_log(LOG_DEBUG, "%s\n", buf);
	system(buf);
}

/* Resolv name into ip (A or AAA record), update IP list for peer */
int resolv(SIP_PEER *peer, const char *domain)
{
	struct addrinfo *result;
	struct addrinfo *res;
	int error;

	/* Resolve the domain name into a list of addresses, don't specify any services */
	error = getaddrinfo(domain, NULL, NULL, &result);
	if (error != 0)
	{
		ast_log(LOG_WARNING, "error in getaddrinfo: %s\n", gai_strerror(error));
		return 1;
	}

	/* Loop over all returned results and convert IP from network to textual form */
	for (res = result; res != NULL; res = res->ai_next)
	{
		char ip_addr[NI_MAXHOST];
		void *in_addr;
		switch (res->ai_family) {
			case AF_INET: {
				struct sockaddr_in *s_addr = (struct sockaddr_in *) res->ai_addr;
				in_addr = &s_addr->sin_addr;
				break;
			}
#ifdef USE_IPV6
			case AF_INET6: {
				struct sockaddr_in6 *s_addr6 = (struct sockaddr_in6 *) res->ai_addr;
				in_addr = &s_addr6->sin6_addr;
				break;
			}
#endif
			default:
				continue;
		}
		inet_ntop(res->ai_family, in_addr, (void *)&ip_addr, NI_MAXHOST);

		/* Add to list of IPs if not already there */
		sip_peer_add_ip(peer, ip_addr, res->ai_family);
	}

	freeaddrinfo(result);

	return 0;

}
