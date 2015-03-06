/*
 * res_ubus.c
 *
 * UBUS resource
 * -Connects to UBUS and registers commands
 * -Hooks into Asterisk manager interface
 * -Data from either side is handled my main thread ubus_thread()
 *
 */

#include "asterisk.h"
#include "asterisk/module.h"
#include "asterisk/manager.h"
#include "asterisk/config.h"

#include "ubus/ami.h"
#include "ubus/ucix.h"

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json/json.h>

#define BUFLEN 512

/********/
/* UBUS */
/********/
static void *ubus_thread(void *arg);                     //Main thread
static struct ubus_context *ubus_setup(void);            //Setup ubus connection and add objects
static void ubus_disconnect(struct ubus_context **ctx);  //Disconnect from ubus
static int ubus_add_objects(struct ubus_context *ctx);   //Add supported ubus objects
static void system_fd_set_cloexec(int fd);               //Sets the close-on-exec flag for the file descriptor

static void ami_handle_message(                          //Handle events and responses from AMI
		struct ubus_context *ctx,
		struct ami *mgr,
		int fd);

/******************/
/* UBUS callbacks */
/******************/
static int ubus_asterisk_sip_dump_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static int ubus_asterisk_sip_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static int ubus_asterisk_brcm_dump_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static int ubus_asterisk_brcm_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static int ubus_asterisk_status_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static int ubus_asterisk_call_log_list_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static int ubus_asterisk_dect_list_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static int ubus_asterisk_codecs_cb(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

static void ubus_connection_lost_cb(
		struct ubus_context *ctx);

struct ami_context
{
	struct ubus_context *ctx;
	struct ubus_request_data req;
	int (*handle_response)(struct ubus_context *, struct ubus_request_data *, char *);
};

/***********/
/* Globals */
/***********/
static int ubus_connected = 0;
static int running = 0;
static pthread_t ubus_thread_handle;
struct ami* mgr; //manager listener context
int mgr_fd[2];

/*****************/
/* SIP IP struct */
/*****************/
#ifndef   NI_MAXHOST
#define   NI_MAXHOST 65
#endif
#define	MAX_IP_LIST_LENGTH	20

typedef struct IP
{
	int family;
	char addr[NI_MAXHOST];
} IP;

/*************/
/* SIP stuff */
/*************/
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

#define MAX_ACCOUNT_NAME	10
typedef struct SIP_ACCOUNT
{
	SIP_ACCOUNT_ID id;
	char name[MAX_ACCOUNT_NAME];
} SIP_ACCOUNT;

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

#define MAX_SIP_PEERS 10
#define MAX_SIP_PEER_NAME 10
#define MAX_SIP_PEER_USERNAME 128
#define MAX_SIP_PEER_DOMAIN 128
#define MAX_SIP_PEER_STATE 128
typedef struct SIP_PEER
{
	SIP_ACCOUNT	account;
	int		sip_registry_request_sent;		//Bool indicating if we have sent a registration request
	int		sip_registry_registered;		//Bool indicating if we are registered or not
	time_t	sip_registry_time;				//The time when we received the registry event
	IP		ip_list[MAX_IP_LIST_LENGTH];	//IP addresses of the sip registrar
	int		ip_list_length;					//Number of addresses

	//Info from sip show registry
	int port;								//The port we are connected to
	char username[MAX_SIP_PEER_USERNAME];	//Our username
	char domain[MAX_SIP_PEER_DOMAIN];		//The domain we are registered on
	int domain_port;						//The domain port
	int refresh;							//Refresh interval for this registration
	char state[MAX_SIP_PEER_STATE];			//Registration state e.g. Registered
	time_t registration_time;				//Registration timestamp, 1401282865

	struct ubus_object *ubus_object;
} SIP_PEER;

static SIP_PEER sip_peers[SIP_ACCOUNT_UNKNOWN + 1];
static void init_sip_peers(void);
static void sip_peer_add_ip(SIP_PEER *peer, char *addr, int family);
static void sip_peer_log_all(void);

/********/
/* UCIX */
/********/
#define UCI_VOICE_PACKAGE "voice_client"
#define UCI_CODEC_PACKAGE "voice_codecs"

static struct codec *uci_get_codecs(void);
static int uci_get_rtp_port_start(void);
static int uci_get_rtp_port_end(void);
static int uci_get_sip_proxy(struct list_head *proxies);
static const char* uci_get_peer_host(SIP_PEER *peer);
static const char* uci_get_peer_domain(SIP_PEER *peer);
static int uci_get_peer_enabled(SIP_PEER* peer);
static void ucix_reload(void);
static void uci_codec_cb(const char * name, void *priv);

struct uci_context *uci_voice_client_ctx = NULL;
struct uci_context *uci_voice_codecs_ctx = NULL;

/****************************/
/* Dynamic firewall support */
/****************************/
#define IPTABLES_CHAIN "zone_wan_input"
#define IPTABLES_BIN "iptables"
#define IPTABLES_FILE "/etc/firewall.sip"
#ifdef USE_IPV6
#define IP6TABLES_BIN "ip6tables"
#define IP6TABLES_FILE "/etc/firewall6.sip"
#endif
#define ECHO_BIN "echo"
#define UCI_BIN "uci"
#define UCI_VOICE_PACKAGE "voice_client"
#define UCI_CODEC_PACKAGE "voice_codecs"

#define RTP_RANGE_START_DEFAULT	10000
#define RTP_RANGE_END_DEFAULT	20000

static int rtpstart_current = 0;
static int rtpend_current = 0;
static IP* ip_list_current = NULL;
static int ip_list_length_current = 0;

static int fw_resolv(SIP_PEER *peer, const char *domain);
static IP* fw_ip_set_create(int family, int *ip_list_length);
static int fw_ip_set_compare(IP* ip_list1, int ip_list_length1, IP* ip_list2, int ip_list_length2);
static void fw_write(int family);
static int fw_manage(SIP_PEER *peer, int doResolv);

/**************/
/* BRCM stuff */
/**************/
//These are used to map SIP peer name to a port
//CPE may be configured to share the same SIP-account for several ports or to use individual accounts
typedef enum BRCM_PORT
{
	PORT_BRCM0 = 0,
	PORT_BRCM1,
	PORT_BRCM2,
	PORT_BRCM3,
	PORT_BRCM4,
	PORT_BRCM5,
	PORT_ALL,
	PORT_UNKNOWN
} BRCM_PORT;

typedef struct SUBCHANNEL
{
	char		state[80];
} SUBCHANNEL;

#define MAX_PORT_NAME	10
typedef struct PORT_MAP
{
	char		name[MAX_PORT_NAME];
	BRCM_PORT	port;
	int		off_hook;
	SUBCHANNEL	sub[2]; //TODO define for number of subchannels?
	struct ubus_object *ubus_object;
} PORT_MAP;

static PORT_MAP brcm_ports[] =
{
	{"brcm0",	PORT_BRCM0,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm1",	PORT_BRCM1,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm2",	PORT_BRCM2,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm3",	PORT_BRCM3,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm4",	PORT_BRCM4,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm5",	PORT_BRCM5,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	//Add other ports here as needed
	{"port_all",	PORT_ALL,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"-",		PORT_UNKNOWN,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
};

static void init_brcm_ports(void);

/*********/
/* Codec */
/*********/
struct codec {
  char *key;
  char *value;
  unsigned int bitrate;
  struct codec *next;
};
static struct codec *codec_create(void);
static void codec_delete(struct codec *codec);

/***************************/
/* UCI interface functions */
/***************************/

/*
 * Create list of supported codecs, used by ubus_codecs_cb()
 */
struct codec *uci_get_codecs(void)
{
	/* Create space for first codec */
	struct codec *c = codec_create();

	ucix_reload();
	ucix_for_each_section_type(uci_voice_codecs_ctx, UCI_CODEC_PACKAGE, "supported_codec", uci_codec_cb, c);
	return c;
}

/*
 * callback, called for each "supported_codec" found
 */
static void uci_codec_cb(const char * name, void *priv)
{
	struct codec *c = (struct codec *) priv;

	/* Store key/value to last codec in list */
	while (c->next) {
		c = c->next;
	}
	c->key = strdup(name);
	c->value = strdup(ucix_get_option(uci_voice_codecs_ctx, UCI_CODEC_PACKAGE, name, "name"));
	const char *bitrate = ucix_get_option(uci_voice_codecs_ctx, UCI_CODEC_PACKAGE, name, "bitrate");
	c->bitrate = bitrate ? atoi(bitrate) : 0;

	/* Create space for next codec */
	c->next = codec_create();
}

int uci_get_rtp_port_start()
{
	ucix_reload();
	return ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, "SIP", "rtpstart", RTP_RANGE_START_DEFAULT);
}

int uci_get_rtp_port_end()
{
	ucix_reload();
	return ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, "SIP", "rtpend", RTP_RANGE_END_DEFAULT);
}

int uci_get_sip_proxy(struct list_head *proxies)
{
	ucix_reload();
	return ucix_get_option_list(uci_voice_client_ctx, UCI_VOICE_PACKAGE, "SIP", "sip_proxy", proxies);
}

const char* uci_get_peer_host(SIP_PEER *peer)
{
	ucix_reload();
	int enabled = ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "enabled", 0);
	if (enabled == 0) {
		return NULL;
	}
	return ucix_get_option(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "host");
}

const char* uci_get_peer_domain(SIP_PEER *peer)
{
	ucix_reload();
	int enabled = ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "enabled", 0);
	if (enabled == 0) {
		return NULL;
	}
	return ucix_get_option(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "domain");
}

int uci_get_peer_enabled(SIP_PEER* peer)
{
	ucix_reload();
	return ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "enabled", 0);
}

/*
 * Reload uci context, as any changes to config will not be read otherwise
 */
void ucix_reload(void)
{
	if (uci_voice_client_ctx) {
		ucix_cleanup(uci_voice_client_ctx);
	}
	uci_voice_client_ctx = ucix_init(UCI_VOICE_PACKAGE);

	if (uci_voice_codecs_ctx) {
		ucix_cleanup(uci_voice_codecs_ctx);
	}
	uci_voice_codecs_ctx = ucix_init(UCI_CODEC_PACKAGE);
}

/****************************/
/* UBUS interface functions */
/****************************/

//Main thread
static void *ubus_thread(void *arg)
{
	struct ubus_context* ctx; //ubus context

	fd_set fset;              //FD set
	struct timeval timeout;   //Timeout for select
	int rv;                   //select() return value

	//Setup
	init_brcm_ports();
	init_sip_peers();
	ctx = ubus_setup();
	if (pipe(mgr_fd) < 0) {
		ast_log(LOG_ERROR, "Failed to open pipe: %s\n", strerror(errno));
		return NULL;
	}
	mgr = ami_setup(mgr_fd[1]);

	ami_action_send_sip_reload(mgr);

	while (running) {
		FD_ZERO(&fset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		FD_SET(mgr_fd[0], &fset);
		if (ubus_connected) {
			FD_SET(ctx->sock.fd, &fset);
		}

		//Wait for events from ubus or manager
		rv = select(FD_SETSIZE, &fset, NULL, NULL, &timeout);
		if(rv < 0) {
			if (errno == EINTR) {
				continue;
			}
			ast_log(LOG_ERROR, "error: %s\n", strerror(errno));
			ubus_disconnect(&ctx);
		}

		if (ubus_connected && FD_ISSET(ctx->sock.fd, &fset)) {
			//Connected to ubus and data available
			ubus_handle_event(ctx);
		}
		else if (!ubus_connected) {
			//Try to setup ubus connection again
			if (ctx && ubus_reconnect(ctx, NULL) == 0) {
				ast_log(LOG_DEBUG, "UBUS reconnected\n");
				ubus_connected = 1;
				system_fd_set_cloexec(ctx->sock.fd);
			}
			else if (!ctx) {
				ctx = ubus_setup();
			}
		}

		if (FD_ISSET(mgr_fd[0], &fset)) {
			//New manager message available
			ami_handle_message(ctx, mgr, mgr_fd[0]);
		}
	}

	//Teardown
	ami_free(mgr);
	if (ctx) {
		ubus_disconnect(&ctx);
	}

	return NULL;
}

//Initialize ubus connection and register asterisk object
static struct ubus_context *ubus_setup(void)
{
	int ret;
	struct ubus_context *ctx = NULL;

	ast_log(LOG_DEBUG, "Connecting to UBUS\n");
	ubus_connected = 0;
	ctx = ubus_connect(NULL);

	if (ctx) {
		ctx->connection_lost = ubus_connection_lost_cb;
		system_fd_set_cloexec(ctx->sock.fd);
		ret = ubus_add_objects(ctx);
		if (ret != 0) {
			ubus_disconnect(&ctx);
		}
		else {
			ubus_connected = 1;
		}
	}

	return ctx;
}

static void ubus_disconnect(struct ubus_context **ctx)
{
	ubus_free(*ctx);
	*ctx = NULL;
	ubus_connected = 0;
}

static void ubus_connection_lost_cb(struct ubus_context *ctx)
{
	ast_log(LOG_WARNING, "UBUS connection lost\n");
	ubus_connected = 0;
}

static void system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

static void init_brcm_ports()
{
	PORT_MAP *ports;

	ports = brcm_ports;
	while (ports->port != PORT_UNKNOWN) {
		ports->off_hook = 0;
		strcpy(ports->sub[0].state, "ONHOOK");
		strcpy(ports->sub[1].state, "ONHOOK");
		ports++;
	}
}

static void init_sip_peers()
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

	if (peer->ip_list_length >= MAX_IP_LIST_LENGTH) {
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

/**********************/
/* Firewall functions */
/**********************/

/* Resolv name into ip (A or AAA record), update IP list for peer */
int fw_resolv(SIP_PEER *peer, const char *domain)
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

/* Create a set of all resolved IPs for all peers */
IP* fw_ip_set_create(int family, int *ip_list_length) {
	SIP_PEER *peer;
	IP *ip_list;

	*ip_list_length = 0;
	ip_list = (IP *) malloc(MAX_IP_LIST_LENGTH * sizeof(struct IP));

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
				if (*ip_list_length == MAX_IP_LIST_LENGTH) {
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
int fw_ip_set_compare(IP* ip_list1, int ip_list_length1, IP* ip_list2, int ip_list_length2)
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

void fw_write(int family)
{
	char *tables_file;
	char *iptables_bin;
	char buf[BUFLEN];
	int ip_list_length;
	IP* ip_list;

	/* Is there a change in IP or RTP port range? */
	ip_list = fw_ip_set_create(family, &ip_list_length);
	int rtpstart = uci_get_rtp_port_start();
	int rtpend = uci_get_rtp_port_end();

	if (fw_ip_set_compare(ip_list_current, ip_list_length_current, ip_list, ip_list_length) == 0 &&
	    rtpstart_current == rtpstart &&
	    rtpend_current == rtpend) {
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
	if (ip_list_current) {
		free(ip_list_current);
	}
	ip_list_current = ip_list;
	ip_list_length_current = ip_list_length;

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
	rtpstart_current = rtpstart;
	rtpend_current = rtpend;

	snprintf((char *)&buf, BUFLEN, "/etc/init.d/firewall reload");
	ast_log(LOG_DEBUG, "%s\n", buf);
	system(buf);
}

/* Resolv host and add IPs to iptables */
int fw_manage(SIP_PEER *peer, int doResolv)
{
	/* Clear old IP list */
	peer->ip_list_length = 0;

	if (doResolv) {
		/* Get domain to resolv */
		const char* domain = uci_get_peer_domain(peer);
		if (domain) {
			fw_resolv(peer, domain);
		}
		else {
			ast_log(LOG_WARNING, "Failed to get sip domain\n");
			return 1;
		}

		const char* host = uci_get_peer_host(peer);
		if (host) {
			fw_resolv(peer, host);
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
				fw_resolv(peer, proxy->val);
				free(proxy->val);
				free(proxy);
			}
		}
	}

	/* Write new config to firewall.sip and reload firewall */
	fw_write(AF_INET);
#ifdef USE_IPV6
	fw_write(AF_INET6);
#endif

	return 0;
}

void sip_peer_log_all(void)
{
	const SIP_PEER *peers = sip_peers;
	while (peers->account.id != SIP_ACCOUNT_UNKNOWN) {
		ast_log(LOG_DEBUG, "sip_peer %d:\n", peers->account.id);
		ast_log(LOG_DEBUG, "\tname %s:\n", peers->account.name);
		ast_log(LOG_DEBUG, "\tsip_registry_request_sent: %d\n", peers->sip_registry_request_sent);
		ast_log(LOG_DEBUG, "\tsip_registry_registered: %d\n", peers->sip_registry_registered);
		ast_log(LOG_DEBUG, "\n");
		peers++;
	}
}

/******************************************/
/* UBUS function and structs for commands */
/******************************************/
enum {
	UBUS_ARG0,
	__UBUS_ARGMAX,
};

static const struct blobmsg_policy ubus_string_argument[__UBUS_ARGMAX] =
{
	[UBUS_ARG0] = { .name = "info", .type = BLOBMSG_TYPE_STRING },
};

static struct blob_buf bb;

static struct ubus_method sip_main_object_methods[] = {
	{ .name = "dump", .handler = ubus_asterisk_sip_dump_cb },
};

static struct ubus_object_type sip_main_object_type =
	UBUS_OBJECT_TYPE("sip_main_object", sip_main_object_methods);

static struct ubus_object ubus_sip_main_object[] = {
	{ .name = "asterisk.sip", .type = &sip_main_object_type, .methods = sip_main_object_methods, .n_methods = ARRAY_SIZE(sip_main_object_methods) }
};

static struct ubus_method sip_peer_object_methods[] = {
	{ .name = "status", .handler = ubus_asterisk_sip_cb },
};

static struct ubus_object_type sip_peer_object_type =
	UBUS_OBJECT_TYPE("sip_peer_object", sip_peer_object_methods);

static struct ubus_object ubus_sip_peer_objects[] = {
	{ .name = "asterisk.sip.0", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) },
	{ .name = "asterisk.sip.1", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) },
	{ .name = "asterisk.sip.2", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) },
	{ .name = "asterisk.sip.3", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) },
	{ .name = "asterisk.sip.4", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) },
	{ .name = "asterisk.sip.5", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) },
	{ .name = "asterisk.sip.6", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) },
	{ .name = "asterisk.sip.7", .type = &sip_peer_object_type, .methods = sip_peer_object_methods, .n_methods = ARRAY_SIZE(sip_peer_object_methods) }
};

static struct ubus_method brcm_main_object_methods[] = {
	{ .name = "dump", .handler = ubus_asterisk_brcm_dump_cb },
};

static struct ubus_object_type brcm_main_object_type =
	UBUS_OBJECT_TYPE("brcm_main_object", brcm_main_object_methods);

static struct ubus_object ubus_brcm_main_object[] = {
	{ .name = "asterisk.brcm", .type = &brcm_main_object_type, .methods = brcm_main_object_methods, .n_methods = ARRAY_SIZE(brcm_main_object_methods) }
};

static struct ubus_method brcm_line_object_methods[] = {
	{ .name = "status", .handler = ubus_asterisk_brcm_cb },
};

static struct ubus_object_type brcm_line_object_type =
	UBUS_OBJECT_TYPE("brcm_object", brcm_line_object_methods);

static struct ubus_object ubus_brcm_line_objects[] = {
	{ .name = "asterisk.brcm.0", .type = &brcm_line_object_type, .methods = brcm_line_object_methods, .n_methods = ARRAY_SIZE(brcm_line_object_methods) },
	{ .name = "asterisk.brcm.1", .type = &brcm_line_object_type, .methods = brcm_line_object_methods, .n_methods = ARRAY_SIZE(brcm_line_object_methods) },
	{ .name = "asterisk.brcm.2", .type = &brcm_line_object_type, .methods = brcm_line_object_methods, .n_methods = ARRAY_SIZE(brcm_line_object_methods) },
	{ .name = "asterisk.brcm.3", .type = &brcm_line_object_type, .methods = brcm_line_object_methods, .n_methods = ARRAY_SIZE(brcm_line_object_methods) },
	{ .name = "asterisk.brcm.4", .type = &brcm_line_object_type, .methods = brcm_line_object_methods, .n_methods = ARRAY_SIZE(brcm_line_object_methods) },
	{ .name = "asterisk.brcm.5", .type = &brcm_line_object_type, .methods = brcm_line_object_methods, .n_methods = ARRAY_SIZE(brcm_line_object_methods) }
};

static struct ubus_method asterisk_object_methods[] = {
	{ .name = "status", .handler = ubus_asterisk_status_cb },
	{ .name = "codecs", .handler = ubus_asterisk_codecs_cb },
};

static struct ubus_object_type asterisk_object_type =
	UBUS_OBJECT_TYPE("asterisk_object", asterisk_object_methods);

static struct ubus_object ubus_asterisk_object = {
		.name = "asterisk",
		.type = &asterisk_object_type,
		.methods = asterisk_object_methods,
		.n_methods = ARRAY_SIZE(asterisk_object_methods) };

static struct ubus_method asterisk_call_log_object_methods[] = {
	{ .name = "list", .handler = ubus_asterisk_call_log_list_cb }
};

static struct ubus_object_type asterisk_call_log_object_type =
	UBUS_OBJECT_TYPE("asterisk_call_log_object", asterisk_call_log_object_methods);

static struct ubus_object ubus_asterisk_call_log_object = {
		.name = "asterisk.call_log",
		.type = &asterisk_call_log_object_type,
		.methods = asterisk_call_log_object_methods,
		.n_methods = ARRAY_SIZE(asterisk_call_log_object_methods) };

static struct ubus_method asterisk_dect_object_methods[] = {
	{ .name = "list", .handler = ubus_asterisk_dect_list_cb }
};

static struct ubus_object_type asterisk_dect_object_type =
	UBUS_OBJECT_TYPE("asterisk_dect_object", asterisk_dect_object_methods);

static struct ubus_object ubus_asterisk_dect_object = {
		.name = "asterisk.dect",
		.type = &asterisk_dect_object_type,
		.methods = asterisk_dect_object_methods,
		.n_methods = ARRAY_SIZE(asterisk_dect_object_methods) };

static int ubus_add_objects(struct ubus_context *ctx)
{
	int ret = 0;

	SIP_PEER *peer;
	peer = sip_peers;
	while (peer->account.id != SIP_ACCOUNT_UNKNOWN) {
		peer->ubus_object = &ubus_sip_peer_objects[peer->account.id];
		ret &= ubus_add_object(ctx, peer->ubus_object);
		peer++;
	}

	PORT_MAP *port;
	port = brcm_ports;
	while (port->port != PORT_ALL) {
		port->ubus_object = &ubus_brcm_line_objects[port->port];
		ret &= ubus_add_object(ctx, port->ubus_object);
		port++;
	}

	ret &= ubus_add_object(ctx, &ubus_sip_main_object);
	ret &= ubus_add_object(ctx, &ubus_brcm_main_object);
	ret &= ubus_add_object(ctx, &ubus_asterisk_object);
	ret &= ubus_add_object(ctx, &ubus_asterisk_call_log_object);
	ret &= ubus_add_object(ctx, &ubus_asterisk_dect_object);

	return ret;
}

/*
 * Sends asterisk.sip events
 */
static int ubus_send_sip_event(struct ubus_context *ctx, const SIP_PEER *peer, const char *key, const int value)
{
	char id[BUFLEN];
	char sValue[BUFLEN];

	snprintf(id, BUFLEN, "asterisk.sip.%d", peer->account.id);
	snprintf(sValue, BUFLEN, "%d", value);

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, key, sValue);

	return ubus_send_event(ctx, id, bb.head);
}

/*
 * Sends asterisk.brcm events
 */
static int ubus_send_brcm_event(struct ubus_context *ctx, const PORT_MAP *port, const char *key, const char *value)
{
	char id[BUFLEN];
	snprintf(id, BUFLEN, "asterisk.brcm.%d", port->port);

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, key, value);

	return ubus_send_event(ctx, id, bb.head);
}

/*
 * Collects and returns information on a single brcm line to a ubus message buffer
 */
static int ubus_get_brcm_line(struct blob_buf *b, int line)
{
	if (line >= PORT_UNKNOWN || line >= PORT_ALL || line < 0) {
		return 1;
	}

	const PORT_MAP *p = &(brcm_ports[line]);
	blobmsg_add_string(b, "sub_0_state", p->sub[0].state);
	blobmsg_add_string(b, "sub_1_state", p->sub[1].state);

	return 0;
}

/*
 * Collects and returns information on a single sip account to a ubus message buffer
 */
static int ubus_get_sip_account(struct blob_buf *b, int account_id)
{
	if (account_id >= SIP_ACCOUNT_UNKNOWN || account_id < 0) {
		return 1;
	}

	blobmsg_add_u8(b, "registered", sip_peers[account_id].sip_registry_registered);
	blobmsg_add_u8(b, "registry_request_sent", sip_peers[account_id].sip_registry_request_sent);

	//IP address(es) of the sip registrar
	int i;
	for (i = 0; i<sip_peers[account_id].ip_list_length; i++) {
		blobmsg_add_string(b, "ip", sip_peers[account_id].ip_list[i].addr);
	}

	blobmsg_add_u32(b, "port", sip_peers[account_id].port);
	blobmsg_add_string(b, "username", sip_peers[account_id].username);
	blobmsg_add_string(b, "domain", sip_peers[account_id].domain);
	blobmsg_add_u32(b, "domain_port", sip_peers[account_id].domain_port);
	blobmsg_add_u32(b, "refresh_interval", sip_peers[account_id].refresh);
	blobmsg_add_string(b, "state", sip_peers[account_id].state);

	//Format registration time
	if (sip_peers[account_id].registration_time > 0) {
		struct tm* timeinfo;
		char buf[80];
		timeinfo = localtime(&(sip_peers[account_id].registration_time));
		strftime(buf, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
		blobmsg_add_string(b, "registration_time", buf);
	}
	else {
		blobmsg_add_string(b, "registration_time", "-");
	}

	//This is the time of last successful registration for this account,
	//regardless of the current registration state (differs from registration_time)
	if (sip_peers[account_id].sip_registry_time > 0) {
		struct tm* timeinfo;
		char buf[80];
		timeinfo = localtime(&(sip_peers[account_id].sip_registry_time));
		strftime(buf, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
		blobmsg_add_string(b, "last_successful_registration", buf);
	}
	else {
		blobmsg_add_string(b, "last_successful_registration", "-");
	}

	return 0;
}

/*
 * ubus callback that replies to "asterisk.sip.X status"
 */
static int ubus_asterisk_sip_cb(
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];

	blobmsg_parse(ubus_string_argument, __UBUS_ARGMAX, tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	SIP_PEER *peer = sip_peers;
	while (peer->account.id != SIP_ACCOUNT_UNKNOWN) {
		if (peer->ubus_object == obj) {
			ubus_get_sip_account(&bb, peer->account.id); //Add SIP account status to message
			break;
		}
		peer++;
	}

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static int ubus_asterisk_sip_dump_handle_response_cb(
	struct ubus_context *ctx, struct ubus_request_data *req,
	char *data)
{
	blob_buf_init(&bb, 0);

	/* Parse AMI response */
	char outbound_transport[32];
	char allowed_transports[32];

	memset(outbound_transport, 0, sizeof(outbound_transport));
	memset(allowed_transports, 0, sizeof(allowed_transports));

	char *sub = strstr(data, "OutboundTransport: ");
	if (sub) {
		sscanf(sub, "OutboundTransport: %s\r\n", outbound_transport);
	}

	sub = strstr(data, "AllowedTransports: ");
	if (sub) {
		sscanf(sub, "AllowedTransports: %s\r\n", allowed_transports);
	}

	/* Reply to ubus */
	void *a = blobmsg_open_table(&bb, "transports");

	blobmsg_add_string(&bb, "outbound", outbound_transport);
	blobmsg_add_string(&bb, "allowed", allowed_transports);

	blobmsg_close_table(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	ubus_complete_deferred_request(ctx, req, 0);

	return 0;
}

/*
 * ubus callback that replies to "asterisk.sip dump"
 */
static int ubus_asterisk_sip_dump_cb (
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct ami_context *ami_ctx;
	ami_ctx = (struct ami_context *)malloc(sizeof(struct ami_context));
	ami_ctx->ctx = ctx;
	ami_ctx->handle_response = ubus_asterisk_sip_dump_handle_response_cb;

	ami_action_send_sip_dump(mgr, ami_ctx);
	ubus_defer_request(ctx, req, &ami_ctx->req);

	return 0;
}

/*
 * ubus callback that replies to "asterisk.brcm.X status"
 */
static int ubus_asterisk_brcm_cb (
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];

	blobmsg_parse(ubus_string_argument, __UBUS_ARGMAX, tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	PORT_MAP *port;
	port = brcm_ports;
	while (port->port != PORT_UNKNOWN) {
		if (port->ubus_object == obj) {
			ubus_get_brcm_line(&bb, port->port); //Add port status to message
			break;
		}
		port++;
	}

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static int ubus_asterisk_brcm_dump_handle_response_cb(
	struct ubus_context *ctx, struct ubus_request_data *req,
	char *data)
{
	blob_buf_init(&bb, 0);

	/* Parse AMI response */
	int num_subchannels = -1;
	int num_lines = -1;

	char *sub = strstr(data, "NumSubchannels: ");
	if (sub) {
		sscanf(sub, "NumSubchannels: %d\r\n", &num_subchannels);
	}

	sub = strstr(data, "NumLines: ");
	if (sub) {
		sscanf(sub, "NumLines: %d\r\n", &num_lines);
	}

	/* Reply to ubus */
	blobmsg_add_u32(&bb, "num_subchannels", num_subchannels);
	blobmsg_add_u32(&bb, "num_lines", num_lines);

	ubus_send_reply(ctx, req, bb.head);
	ubus_complete_deferred_request(ctx, req, 0);

	return 0;
}

/*
 * ubus callback that replies to "asterisk.brcm dump"
 */
static int ubus_asterisk_brcm_dump_cb(
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct ami_context *ami_ctx;
	ami_ctx = (struct ami_context *)malloc(sizeof(struct ami_context));
	ami_ctx->ctx = ctx;
	ami_ctx->handle_response = ubus_asterisk_brcm_dump_handle_response_cb;

	ami_action_send_brcm_dump(mgr, ami_ctx);
	ubus_defer_request(ctx, req, &ami_ctx->req);

	return 0;
}

/*
 * ubus callback that replies to "asterisk status".
 * Recursively reports status for all lines/accounts
 */
static int ubus_asterisk_status_cb (
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];

	blobmsg_parse(ubus_string_argument, __UBUS_ARGMAX, tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	SIP_PEER *peer = sip_peers;
	void *sip_table = blobmsg_open_table(&bb, "sip");
	while (peer->account.id != SIP_ACCOUNT_UNKNOWN) {
		void *sip_account_table = blobmsg_open_table(&bb, peer->account.name);
		ubus_get_sip_account(&bb, peer->account.id); //Add SIP account status to message
		blobmsg_close_table(&bb, sip_account_table);
		peer++;
	}
	blobmsg_close_table(&bb, sip_table);

	PORT_MAP *port = brcm_ports;
	void *brcm_table = blobmsg_open_table(&bb, "brcm");
	while (port->port != PORT_UNKNOWN && port->port != PORT_ALL) {
		void *line_table = blobmsg_open_table(&bb, port->name);
		ubus_get_brcm_line(&bb, port->port); //Add port status to message
		blobmsg_close_table(&bb, line_table);
		port++;
	}
	blobmsg_close_table(&bb, brcm_table);

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}
/*
 * ubus callback that replies to "asterisk.call_log list".
 */
static int ubus_asterisk_call_log_list_cb (
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];

	blobmsg_parse(ubus_string_argument, __UBUS_ARGMAX, tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	void *log = blobmsg_open_array(&bb, "call_log");

	/* Read call log file line by line */
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	fp = fopen("/var/call_log", "r");
	if (fp == NULL) {
		goto fail;
	}

	const char delim[] = ";";
	const char *tokens[3];
	while ((read = getline(&line, &len, fp)) != -1) {
		memset(tokens, 0, sizeof(tokens));
		char *token = strtok(line, delim);
		int k = 0;

		while (token != NULL && k < (sizeof(tokens) / sizeof(void*))) {
			/* Trim new-line character */
			char *nl = strchr(token, '\n');
			if (nl != NULL) {
				*nl = '\0';
			}
			tokens[k] = token;
			token = strtok(NULL, delim);
			k += 1;
		}

		if (k >= 3) {
			void *e = blobmsg_open_table(&bb, NULL);
			blobmsg_add_string(&bb, "time", tokens[0]);
			blobmsg_add_string(&bb, "direction", tokens[1]);
			blobmsg_add_string(&bb, "number", tokens[2]);
			blobmsg_close_table(&bb, e);
		}
	}

	fclose(fp);
	if (line) {
		free(line);
	}

fail:
	blobmsg_close_array(&bb, log);

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

/*
 * ubus callback that replies to "asterisk.dect list".
 */
static int ubus_asterisk_dect_list_cb (
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];

	blobmsg_parse(ubus_string_argument, __UBUS_ARGMAX, tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	void *handsets = blobmsg_open_array(&bb, "handsets");

	char *buf = NULL;
	const int buflen = 4096;
	FILE *fp = NULL;
	size_t read;
	struct json_tokener *tok = NULL;
	json_object *jobj = NULL;

	buf = (char *)calloc(sizeof(char), buflen);
	if (buf == NULL) {
		goto reply;
	}

	fp = popen("/usr/bin/dect -j", "r");
	if (fp == NULL) {
		goto reply;
	}

	/* Read output into buffer */
	read = fread(buf, sizeof(char), buflen, fp);

	/*
	 Example:
	 {
		"reg_active":false,
		"handsets":[
		{
			"handset":1,
			"rfpi":"01 5c 64 42 43 ",
			"present":true,
			"pinging":false
		},
		{
			"handset":2,
			"rfpi":"00 c2 82 e4 9a ",
			"present":true,
			"pinging":false
		}
		],
		"ule":[
		]
	 }
	 */

	tok = json_tokener_new();
	jobj = json_tokener_parse_ex(tok, buf, read);
	if (jobj == NULL) {
		switch (json_tokener_get_error(tok)) {
		case json_tokener_continue:
			/* Not enough data */
			/* Too bad we did not read enough */
			goto reply;
		default:
			/* Corrupt input to parser */
			goto reply;
		}
	}

	json_object_object_foreach(jobj, key, val) {
		if (strcmp(key, "handsets") == 0 && json_object_get_type(val) == json_type_array) {
			json_object *array = json_object_object_get(jobj, key);
			int arraylen = json_object_array_length(array);

			int i;
			for (i = 0; i < arraylen; i++) {
				json_object *item = json_object_array_get_idx(array, i);
				if (json_object_get_type(item) == json_type_object) {
					unsigned int handset = 0;
					unsigned int present = 0;

					json_object_object_foreach(item, k, v) {
						if (strcmp(k, "handset") == 0 && json_object_get_type(v) == json_type_int) {
							handset = (unsigned int)json_object_get_int(v);
						}
						else if (strcmp(k, "present") == 0 && json_object_get_type(v) == json_type_boolean) {
							present = (unsigned int)json_object_get_boolean(v);
						}
					}

					void *e = blobmsg_open_table(&bb, NULL);
					blobmsg_add_u32(&bb, "handset", handset);
					blobmsg_add_u8(&bb, "present", present);
					blobmsg_close_table(&bb, e);
				}
			}
		}
	}

reply:
	if (fp != NULL) {
		pclose(fp);
	}

	if (buf != NULL) {
		free(buf);
	}

	if (jobj != NULL) {
		json_object_put(jobj);
	}

	if (tok != NULL) {
		json_tokener_free(tok);
	}

	blobmsg_close_array(&bb, handsets);

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

/*
 * ubus callback that replies to "asterisk.codecs status"
 */
static int ubus_asterisk_codecs_cb (
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];
	struct codec *codec;
	struct codec *codec_tmp;

	blobmsg_parse(ubus_string_argument, __UBUS_ARGMAX, tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	codec = uci_get_codecs();

	while (codec) {
		/* Node with next == NULL serves as end marker */
		if (codec->next == NULL) {
			codec_delete(codec);
			break;
		}

		void *table = blobmsg_open_table(&bb, codec->key);
		blobmsg_add_string(&bb, "name", codec->value);
		if (codec->bitrate) {
			blobmsg_add_u32(&bb, "bitrate", codec->bitrate);
		}
		blobmsg_close_table(&bb, table);

		codec_tmp = codec;
		codec = codec->next;
		codec_delete(codec_tmp);
	}

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static void ubus_handle_registry_event(struct ubus_context *ctx, struct ami_event *event)
{
	const SIP_ACCOUNT* accounts = sip_accounts;
	SIP_PEER *peer = &sip_peers[PORT_UNKNOWN];
	char* account_name = event->registry_event->account_name;

	//Lookup peer by account name
	while (accounts->id != SIP_ACCOUNT_UNKNOWN) {
		if (!strcmp(accounts->name, account_name)) {
			peer = &sip_peers[accounts->id];
			break;
		}
		accounts++;
	}

	if (peer->account.id == SIP_ACCOUNT_UNKNOWN) {
		ast_log(LOG_WARNING, "Registry event for unknown account: %s\n", account_name);
		return;
	}

	switch (event->registry_event->status) {
		case REGISTRY_REGISTERED_EVENT:
			ast_log(LOG_DEBUG, "sip registry registered\n");
			peer->sip_registry_registered = 1;
			peer->sip_registry_request_sent = 0;
			time(&(peer->sip_registry_time)); //Last registration time
			if (ctx) {
				ubus_send_sip_event(ctx, peer, "registered", peer->sip_registry_registered);
				ubus_send_sip_event(ctx, peer, "registry_request_sent", peer->sip_registry_request_sent);
			}
			fw_manage(peer, 1);
			break;
		case REGISTRY_UNREGISTERED_EVENT:
			ast_log(LOG_DEBUG, "sip registry unregistered\n");
			peer->sip_registry_registered = 0;
			peer->sip_registry_request_sent = 0;
			if (ctx) {
				ubus_send_sip_event(ctx, peer, "registered", peer->sip_registry_registered);
				ubus_send_sip_event(ctx, peer, "registry_request_sent", peer->sip_registry_request_sent);
			}
			fw_manage(peer, 0);
			break;
		case REGISTRY_REQUEST_SENT_EVENT:
			if (peer->sip_registry_request_sent == 1) {
				//This means we sent a "REGISTER" without receiving "Registered" event
				peer->sip_registry_registered = 0;
				fw_manage(peer, 0);
			}
			peer->sip_registry_request_sent = 1;
			if (ctx) {
				ubus_send_sip_event(ctx, peer, "registered", peer->sip_registry_registered);
				ubus_send_sip_event(ctx, peer, "registry_request_sent", peer->sip_registry_request_sent);
			}
			break;
		default:
			break;
	}
}

static void ubus_handle_registry_entry_event(struct ami_event *event)
{
	ast_log(LOG_NOTICE, "Got registry entry event for SIP account %s\n", event->registry_entry_event->host);
	const SIP_ACCOUNT* accounts = sip_accounts;
	SIP_PEER *peer = &sip_peers[PORT_UNKNOWN];
	char* account_name = event->registry_entry_event->host;

	//Lookup peer by account name
	while (accounts->id != SIP_ACCOUNT_UNKNOWN) {
		if (!strcmp(accounts->name, account_name)) {
			peer = &sip_peers[accounts->id];
			break;
		}
		accounts++;
	}

	if (peer->account.id == SIP_ACCOUNT_UNKNOWN) {
		ast_log(LOG_NOTICE, "RegistryEntry event for unknown account: %s\n", account_name);
		return;
	}

	//Update our sip peer with event information
	strncpy(peer->username, event->registry_entry_event->username, MAX_SIP_PEER_USERNAME);
	peer->username[MAX_SIP_PEER_USERNAME - 1]= '\0';
	strncpy(peer->domain, event->registry_entry_event->domain, MAX_SIP_PEER_DOMAIN);
	peer->domain[MAX_SIP_PEER_USERNAME - 1]= '\0';
	strncpy(peer->state, event->registry_entry_event->state, MAX_SIP_PEER_STATE);
	peer->state[MAX_SIP_PEER_USERNAME - 1]= '\0';
	peer->port = event->registry_entry_event->port;
	peer->domain_port = event->registry_entry_event->domain_port;
	peer->refresh = event->registry_entry_event->refresh;
	peer->registration_time = event->registry_entry_event->registration_time;
}

static void ubus_handle_brcm_event(struct ami *mgr, struct ubus_context *ctx, struct ami_event *event)
{
	int line_id;
	int subchannel_id;

	switch (event->brcm_event->type) {
		case BRCM_STATUS_EVENT:
			ast_log(LOG_DEBUG, "Got BRCM_STATUS_EVENT for %d, offhook = %d\n", event->brcm_event->status.line_id, event->brcm_event->status.off_hook);
			line_id = event->brcm_event->status.line_id;
			if (line_id >= 0 && line_id < PORT_ALL) {
				brcm_ports[line_id].off_hook = event->brcm_event->status.off_hook;
			}
			else {
				ast_log(LOG_DEBUG, "Got BRCM Status event for unknown line %d\n", line_id);
			}
			break;
		case BRCM_STATE_EVENT:
			ast_log(LOG_DEBUG, "Got BRCM_STATE_EVENT for %d.%d: %s\n", event->brcm_event->state.line_id, event->brcm_event->state.subchannel_id, event->brcm_event->state.state);
			line_id = event->brcm_event->state.line_id;
			subchannel_id = event->brcm_event->state.subchannel_id;

			if (line_id >= 0 && line_id < PORT_ALL) {
				strcpy(brcm_ports[line_id].sub[subchannel_id].state, event->brcm_event->state.state);
				char* subchannel = subchannel_id ? "0" : "1";
				if (ctx) {
					ubus_send_brcm_event(ctx, &brcm_ports[line_id], subchannel, brcm_ports[line_id].sub[subchannel_id].state);
				}
			}
			else {
				ast_log(LOG_DEBUG, "Got BRCM Status event for unknown line %d\n", line_id);
			}
			break;
		case BRCM_MODULE_EVENT:
			//No action required
			break;
		default:
			break;
	}
}

static void ubus_handle_varset_event(struct ubus_context *ctx, struct ami_event *event)
{
	if (ctx && event->varset_event->channel && event->varset_event->variable && event->varset_event->value) {
		//Event contained all vital parts, send ubus event
		blob_buf_init(&bb, 0);
		blobmsg_add_string(&bb, event->varset_event->variable, event->varset_event->value);
		ubus_send_event(ctx, event->varset_event->channel, bb.head);
	}
}

//Handle AMI event
//Note that ubus_context may be NULL, if we receive messages while not
//connected to ubus. Each event handler should check this before trying to use ubus.
static void ubus_handle_ami_event(struct ami *mgr, struct ubus_context *ctx, struct ami_event *event)
{
	switch (event->type) {
	case REGISTRY:
		ubus_handle_registry_event(ctx, event);
		ami_action_send_sip_show_registry(mgr);
		break;
	case REGISTRY_ENTRY:
		ubus_handle_registry_entry_event(event);
		break;
	case BRCM:
		ubus_handle_brcm_event(mgr, ctx, event);
		break;
	case CHANNELRELOAD:
		if (event->channel_reload_event->channel_type == CHANNELRELOAD_SIP_EVENT) {
			ast_log(LOG_DEBUG, "SIP channel was reloaded\n");
			init_sip_peers(); //SIP has reloaded, initialize sip peer structs
		}
		break;
	case VARSET:
		ubus_handle_varset_event(ctx, event);
		break;
	case REGISTRATIONS_COMPLETE:
		//No action required
		break;
	case FULLYBOOTED:
		ami_action_send_sip_reload(mgr);
		break;
	case UNKNOWN_EVENT:
		break; //An event that ami_parser could not handle
	default:
		break; //An event that we don't care about
	}
}

static void ubus_handle_ami_response(struct ami *mgr, struct ubus_context *ctx, struct ami_response *resp)
{
	struct ami_context *ami_ctx;
	if (resp->userdata) {
		ami_ctx = (struct ami_context *)resp->userdata;
		if (ami_ctx->handle_response) {
			ami_ctx->handle_response(ami_ctx->ctx, &ami_ctx->req, resp->response);
		}
		free(resp->userdata);
	}
}


/*****************************************/
/* Asterisk module and manager interface */
/*****************************************/
static void ami_handle_message(struct ubus_context *ctx, struct ami *mgr, int fd)
{
	char c;
	struct ami_message *message;

	if (read(fd, &c, sizeof(char)) < 0) {
		ast_log(LOG_ERROR, "Failed to read manager fd: %s\n", strerror(errno));
		return;
	}

	while ((message = ami_get_next_message(mgr))) {
		switch (message->type) {
		case EVENT_MESSAGE:
			ubus_handle_ami_event(mgr, ctx, message->event);
			break;
		case RESPONSE_MESSAGE:
			ubus_handle_ami_response(mgr, ctx, message->response);
			break;
		default:
			break; //Message ignored
		}
		ami_message_free(message);
	}
}

static struct codec *codec_create(void)
{
	struct codec *c = malloc(sizeof(struct codec));
	memset(c, 0, sizeof(struct codec));

	return c;
}

static void codec_delete(struct codec *c)
{
	if (c->key) {
		free(c->key);
	}

	if (c->value) {
		free(c->value);
	}

	free(c);
}

static int ubus_load(void)
{
	running = 1;
	if (ast_pthread_create_detached_background(&ubus_thread_handle, NULL, ubus_thread, NULL) < 0) {
		//Could not start thread
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

static int ubus_unload(void)
{
	if (running) {
		running = 0;
		while (pthread_kill(ubus_thread_handle, SIGURG) == 0) {
			sched_yield();
		}
		pthread_join(ubus_thread_handle, NULL);
	}
	ubus_thread_handle = AST_PTHREADT_STOP;

	return 0;
}

static int load_module(void)
{
	int rv;

	if ((rv = ubus_load())) {
		ast_log(LOG_WARNING, "Failed to load res_ubus\n");
	}

	return rv;
}

static int unload_module(void)
{
	return ubus_unload();
}


AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "UBUS Resource",
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_DEVSTATE_CONSUMER,
);

