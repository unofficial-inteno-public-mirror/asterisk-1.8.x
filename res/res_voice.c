/*
 * res_voice.c
 *
 * Voice client/pbx resource
 * -Connects to UBUS and registers commands
 * -Hooks into Asterisk manager interface
 * -Data from either side is handled my main thread res_voice_thread()
 *
 */

#define __AST_SELECT_H											// Prevent Asterisk from replacing libc FD_ZERO() with ugliness
#include "asterisk.h"
#include "asterisk/module.h"
#include "asterisk/manager.h"
#include "asterisk/paths.h"

#include "voice/ami.h"
#include "voice/brcm.h"
#include "voice/codec.h"
#include "voice/fw.h"
#include "voice/ip.h"
#include "voice/leds.h"
#include "voice/sip.h"
#include "voice/uci.h"

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <pthread.h>
#include <signal.h>
#include <json-c/json.h>

#define BUFLEN 512
#define MODULE_SHOW_INTERVAL_S 5
#define BOOT_WAIT_TIME_S 30

#define CSV_LOG_DIR "/cdr-csv"
#define CSV_MASTER  "/Master.csv"

/********/
/* UBUS */
/********/
static void *res_voice_thread(void *arg);                     //Main thread
static struct ubus_context *ubus_setup(void);            //Setup ubus connection and add objects
static void ubus_disconnect(struct ubus_context **ctx);  //Disconnect from ubus
static int ubus_add_objects(struct ubus_context *ctx);   //Add supported ubus objects
static void system_fd_set_cloexec(int fd);               //Sets the close-on-exec flag for the file descriptor

static void ami_handle_message(                          //Handle events and responses from AMI
		struct ubus_context *ctx,
		struct ami *mgr,
		int fd);

static void ami_refresh_action(void *userdata);          //AMI callback, refresh action userdata

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

static int ubus_asterisk_call_log_delete_cb(
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
	int ubus_ctx_lost;
	struct ubus_request_data req;
	int (*handle_response)(struct ubus_request_data *, char *, int ubus_lost);
};

/***********/
/* Globals */
/***********/
static int ubus_connected = 0;
static int running = 0;
static pthread_t res_voice_thread_handle;
struct ubus_context* ctx; //ubus context
struct ami* mgr; //manager listener context
struct fw* fw; //Managed firewall struct
struct leds* leds; //Managed leds struct
int mgr_fd[2];
static SIP_PEER sip_peers[SIP_ACCOUNT_UNKNOWN + 1];
static BRCM_PORT_MAP brcm_ports[BRCM_PORT_UNKNOWN + 1];

#define UCI_BIN "uci"
#define UCI_VOICE_PACKAGE "voice_client"
#define UCI_CODEC_PACKAGE "voice_codecs"

enum modules_loaded_flags {
	CHAN_SIP_LOADED = (1 << 0),
	CHAN_BRCM_LOADED = (1 << 1),
};
struct ast_flags modules_loaded = { 0 };

time_t sip_timestamp;
time_t brcm_timestamp;

/********************/
/* Static functions */
/********************/
static int module_show_brcm_request(void);
static int module_show_brcm_handle_response_cb(
		struct ubus_request_data *req,
		char *data,
		int ubus_lost);
static int brcm_ports_show_request(void);
static int brcm_ports_show_response_cb(
		struct ubus_request_data *req,
		char *data,
		int ubus_lost);
static int module_show_sip_request(void);
static int module_show_sip_handle_response_cb(
		struct ubus_request_data *req,
		char *data,
		int ubus_lost);
static void set_brcm_loaded(unsigned int loaded);
static void set_sip_loaded(unsigned int loaded);
static void sip_module_status_refresh(void);
static void brcm_module_status_refresh(void);
static int all_modules_loaded(void);

/****************************/
/* UBUS interface functions */
/****************************/

//Main thread
static void *res_voice_thread(void *arg)
{
	fd_set fset;              //FD set
	struct timeval timeout;   //Timeout for select
	int rv;                   //select() return value

	ast_clear_flag(&modules_loaded, CHAN_SIP_LOADED);
	ast_clear_flag(&modules_loaded, CHAN_BRCM_LOADED);

	time_t start = time(NULL);
	time_t now = start;
	while (!ast_test_flag(&ast_options, AST_OPT_FLAG_FULLY_BOOTED)) {
		if ((now - start) > BOOT_WAIT_TIME_S) {
			ast_log(LOG_ERROR,
					"Asterisk was not fully booted in %ds, continuing anyway...\n",
					BOOT_WAIT_TIME_S);
			break;
		}

		//Wait for asterisk to be fully booted
		struct timespec req, rem;
		req.tv_sec = 0;
		req.tv_nsec = 500000000L;
		while (nanosleep(&req, &rem) < 0) {
			if (errno != EINTR) {
				break;
			}
			req = rem;
		}

		now = time(NULL);
	}

	//Setup
	brcm_port_init_all(brcm_ports);
	sip_peer_init_all(sip_peers);

	ctx = ubus_setup();
	if (pipe(mgr_fd) < 0) {
		ast_log(LOG_ERROR, "Failed to open pipe: %s\n", strerror(errno));
		return NULL;
	}
	mgr = ami_setup(mgr_fd[1], ami_refresh_action);
	fw = fw_create();

	while (running) {

		sip_module_status_refresh();
		brcm_module_status_refresh();

		FD_ZERO(&fset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		FD_SET(mgr_fd[0], &fset);
		if (ubus_connected) {
			FD_SET(ctx->sock.fd, &fset);
		}

		//Wait for events from ubus or manager
		rv = select(FD_SETSIZE, &fset, NULL, NULL, &timeout);
		if (rv < 0) {
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
				if (leds) {
					leds_ubus_connected(leds, ctx);
				}
			}
		}

		if (FD_ISSET(mgr_fd[0], &fset)) {
			//New manager message available
			ami_handle_message(ctx, mgr, mgr_fd[0]);
		}
	}

	//Teardown
	if (ctx) {
		ubus_disconnect(&ctx);
	}
	ami_free(mgr);

	fw_delete(fw);

	if (leds) {
		leds_delete(leds);
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
	if (leds) {
		leds_ubus_disconnected(leds);
	}
	ami_refresh(mgr);
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

static struct ubus_object ubus_sip_main_object = {
		.name = "asterisk.sip",
		.type = &sip_main_object_type,
		.methods = sip_main_object_methods,
		.n_methods = ARRAY_SIZE(sip_main_object_methods)
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

static struct ubus_object ubus_brcm_main_object = {
		.name = "asterisk.brcm",
		.type = &brcm_main_object_type,
		.methods = brcm_main_object_methods,
		.n_methods = ARRAY_SIZE(brcm_main_object_methods)
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

static struct blobmsg_policy asterisk_call_log_list_policy[] = {
	{ .name = "number", .type = BLOBMSG_TYPE_STRING },
	{ .name = "type", .type = BLOBMSG_TYPE_STRING },
	{ .name = "limit", .type = BLOBMSG_TYPE_INT32 }
};

static struct blobmsg_policy asterisk_call_log_delete_policy[] = {
	{ .name = "uniqueid", .type = BLOBMSG_TYPE_STRING }
};

static struct ubus_method asterisk_call_log_object_methods[] = {
	{
		.name = "list",
		.handler = ubus_asterisk_call_log_list_cb,
		.policy = asterisk_call_log_list_policy,
		.n_policy = ARRAY_SIZE(asterisk_call_log_list_policy)
	},
	{
		.name = "delete",
		.handler = ubus_asterisk_call_log_delete_cb,
		.policy = asterisk_call_log_delete_policy,
		.n_policy = ARRAY_SIZE(asterisk_call_log_delete_policy)
	}
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
	while (peer->account.id < SIP_ACCOUNT_UNKNOWN) {
		peer->ubus_object = &ubus_sip_peer_objects[peer->account.id];
		ret &= ubus_add_object(ctx, peer->ubus_object);
		peer++;
	}

	BRCM_PORT_MAP *port;
	port = brcm_ports;
	while (port->port != BRCM_PORT_ALL) {
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
static int ubus_send_brcm_event(struct ubus_context *ctx, const BRCM_PORT_MAP *port, const char *key, const char *value)
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
	if (line >= BRCM_PORT_UNKNOWN || line >= BRCM_PORT_ALL || line < 0) {
		return 1;
	}

	const BRCM_PORT_MAP *p = &(brcm_ports[line]);
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
	struct ubus_request_data *req,
	char *data,
	int ubus_lost)
{
	if (ubus_lost) {
		ast_log(LOG_WARNING, "Ubus context reset while waiting for response from asterisk\n");
		return 1;
	}

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
	ami_ctx = malloc(sizeof(struct ami_context));
	memset(ami_ctx, 0, sizeof(struct ami_context));
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

	BRCM_PORT_MAP *port;
	port = brcm_ports;
	while (port->port != BRCM_PORT_UNKNOWN) {
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
	struct ubus_request_data *req,
	char *data,
	int ubus_lost)
{
	if (ubus_lost) {
		ast_log(LOG_WARNING, "Ubus context reset while waiting for response from asterisk\n");
		return 1;
	}

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
	ami_ctx = malloc(sizeof(struct ami_context));
	memset(ami_ctx, 0, sizeof(struct ami_context));
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

	BRCM_PORT_MAP *port = brcm_ports;
	void *brcm_table = blobmsg_open_table(&bb, "brcm");
	while (port->port != BRCM_PORT_UNKNOWN && port->port != BRCM_PORT_ALL) {
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
	char *number_filter = NULL;
	char *type_filter = NULL;
	int maxresults = 0; /* Max number of results to return. 0 means unlimited. */

	blobmsg_parse(asterisk_call_log_list_policy,
			ARRAY_SIZE(asterisk_call_log_list_policy),
			tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	if (tb[0]) {
		number_filter = blobmsg_data(tb[0]);
	}

	if (tb[1]) {
		type_filter = blobmsg_data(tb[1]);
	}

	if (tb[2]) {
		maxresults = blobmsg_get_u32(tb[2]);
	}

	void *log = blobmsg_open_array(&bb, "call_log");

	/* Read CDRs one by one */
	FILE *mf = NULL;
	char buf[1024];
	/* Size large enough to capture longest comma seperated entry per row in cdr_csv file (cdr.h) */
	char token[256];
	char csvmaster[PATH_MAX];

	snprintf(csvmaster, sizeof(csvmaster),"%s/%s/%s", ast_config_AST_LOG_DIR, CSV_LOG_DIR, CSV_MASTER);

	if ((mf = fopen(csvmaster, "r")) == NULL) {
		ast_log(LOG_ERROR, "Unable to open master file %s : %s\n", csvmaster, strerror(errno));
		return -1;
	}

	/* Size should match the ones specified for struct "ast_cdr" (cdr.h) */
	char time[20];
	int duration;
	char disposition[32];
	char direction[16];
	char from[80];
	char to[80];
	char uniqueid[150];

	int numresults = 0; /* Number of rows included in results so far */

	static char delim = ',';

	while (fgets(buf, sizeof(buf), mf) != NULL) {
		/* reset variables */
		memset(time, 0, sizeof(time));
		duration = 0;
		memset(disposition, 0, sizeof(disposition));
		memset(direction, 0, sizeof(direction));
		memset(from, 0, sizeof(from));
		memset(to, 0, sizeof(to));

		/* reset CSV row parser state */
		char *start = buf;
		char *cursor = start;
		int inquotation = 0;
		int tokenindex = 0;

		while (cursor < (buf + sizeof(buf)) && *cursor) {
			if (inquotation) {
				if (cursor[0] == '"') {
					if (&cursor[1] < (buf + sizeof(buf)) && cursor[1] == '"') {
						/* quotation mark inside string */
						cursor += 2;
						continue;
					} else {
						/* exit quoted string */
						inquotation = 0;
					}
				}
			}
			else {
				if (cursor[0] == '"') {
					/* enter quoted string */
					inquotation = 1;
				}
				else if (cursor[0] == delim || cursor[0] == '\n') {
					/* found new token */
					memset(token, 0, sizeof(token));
					if (start[0] == '"') {
						/* strip quotations */
						strncpy(token, &start[1], (size_t)(cursor - start - 2));
					}
					else {
						strncpy(token, start, (size_t)(cursor - start));
					}

					switch (tokenindex) {
					case 1: /* src */
						strncpy(from, token, sizeof(from));
						break;
					case 2: /* dst */
						strncpy(to, token, sizeof(to));
						break;
					case 3: /* dcontext */
						if (strncmp(token, "sip", 3) == 0) {
							strncpy(direction, "OUTGOING", sizeof(direction));
						}
						else {
							strncpy(direction, "INCOMING", sizeof(direction));
						}
						break;
					case 9: /* start */
						strncpy(time, token, sizeof(time));
						break;
					case 13: /* billsec */
						duration = atoi(token);
						break;
					case 14: /* disposition */
						strncpy(disposition, token, sizeof(disposition));
						break;
					case 16: /* uniqueid */
						strncpy(uniqueid, token, sizeof(uniqueid));
						break;
					default:
						break;
					}

					start = cursor + sizeof(delim);
					tokenindex++;
				}
			}

			cursor++;
		}

		/* Process CDR */

		if (maxresults > 0 && numresults >= maxresults) {
			break;
		}

		/* This is always our number.
		 * For an incoming call it should be the to number.
		 * For an outgoing call it should be the from number.
		 */
		const char* our;

		if (strcmp(direction, "INCOMING") == 0) {
			our = to;
		}
		else {
			our = from;
		}

		/* If number filter is set to anything else than "all" our number
		 * must match exactly.
		 */
		if (number_filter && strcmp(number_filter, "all") != 0) {
			if (strcmp(number_filter, our) != 0) {
				continue;
			}
		}

		if (type_filter) {
			if (strcmp(type_filter, "outgoing") == 0) {
				if (strcmp(direction, "OUTGOING") != 0) {
					continue;
				}
			}
			else if (strcmp(type_filter, "incoming") == 0) {
				if (strcmp(direction, "INCOMING") != 0) {
					continue;
				}
			}
			else {
				/* Unsupported filter type */
				continue;
			}
		}

		void *e = blobmsg_open_table(&bb, NULL);
		blobmsg_add_string(&bb, "uniqueid", uniqueid);
		blobmsg_add_string(&bb, "time", time);
		blobmsg_add_u32(&bb, "duration", duration);
		blobmsg_add_string(&bb, "disposition", disposition);
		blobmsg_add_string(&bb, "direction", direction);
		blobmsg_add_string(&bb, "from", from);
		blobmsg_add_string(&bb, "to", to);
		blobmsg_close_table(&bb, e);

		numresults++;
	}

	fclose(mf);

	blobmsg_close_array(&bb, log);

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

/*
 * ubus callback that replies to "asterisk.call_log delete".
 */
static int ubus_asterisk_call_log_delete_cb (
	struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method,
	struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];
	char *uniqueid = NULL;

	blobmsg_parse(asterisk_call_log_delete_policy,
			ARRAY_SIZE(asterisk_call_log_delete_policy),
			tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	if (tb[0]) {
		uniqueid = blobmsg_data(tb[0]);
	}

	char cmd[128];

	if (uniqueid) {
		/* This is a bit ugly.
		 * CDRs can only be removed through the Asterisk CLI.
		 */
		snprintf(cmd, sizeof(cmd), "asterisk -rx \"cdr_csv remove cdr %s\"", uniqueid);
		system(cmd);
	}

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

static void res_voice_handle_registry_event(struct ubus_context *ctx, struct ami_event *event)
{
	SIP_PEER *peer = sip_peers;
	char* account_name = event->registry_event->account_name;

	//Lookup peer by account name
	while (peer->account.id < SIP_ACCOUNT_UNKNOWN) {
		if (!strcmp(peer->account.name, account_name)) {
			break;
		}
		peer++;
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
			system("ubus -t 1 call led.voice1 set \"{'state':'ok'}\"");
			if (ctx) {
				ubus_send_sip_event(ctx, peer, "registered", peer->sip_registry_registered);
				ubus_send_sip_event(ctx, peer, "registry_request_sent", peer->sip_registry_request_sent);
			}
			fw_manage(fw, peer, 1);
			break;
		case REGISTRY_UNREGISTERED_EVENT:
			ast_log(LOG_DEBUG, "sip registry unregistered\n");
			peer->sip_registry_registered = 0;
			peer->sip_registry_request_sent = 0;
			system("ubus -t 1 call led.voice1 set \"{'state':'off'}\"");
			if (ctx) {
				ubus_send_sip_event(ctx, peer, "registered", peer->sip_registry_registered);
				ubus_send_sip_event(ctx, peer, "registry_request_sent", peer->sip_registry_request_sent);
			}
			fw_manage(fw, peer, 0);
			break;
		case REGISTRY_REQUEST_SENT_EVENT:
			if (peer->sip_registry_request_sent == 1) {
				//This means we sent a "REGISTER" without receiving "Registered" event
				peer->sip_registry_registered = 0;
				fw_manage(fw, peer, 0);
			}
			peer->sip_registry_request_sent = 1;
			system("ubus -t 1 call led.voice1 set \"{'state':'off'}\"");
			if (ctx) {
				ubus_send_sip_event(ctx, peer, "registered", peer->sip_registry_registered);
				ubus_send_sip_event(ctx, peer, "registry_request_sent", peer->sip_registry_request_sent);
			}
			break;
		default:
			system("ubus -t 1 call led.voice1 set \"{'state':'off'}\"");
			break;
	}
}

static void res_voice_handle_registry_entry_event(struct ami_event *event)
{
	ast_log(LOG_NOTICE, "Got registry entry event for SIP account %s\n", event->registry_entry_event->host);
	SIP_PEER *peer = sip_peers;
	char* account_name = event->registry_entry_event->host;

	//Lookup peer by account name
	while (peer->account.id < SIP_ACCOUNT_UNKNOWN) {
		if (!strcmp(peer->account.name, account_name)) {
			break;
		}
		peer++;
	}

	if (peer->account.id == SIP_ACCOUNT_UNKNOWN) {
		ast_log(LOG_NOTICE, "RegistryEntry event for unknown account: %s\n", account_name);
		return;
	}

	//Update our sip peer with event information
	strncpy(peer->username, event->registry_entry_event->username, SIP_MAX_PEER_USERNAME);
	peer->username[SIP_MAX_PEER_USERNAME - 1]= '\0';
	strncpy(peer->domain, event->registry_entry_event->domain, SIP_MAX_PEER_DOMAIN);
	peer->domain[SIP_MAX_PEER_USERNAME - 1]= '\0';
	strncpy(peer->state, event->registry_entry_event->state, SIP_MAX_PEER_STATE);
	peer->state[SIP_MAX_PEER_USERNAME - 1]= '\0';
	peer->port = event->registry_entry_event->port;
	peer->domain_port = event->registry_entry_event->domain_port;
	peer->refresh = event->registry_entry_event->refresh;
	peer->registration_time = event->registry_entry_event->registration_time;
}

static void res_voice_handle_brcm_event(struct ami *mgr, struct ubus_context *ctx, struct ami_event *event)
{
	int line_id;
	int subchannel_id;

	SIP_PEER *peer = sip_peers;
	int registered_peer = 0;

	while (peer->account.id < SIP_ACCOUNT_UNKNOWN) {
		if (peer->sip_registry_registered)
			registered_peer++;
		peer++;
	}

	switch (event->brcm_event->type) {
		case BRCM_STATUS_EVENT:
			ast_log(LOG_DEBUG, "Got BRCM_STATUS_EVENT for %d, offhook = %d\n", event->brcm_event->status.line_id, event->brcm_event->status.off_hook);
			line_id = event->brcm_event->status.line_id;
			if (line_id >= 0 && line_id < BRCM_PORT_ALL) {
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

			if (line_id >= 0 && line_id < BRCM_PORT_ALL) {
				strcpy(brcm_ports[line_id].sub[subchannel_id].state, event->brcm_event->state.state);
				char* subchannel = !subchannel_id ? "0" : "1";

				if (strcmp(event->brcm_event->state.state, "ONHOOK") != 0 && strcmp(event->brcm_event->state.state, "CALLENDED") != 0)
					system("ubus -t 1 call led.voice1 set  \"{'state':'notice'}\"");
				else if (registered_peer > 0)
					system("ubus -t 1 call led.voice1 set  \"{'state':'ok'}\"");
				else
					system("ubus -t 1 call led.voice1 set  \"{'state':'off'}\"");
				if (ctx) {
					ubus_send_brcm_event(ctx, &brcm_ports[line_id], subchannel, brcm_ports[line_id].sub[subchannel_id].state);
				}
			}
			else {
				ast_log(LOG_DEBUG, "Got BRCM Status event for unknown line %d\n", line_id);
			}
			break;
		case BRCM_MODULE_EVENT:
			set_brcm_loaded(event->brcm_event->module_loaded);

			if (leds) {
				leds_set_ready(leds, all_modules_loaded());
			}
			break;
		default:
			break;
	}
}

static void res_voice_handle_sip_event(struct ami *mgr, struct ubus_context *ctx, struct ami_event *event)
{
	switch (event->sip_event->type) {
		case SIP_MODULE_EVENT:
			set_sip_loaded(event->sip_event->module_loaded);

			if (leds) {
				leds_set_ready(leds, all_modules_loaded());
			}
			break;
		default:
			break;
	}
}

static void res_voice_handle_varset_event(struct ubus_context *ctx, struct ami_event *event)
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
static void res_voice_handle_ami_event(struct ami *mgr, struct ubus_context *ctx, struct ami_event *event)
{
	switch (event->type) {
	case REGISTRY:
		res_voice_handle_registry_event(ctx, event);
		ami_action_send_sip_show_registry(mgr);
		break;
	case REGISTRY_ENTRY:
		res_voice_handle_registry_entry_event(event);
		break;
	case BRCM:
		res_voice_handle_brcm_event(mgr, ctx, event);
		break;
	case SIP:
		res_voice_handle_sip_event(mgr, ctx, event);
		break;
	case CHANNELRELOAD:
		if (event->channel_reload_event->channel_type == CHANNELRELOAD_SIP_EVENT) {
			ast_log(LOG_DEBUG, "SIP channel was reloaded\n");
			sip_peer_init_all(sip_peers); //SIP has reloaded, initialize sip peer structs
			if (leds) {
				leds_configure(leds);
			}
		}
		break;
	case VARSET:
		res_voice_handle_varset_event(ctx, event);
		break;
	case REGISTRATIONS_COMPLETE:
		//No action required
		break;
	case FULLYBOOTED:
		//No action required
		break;
	case UNKNOWN_EVENT:
		break; //An event that ami_parser could not handle
	default:
		break; //An event that we don't care about
	}

	if (leds) {
		leds_manage(leds);
	}
}

static void res_voice_handle_ami_response(struct ami *mgr, struct ubus_context *ctx, struct ami_response *resp)
{
	struct ami_context *ami_ctx;
	if (resp->userdata) {
		ami_ctx = (struct ami_context *)resp->userdata;
		if (ami_ctx->handle_response) {
			ami_ctx->handle_response(&ami_ctx->req, resp->response, ami_ctx->ubus_ctx_lost);
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
			res_voice_handle_ami_event(mgr, ctx, message->event);
			break;
		case RESPONSE_MESSAGE:
			res_voice_handle_ami_response(mgr, ctx, message->response);
			break;
		default:
			break; //Message ignored
		}
		ami_message_free(message);
	}
}

static void ami_refresh_action(void *userdata)
{
	struct ami_context *ami_ctx;

	if (!userdata) {
		return;
	}

	if (!ctx) {
		ami_ctx = (struct ami_context *) userdata;
		ami_ctx->ubus_ctx_lost = 1;
	}
}

static int module_show_brcm_request(void)
{
	ast_log(LOG_DEBUG, "Requesting BRCM load status\n");
	struct ami_context *ami_ctx;
	ami_ctx = malloc(sizeof(struct ami_context));
	memset(ami_ctx, 0, sizeof(struct ami_context));
	ami_ctx->handle_response = module_show_brcm_handle_response_cb;

	ami_send_module_show_brcm(mgr, ami_ctx);

	return 0;
}

static int module_show_brcm_handle_response_cb(
	struct ubus_request_data *req,
	char *data,
	int ubus_lost)
{
	if (strstr(data, "1 modules loaded")) {
		ast_log(LOG_DEBUG, "BRCM channel driver is loaded\n");
		brcm_ports_show_request();
		set_brcm_loaded(1);
	}
	else {
		ast_log(LOG_DEBUG, "BRCM channel driver is not loaded\n");
		set_brcm_loaded(0);
	}

	if (leds) {
		leds_set_ready(leds, all_modules_loaded());
	}

	return 0;
}

int brcm_ports_show_request(void)
{
	struct ami_context *ami_ctx;
	ami_ctx = malloc(sizeof(struct ami_context));
	memset(ami_ctx, 0, sizeof(struct ami_context));
	ami_ctx->handle_response = brcm_ports_show_response_cb;

	ami_send_brcm_ports_show(mgr, ami_ctx);

	return 0;
}

int brcm_ports_show_response_cb(
	struct ubus_request_data *req,
	char *data,
	int ubus_lost)
{

	int result = 1;
	int fxs_line_count = 0;
	int dect_line_count = 0;

	char* fxs_needle = strstr(data, "FXS");
	if (fxs_needle == NULL) {
		ast_log(LOG_ERROR, "Could not find number of FXS ports\n");
		result = 0;
	}
	else {
		fxs_line_count = strtol(fxs_needle + 4, NULL, 10);
		ast_log(LOG_DEBUG, "Found %d FXS ports\n", fxs_line_count);
	}

	char* dect_needle = strstr(data, "DECT");
	if (dect_needle == NULL) {
		ast_log(LOG_ERROR, "Could not find number of DECT ports\n");
		result = 0;
	}
	else {
		dect_line_count = strtol(dect_needle + 5, NULL, 10);
		ast_log(LOG_DEBUG, "Found %d DECT ports\n", dect_line_count);
	}

	if (result) {
		if (leds &&
				(leds_fxs_line_count(leds) != fxs_line_count || leds_dect_line_count(leds) != dect_line_count))
		{
			/* This will most likely not be reached */
			leds_delete(leds);
			leds = NULL;
		}

		if (!leds) {
			/* No previous leds struct (probably booting up) or a change in configuration.
			 * All information needed for led is now gathered, create leds struct */
			leds = leds_create(ctx,
					sip_peers,
					brcm_ports,
					fxs_line_count,
					dect_line_count,
					all_modules_loaded());
		}
	}

	return result;
}

int module_show_sip_request(void)
{
	ast_log(LOG_DEBUG, "Requesting SIP load status\n");
	struct ami_context *ami_ctx;
	ami_ctx = malloc(sizeof(struct ami_context));
	memset(ami_ctx, 0, sizeof(struct ami_context));
	ami_ctx->handle_response = module_show_sip_handle_response_cb;

	ami_send_module_show_sip(mgr, ami_ctx);

	return 0;
}

int module_show_sip_handle_response_cb(
	struct ubus_request_data *req,
	char *data,
	int ubus_lost)
{
	if (strstr(data, "1 modules loaded")) {
		set_sip_loaded(1);
	}
	else {
		set_sip_loaded(0);
	}

	if (leds) {
		leds_set_ready(leds, all_modules_loaded());
	}

	return 0;
}

static void set_brcm_loaded(unsigned int loaded)
{
	brcm_timestamp = time(NULL);

	if (loaded) {
		ast_set_flag(&modules_loaded, CHAN_BRCM_LOADED);
	}
	else {
		ast_clear_flag(&modules_loaded, CHAN_BRCM_LOADED);
	}

	ast_log(LOG_NOTICE, "chan_brcm is %sloaded\n",
			ast_test_flag(&modules_loaded, CHAN_BRCM_LOADED) ? "" : "not ");
}

static void set_sip_loaded(unsigned int loaded)
{
	sip_timestamp = time(NULL);

	if (loaded) {
		ast_set_flag(&modules_loaded, CHAN_SIP_LOADED);
		ami_action_send_sip_reload(mgr);
	}
	else {
		ast_clear_flag(&modules_loaded, CHAN_SIP_LOADED);
	}

	ast_log(LOG_NOTICE, "chan_sip is %sloaded\n",
			ast_test_flag(&modules_loaded, CHAN_SIP_LOADED) ? "" : "not ");
}

//Request chan_sip status if needed
static void sip_module_status_refresh(void)
{
	if (ast_test_flag(&modules_loaded, CHAN_SIP_LOADED)) {
		return;
	}

	time_t now = time(NULL);
	if (now >= (sip_timestamp + MODULE_SHOW_INTERVAL_S)) {
		sip_timestamp = now;
		module_show_sip_request();
	}
}

//Request chan_brcm status if needed
static void brcm_module_status_refresh(void)
{
	if (ast_test_flag(&modules_loaded, CHAN_BRCM_LOADED)) {
		return;
	}

	time_t now = time(NULL);
	if (now >= (brcm_timestamp + MODULE_SHOW_INTERVAL_S)) {
		brcm_timestamp = now;
		module_show_brcm_request();
	}
}

static int all_modules_loaded(void)
{
	return ast_test_flag(&modules_loaded, CHAN_SIP_LOADED) &&
			ast_test_flag(&modules_loaded, CHAN_BRCM_LOADED);
}

static int ubus_load(void)
{
	running = 1;
	if (ast_pthread_create_detached_background(&res_voice_thread_handle, NULL, res_voice_thread, NULL) < 0) {
		//Could not start thread
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

static int ubus_unload(void)
{
	if (running) {
		running = 0;
		while (pthread_kill(res_voice_thread_handle, SIGURG) == 0) {
			sched_yield();
		}
		pthread_join(res_voice_thread_handle, NULL);
	}
	res_voice_thread_handle = AST_PTHREADT_STOP;

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

