#include "asterisk.h"
#include "asterisk/module.h"
#include "asterisk/manager.h"
#include "asterisk/config.h"

#include "ubus/manager_listener.h"

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <pthread.h>
#include <signal.h>

static void *ubus_thread(void *arg);

static struct ubus_context *ubus_setup(void);
static void ubus_disconnect(struct ubus_context **ctx);
static void ubus_connection_lost_cb(struct ubus_context *ctx);
static int ubus_add_objects(struct ubus_context *ctx);
static void system_fd_set_cloexec(int fd);
static int ubus_connected = 0;

static void manager_handle_event(struct manager_listener *mgr, int fd);

static int running = 0;
static pthread_t ubus_thread_handle;


/****************************/
/* UBUS interface functions */
/****************************/

// Main thread
static void *ubus_thread(void *arg)
{
	struct ubus_context* ctx;		// ubus context
	struct manager_listener* mgr;	// manager listener context
	int mgr_fd[2];

	fd_set fset;				// FD set
	struct timeval timeout;		// Timeout for select
	int rv;						// select() return value

	// Setup
	ctx = ubus_setup();
	if (pipe(mgr_fd) < 0) {
		ast_log(LOG_ERROR, "Failed to open pipe: %s\n", strerror(errno));
		return NULL;
	}
	mgr = manager_listener_setup(mgr_fd[1]);

	while (running) {
		FD_ZERO(&fset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		FD_SET(mgr_fd[0], &fset);
		if (ubus_connected) {
			FD_SET(ctx->sock.fd, &fset);
		}

		// Wait for events from ubus or manager
		rv = select(FD_SETSIZE, &fset, NULL, NULL, &timeout);
		ast_log(LOG_ERROR, "tick\n");
		if(rv < 0) {
			if (errno == EINTR) {
				continue;
			}
			ast_log(LOG_ERROR, "error: %s\n", strerror(errno));
			ubus_disconnect(&ctx);
		}

		if (ubus_connected && FD_ISSET(ctx->sock.fd, &fset)) {
			// Connected to ubus and data available
			ubus_handle_event(ctx);
		}
		else if (!ubus_connected) {
			// Try to setup ubus connection again
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
			// New manager data available
			manager_handle_event(mgr, mgr_fd[0]);
		}
	}

	// Teardown
	manager_listener_free(mgr);
	if (ctx) {
		ubus_disconnect(&ctx);
	}

	return NULL;
}

// Initialize ubus connection and register asterisk object
static struct ubus_context *ubus_setup(void)
{
	return NULL;
	struct ubus_context *ctx = NULL;

	ast_log(LOG_DEBUG, "Connecting to UBUS\n");
	ubus_connected = 0;
	ctx = ubus_connect(NULL);

	if (ctx) {
		ctx->connection_lost = ubus_connection_lost_cb;
		system_fd_set_cloexec(ctx->sock.fd);
		int ret = ubus_add_objects(ctx);
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

static int ubus_asterisk_status_cb(struct ubus_context *ctx,
		struct ubus_object *obj,
		struct ubus_request_data *req,
		const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__UBUS_ARGMAX];
	blobmsg_parse(ubus_string_argument, __UBUS_ARGMAX, tb, blob_data(msg), blob_len(msg));
	blob_buf_init(&bb, 0);

	blobmsg_add_u8(&bb, "registered", 1);

	ubus_send_reply(ctx, req, bb.head);
	return 0;
}

static struct ubus_method asterisk_object_methods[] =
{
	{ .name = "status", .handler = ubus_asterisk_status_cb },
};

static struct ubus_object_type asterisk_object_type = UBUS_OBJECT_TYPE("asterisk_object", asterisk_object_methods);

static struct ubus_object ubus_asterisk_object =
{
		.name = "asterisk",
		.type = &asterisk_object_type,
		.methods = asterisk_object_methods,
		.n_methods = ARRAY_SIZE(asterisk_object_methods)
};

static int ubus_add_objects(struct ubus_context *ctx)
{
	int ret = 0;

	ret = ubus_add_object(ctx, &ubus_asterisk_object);

	return ret;
}


/*****************************************/
/* Asterisk module and manager interface */
/*****************************************/

void manager_handle_event(struct manager_listener *mgr, int fd)
{
	char c;

	if (read(fd, &c, sizeof(char)) < 0) {
		ast_log(LOG_ERROR, "Failed to read manager fd: %s\n", strerror(errno));
	}
	else {
		struct manager_listener_data *data;
		while ((data = manager_listener_get_next_data(mgr))) {
			ast_log(LOG_DEBUG, "Got: [%d] [%s] [%s]\n",
					manager_listener_data_get_category(data),
					manager_listener_data_get_event(data),
					manager_listener_data_get_content(data));

			//TODO

			manager_listener_data_free(data);
		}
	}
}

static int ubus_load(void)
{
	running = 1;
	if (ast_pthread_create_detached_background(&ubus_thread_handle, NULL, ubus_thread, NULL) < 0) {
		// Could not start thread
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

