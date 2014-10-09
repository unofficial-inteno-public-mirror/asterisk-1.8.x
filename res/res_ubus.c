#include "asterisk.h"
#include "asterisk/module.h"
#include "asterisk/config.h"

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

static void *ubus_thread(void *arg);
static struct ubus_context *ubus_setup(void);
static void ubus_disconnect(struct ubus_context **ctx);
static void ubus_connection_lost_cb(struct ubus_context *ctx);
static int ubus_add_objects(struct ubus_context *ctx);
static void system_fd_set_cloexec(int fd);

static bool running = false;
static pthread_t ubus_thread_handle;
static bool ubus_connected = false;


/****************************/
/* UBUS interface functions */
/****************************/

/* Main thread */
static void *ubus_thread(void *arg)
{
	struct ubus_context* ctx;	/* ubus context */

	fd_set fset;				/* FD set */
	struct timeval timeout;		/* Timeout for select */
	int rv;						/* Select return value */

	/* Initialize */
	ctx = ubus_setup();

	while (running) {
		FD_ZERO(&fset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		if (ubus_connected) {
			FD_SET(ctx->sock.fd, &fset);
		}

		/* Wait for events from ubus */
		ast_log(LOG_ERROR, "ubus select\n");
		rv = select(FD_SETSIZE, &fset, NULL, NULL, &timeout);
		if(rv < 0) {
			if (errno == EINTR) {
				continue;
			}
			ast_log(LOG_ERROR, "res_ubus error: %s\n", strerror(errno));
			ubus_disconnect(&ctx);
		}

		if (ubus_connected && FD_ISSET(ctx->sock.fd, &fset)) {
			/* Connected to ubus and data available */
			ubus_handle_event(ctx);
		}
		else if (!ubus_connected) {
			/* Try to setup ubus connection again */
			if (ctx && ubus_reconnect(ctx, NULL) == 0) {
				ast_log(LOG_DEBUG, "UBUS reconnected\n");
				ubus_connected = true;
				system_fd_set_cloexec(ctx->sock.fd);
			}
			else if (!ctx) {
				ctx = ubus_setup();
			}
		}
	}

	if (ctx) {
		ubus_disconnect(&ctx);
	}

	return NULL;
}

/* Initialize ubus connection and register asterisk object */
static struct ubus_context *ubus_setup(void)
{
	struct ubus_context *ctx = NULL;

	ast_log(LOG_DEBUG, "Connecting to UBUS\n");
	ubus_connected = false;
	ctx = ubus_connect(NULL);

	if (ctx) {
		ctx->connection_lost = ubus_connection_lost_cb;
		system_fd_set_cloexec(ctx->sock.fd);
		int ret = ubus_add_objects(ctx);
		if (ret != 0) {
			ubus_disconnect(&ctx);
		}
		else {
			ubus_connected = true;
		}
	}

	return ctx;
}

static void ubus_disconnect(struct ubus_context **ctx)
{
	ubus_free(*ctx);
	*ctx = NULL;
	ubus_connected = false;
}

static void ubus_connection_lost_cb(struct ubus_context *ctx)
{
	ast_log(LOG_WARNING, "UBUS connection lost\n");
	ubus_connected = false;
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


/********************/
/* Module interface */
/********************/

static int ubus_load(void)
{
	running = true;
	if (ast_pthread_create_detached_background(&ubus_thread_handle, NULL, ubus_thread, NULL) < 0) {
		/* Could not start thread */
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

