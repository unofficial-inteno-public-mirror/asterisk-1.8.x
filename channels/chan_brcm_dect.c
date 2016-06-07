
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 284597 $")

#include <math.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>


#define __AST_SELECT_H															// Prevent Asterisk from replacing libc FD_ZERO() with ugliness
#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/cli.h"
#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/utils.h"
#include "asterisk/callerid.h"
#include "asterisk/causes.h"
#include "asterisk/stringfields.h"
#include "asterisk/musiconhold.h"
#include "asterisk/indications.h"
#include "asterisk/manager.h"
#include "asterisk/sched.h"

#include "chan_brcm.h"
#include "chan_brcm_dect.h"

#include <libubus.h>

#define PAUSE_KEY	0x05
#define R_KEY		0x15


enum {
	CALL_TERM,																	// Terminal ID
	CALL_ADD,																	// Add call using PCMx
	CALL_REL,																	// Release call using PCMx
	CALL_CID,																	// Caller ID
};


enum {
	DIAL_TERM,																	// Terminal ID
	DIAL_NUMB,																	// Dialed number
	DIAL_PCM,																	// Dial number via PCMx
};


static int dect_release(struct brcm_pvt *p);
static int notify_dectmngr_new_call(struct brcm_pvt *p);
static int dect_dummy(struct brcm_pvt *p);
static int notify_dectmngr_new_call_with_cid(const struct ast_channel *chan, struct brcm_subchannel *s);
static int ubus_request_call(struct ubus_context *ubus_ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *methodName, struct blob_attr *msg);
static int dectmngr_call(int terminal, int add, int release, const char *cid);


//-------------------------------------------------------------
static const char ubusSenderId[] = "asterisk.dect.api";							// The Ubus type we transmitt
static const char ubusIdDectmngr[] = "dect";									// The Ubus type for Dectmngr
static const char pathEndpoint[] = "/dev/bcmendpoint0";


static const struct blobmsg_policy ubusCallKeys[] = {							// ubus RPC "call" arguments (keys and values)
	[CALL_TERM] = { .name = "terminal", .type = BLOBMSG_TYPE_INT32 },
	[CALL_ADD] = { .name = "add", .type = BLOBMSG_TYPE_INT32 },
	[CALL_REL] = { .name = "release", .type = BLOBMSG_TYPE_INT32 },
	[CALL_CID] = { .name = "cid", .type = BLOBMSG_TYPE_STRING },
};


static const struct ubus_method ubusMethods[] = {								// ubus RPC methods
	UBUS_METHOD("call", ubus_request_call, ubusCallKeys),
};


static struct ubus_object_type rpcType[] = {
	UBUS_OBJECT_TYPE(ubusSenderId, ubusMethods)
};


static struct ubus_object rpcObj = {
	.name = ubusSenderId,
	.type = rpcType,
	.methods = ubusMethods,
	.n_methods = ARRAY_SIZE(ubusMethods)
};


extern VRG_ENDPT_STATE endptObjState[MAX_NUM_LINEID];
extern const DTMF_CHARNAME_MAP dtmf_to_charname[];
extern struct brcm_pvt *iflist;

const struct brcm_channel_tech dect_tech = {
	.signal_ringing = notify_dectmngr_new_call,
	.signal_ringing_callerid_pending = dect_dummy,
	.signal_callerid = notify_dectmngr_new_call_with_cid,
	.stop_ringing = dect_release,
	.stop_ringing_callerid_pending = dect_release,
	.release = dect_release,
};


/* Indication of whether Broadcom kernel endpoint dect
 * processing has been started. (Must be done only once.) */
static int hasEpDectProcStarted;



//-------------------------------------------------------------
static int bad_handsetnr(int handset) {
	if ((handset < 0) || (handset >= MAX_NR_HANDSETS)) {
		ast_verbose("Bad handset nr: %d\n", handset);
		return 1;
	}
	return 0;
}


//-------------------------------------------------------------
// Unused but must exist
static int dect_dummy(struct brcm_pvt *p) { return 0; }


//-------------------------------------------------------------
// New incomming SIP call with a caller ID. Notify
// Dectmngr so a hanset will start ringing.
static int notify_dectmngr_new_call_with_cid(const struct ast_channel *chan, struct brcm_subchannel *s) {
	const char *cid;
	int handset;

	handset = s->parent->line_id + 1;
	cid = NULL;

	if(bad_handsetnr(handset)) return 1;

	if(chan->connected.id.number.valid) {
		ast_verbose("notify_dectmngr_new_call_with_cid(): %s\n", chan->connected.id.number.str);	
		cid = chan->connected.id.number.str;
	}

	return dectmngr_call(s->parent->line_id + 1, s->parent->line_id, -1, cid);
}



//-------------------------------------------------------------
// New incomming SIP call (without caller ID). Notify
// Dectmngr so a hanset will start ringing.
static int notify_dectmngr_new_call(struct brcm_pvt *p)
{
	ast_verbose("notify_dectmngr_new_call()\n");
	ast_verbose("line_id: %d\n", p->line_id); 

	return dectmngr_call(p->line_id + 1, p->line_id, -1, NULL);
}



//-------------------------------------------------------------
// Notify Broadcom endpoint of Dect handset on hook
// and off hook events.
static EPSTATUS vrgEndptSendCasEvtToEndpt(ENDPT_STATE *endptState, CAS_CTL_EVENT_TYPE eventType, CAS_CTL_EVENT event) {
	ENDPOINTDRV_SENDCASEVT_CMD_PARM tCasCtlEvtParm;
	int fd, res;

	tCasCtlEvtParm.epStatus      = EPSTATUS_DRIVER_ERROR;
	tCasCtlEvtParm.casCtlEvtType = eventType;
	tCasCtlEvtParm.casCtlEvt     = event;
	tCasCtlEvtParm.lineId        = endptState->lineId;
	tCasCtlEvtParm.size          = sizeof(ENDPOINTDRV_SENDCASEVT_CMD_PARM);

	res = 0;
	fd = open(pathEndpoint, O_RDWR);
	if(fd == -1) {
		ast_verbose("%s: error opening %s\n", __FUNCTION__, pathEndpoint);
		res = -1;
	}
	else if(ioctl(fd, ENDPOINTIOCTL_SEND_CAS_EVT, &tCasCtlEvtParm ) != IOCTL_STATUS_SUCCESS) {
		ast_verbose("%s: error during ioctl %s\n", __FUNCTION__, pathEndpoint);
		res = -1;
	}

	if(fd > 0) close(fd);

	if(!tCasCtlEvtParm.epStatus && res) {
		tCasCtlEvtParm.epStatus = EPSTATUS_DRIVER_ERROR;
	}

	return tCasCtlEvtParm.epStatus;
}



//-------------------------------------------------------------
// Try to start kernel internal dect procesing in endpoint
// driver. This is relevant only for targets with internal
// Dect so we need to probe for what HW is in use.
static EPSTATUS endptProcCtl(EPCONSOLECMD cmd) {
	ENDPOINTDRV_CONSOLE_CMD_PARM tConsoleParm;
	EPCMD_PARMS consoleCmdParams;
	ENDPT_STATE endptState;
	int fd, res;
	
	if(hasEpDectProcStarted) return EPSTATUS_SUCCESS;							// Only start once

	/* Probe for SoC internal Dect. Do nothing
	 * if it's missing. */
	fd = open("/dev/dect", O_RDWR);
	if(fd == -1 && (errno == ENXIO || errno == ENODEV)) {
		ast_verbose("External Dect detected\n");
		hasEpDectProcStarted = 1;
		return EPSTATUS_SUCCESS;
	}
	if(fd > 0) close(fd);

	memset(&consoleCmdParams,0, sizeof(consoleCmdParams));
	memset(&endptState, 0, sizeof(endptState));
	memset(&tConsoleParm, 0, sizeof(tConsoleParm));
	tConsoleParm.state = &endptState;
	tConsoleParm.cmd = cmd;
	tConsoleParm.lineId = endptState.lineId;
	tConsoleParm.consoleCmdParams = &consoleCmdParams;
	tConsoleParm.epStatus = EPSTATUS_DRIVER_ERROR;
	tConsoleParm.size = sizeof(tConsoleParm);
	res = 0;

	fd = open(pathEndpoint, O_RDWR);
	if(fd == -1) {
		 ast_log(LOG_WARNING, "%s: error opening %s\n", __FUNCTION__, pathEndpoint);
		res = -1;
	}
	else if(ioctl(fd, ENDPOINTIOCTL_ENDPT_CONSOLE_CMD, &tConsoleParm) !=
			IOCTL_STATUS_SUCCESS) {
		ast_verbose("%s: error during ioctl %s\n", __FUNCTION__, pathEndpoint);
		res = -1;
	}

	if(fd > 0) close(fd);

	if(!tConsoleParm.epStatus && res) {
		tConsoleParm.epStatus = EPSTATUS_DRIVER_ERROR;
	}

	if(tConsoleParm.epStatus) {
		ast_log(LOG_WARNING, "Failed to start endpoint dect processing\n");
	}
	else {
		ast_verbose("Internal Dect detected\n");
	}

	hasEpDectProcStarted = 1;

	return EPSTATUS_SUCCESS;
}



//-------------------------------------------------------------
static int dect_release(struct brcm_pvt * p) {
	int handset = p->line_id + 1;

	ast_verbose("dect_release: %d\n", handset);

	if (bad_handsetnr(handset)) {
		return 1;
	}
	
	return dectmngr_call(-1, -1, p->line_id, NULL);
}



//-------------------------------------------------------------
// Got a ubus call from dectmngr that user
// has pressed keys and dialed a number. (The
// audio should already be setup.)
static int userDials(int termId, const char *number, int pcm)
{
	struct ast_channel *savedOwner, *savedPeerOwner;
	struct brcm_subchannel *sub, *sub_peer;
	struct brcm_pvt *pvt;
	int i;

	pvt = brcm_get_pvt_from_lineid(iflist, pcm);
	if (!pvt) {
		ast_verbose("no pvt!\n");
		return -1;
	}
	
	/* Abandon all hope ye who enter here. */
	for (i = 0; i < strlen(number); i++) {

		// Verify user digits and map to events
		const DTMF_CHARNAME_MAP *dtmfMap = dtmf_to_charname;
		if(!number[i]) continue;
		while(dtmfMap->event != EPEVT_LAST && number[i] != dtmfMap->c &&
				number[i] != R_KEY && number[i] != PAUSE_KEY) {
			dtmfMap++;
		}
		if(dtmfMap->event == EPEVT_LAST) {
				ast_log(LOG_WARNING, "Invalid DTMF %x\n", number[i]);
				continue;
		}

		/* Get locks in correct order */
		ast_mutex_lock(&pvt->lock);

		sub = brcm_get_active_subchannel(pvt);
		sub_peer = brcm_subchannel_get_peer(sub);
		savedOwner = sub->owner;
		savedPeerOwner = sub_peer->owner;
		
		if (sub->owner) {
			ast_channel_ref(sub->owner);
		}
		if (sub_peer->owner) {
			ast_channel_ref(sub_peer->owner);
		}
		ast_mutex_unlock(&pvt->lock);

		if (sub->owner && sub_peer->owner) {
			if (sub->owner < sub_peer->owner) {
				ast_channel_lock(sub->owner);
				ast_channel_lock(sub_peer->owner);
			}
			else {
				ast_channel_lock(sub_peer->owner);
				ast_channel_lock(sub->owner);
			}
		}
		else if (sub->owner) {
			ast_channel_lock(sub->owner);
		}
		else if (sub_peer->owner) {
			ast_channel_lock(sub_peer->owner);
		}
		ast_mutex_lock(&pvt->lock);
		
		// Pressed "R"?
		if (number[i] == R_KEY) {
			/* Hookflash */
			pvt->hf_detected = 1;
			handle_hookflash(sub, sub_peer, sub->owner, sub_peer->owner);
		}
		else if (number[i] == PAUSE_KEY) {
			/* How to forward a pause digit to the
			 * SIP channel, as in RFC4967? */
			usleep(500000);
		}
		else {
			/* Send DTMF digit event to Asterisk core */
			unsigned int old_state = sub->channel_state;

			// Send two events: press and depress.
			handle_dtmf(dtmfMap->event, sub, sub_peer, sub->owner, sub_peer->owner);
			handle_dtmf(dtmfMap->event, sub, sub_peer, sub->owner, sub_peer->owner);

			if (sub->channel_state == DIALING) {
				if(old_state != sub->channel_state) {
					/* DTMF event took channel state to
					 * DIALING. Stop dial tone. */
					ast_log(LOG_DEBUG, "Dialing. Stop dialtone.\n");
					brcm_stop_dialtone(pvt);
				}
				handle_dtmf_calling(sub);
			}

			if (brcm_should_relay_dtmf(sub)) {
				switch (get_dtmf_relay_type(sub)) {
					case EPDTMFRFC2833_DISABLED:
						ast_debug(5, "Generating inband DTMF for DECT\n");
						brcm_signal_dtmf_ingress(sub, dtmfMap->i);
						break;
					case EPDTMFRFC2833_ENABLED:
					case EPDTMFRFC2833_SUBTRACT: {
						struct ast_frame f;
						memset(&f, 0, sizeof(f));
						f.subclass.integer = dtmfMap->c;
						f.src = "BRCM";
						f.frametype = AST_FRAME_DTMF_END;
						if (sub->owner) ast_queue_frame(sub->owner, &f);
						break;
					}
					default:
						ast_log(LOG_WARNING, "DTMF mode unknown\n");
						break;
				}
			}
		}

		// Release locks
		ast_mutex_unlock(&pvt->lock);

		if (savedOwner) {
			ast_channel_unlock(savedOwner);
			ast_channel_unref(savedOwner);
		}
		if (savedPeerOwner) {
			ast_channel_unlock(savedPeerOwner);
			ast_channel_unref(savedPeerOwner);
		}
	}

	return 0;
}



//-------------------------------------------------------------
// Block and wait for incomming ubus events. uloop
// doesn't work with threads.
static int ubus_poll(struct ubus_context *ctx, int oneShot) {
	fd_set readFds;
	int ret;

	do {
		FD_ZERO(&readFds);
		FD_SET(ctx->sock.fd, &readFds);

		ret = select(ctx->sock.fd + 1, &readFds, NULL, NULL, NULL);

		if(ret == -1 && errno != EINTR) {
			perror("Error waiting for ubus events");
			break;
		}
		else if(ret > 0) {
			ret = 0;

			if(FD_ISSET(ctx->sock.fd, &readFds)) {
				ubus_handle_event(ctx);
			}
		}
	} while(!oneShot);

	return ret;
}



//-------------------------------------------------------------
static int ast_ubus_listen(struct ubus_context *ctx) {
	int ret = 0;

	// Invoke our RPC handler when ubus calls (not events) arrive
	if(ubus_add_object(ctx, &rpcObj) != UBUS_STATUS_OK) {
		ast_verbose("Error registering ubus object");
		return -1;
	}

	// main loop, listen for ubus events
	ret = ubus_poll(ctx, 0);

	ubus_remove_object(ctx, &rpcObj);
	ubus_free(ctx);

	ret = 0;
	pthread_exit(&ret);
}



//-------------------------------------------------------------
// Send a reply for when someone has called us with a request.
static int ubus_reply(struct ubus_context *ubus_ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *methodName, struct blob_attr *msg,
		uint32_t err, int terminal, int pcmId) {
	struct blob_buf blob;

	memset(&blob, 0, sizeof(blob));
	if(blobmsg_buf_init(&blob)) return -1;

	blobmsg_add_u32(&blob, ubusCallKeys[CALL_TERM].name, terminal);
	blobmsg_add_u32(&blob, "pcm", pcmId);
	blobmsg_add_u32(&blob, "errno", err);
	blobmsg_add_string(&blob, "errstr", strerror(err));
	blobmsg_add_string(&blob, "method", methodName);

	ubus_send_reply(ubus_ctx, req, blob.head);
	blob_buf_free(&blob);

	return UBUS_STATUS_OK;
}


//-------------------------------------------------------------
// Callback for: a ubus call (invocation) has replied with some data
static void call_answer(struct ubus_request *req, int type, struct blob_attr *msg)
{
	ast_verbose("ubus call_answer()\n");
}


//-------------------------------------------------------------
// Callback for: a ubus call (invocation) has finished
static void call_complete(struct ubus_request *req, int ret)
{
	ast_verbose("ubus call_complete()\n");
	free(req);
}



//-------------------------------------------------------------
// Tokenize RPC message key/value paris into an array
static int keyTokenize(struct ubus_object *obj, const char *methodName,
		struct blob_attr *msg, struct blob_attr ***keys)
{
	const struct ubus_method *search;

	// Find the ubus policy for the called method
	for(search = obj->methods; strcmp(search->name, methodName); search++);
	*keys = malloc(search->n_policy * sizeof(struct blob_attr*));
	if(!*keys) return UBUS_STATUS_INVALID_ARGUMENT;

	// Tokenize message into an array
	if(blobmsg_parse(search->policy, search->n_policy, *keys, 
			blob_data(msg), blob_len(msg))) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return UBUS_STATUS_OK;
}



//-------------------------------------------------------------
// RPC handler for
// ubus call asterisk.dect.api call '{....}'
static int ubus_request_call(struct ubus_context *ubus_ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *methodName, struct blob_attr *msg)
{
	int res, termId, pcmId, add, release;
	struct blob_attr **keys;
	const char *cid;

	res = 0;
	termId = -1;
	pcmId = -1;
	add = 0;
	release = 0;
	cid = NULL;

	// Tokenize message key/value paris into an array
	res = keyTokenize(obj, methodName, msg, &keys);
	if(res != UBUS_STATUS_OK) goto out;

	// Handle RPC:
	// ubus call asterisk.dect.api call '{ "terminal": 1 }'
	if(keys[CALL_TERM]) {
		termId = blobmsg_get_u32(keys[CALL_TERM]);
		ast_verbose("call terminal %d\n", termId);
	}

	// Handle RPC:
	// ubus call asterisk.dect.api call '{ "add": 1 }'
	if(keys[CALL_ADD]) {
		add = 1;
		pcmId = blobmsg_get_u32(keys[CALL_ADD]);
		ast_verbose("call add pcm %d\n", pcmId);
	}

	if(keys[CALL_REL]) {
		release = 1;
		pcmId = blobmsg_get_u32(keys[CALL_REL]);
		ast_verbose("call release pcm %d\n", pcmId);
	}

	if(keys[CALL_CID]) {
		cid = blobmsg_get_string(keys[CALL_CID]);
		ast_verbose("call cid %s\n", cid);
	}

	// Did we get all arguments we need?
	if(bad_handsetnr(termId) || pcmId < 0 || (cid && cid[strnlen(cid, 64)])) {
		res = EINVAL;
	}
	else if(release) {
		if(vrgEndptSendCasEvtToEndpt(
				(ENDPT_STATE*) &(endptObjState[pcmId]),							/* Signal onhook to endpoint driver */
				CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_ONHOOK)) {
			res = EIO;
		}
	}
	else if(add) {
		if(endptProcCtl(EPCMD_DECT_START_BUFF_PROC)) {
			res = EIO;
		}
		else {
			if(cid) {
				res = userDials(termId, cid, pcmId);							// User dials digits
			}
			else if(vrgEndptSendCasEvtToEndpt(
					(ENDPT_STATE*) &(endptObjState[pcmId]),						/* Signal offhook to endpoint driver */
					CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_OFFHOOK)) {
				res = EIO;
			}
		}
	}
	else {
		res = EINVAL;
	}

	ubus_reply(ubus_ctx, obj, req, methodName, msg, res, termId, pcmId);

out:
	free(keys);
	return res;
}



//-------------------------------------------------------------
// Send a ubus request to Dectmngr. This function is
// executed by another thread than brcm_monitor_dect().
static int dectmngr_call(int terminal, int add, int release, const char *cid) {
	struct ubus_request *req;
	struct ubus_context *ctx;
	struct blob_buf blob;
	uint32_t id;
	int res;

	// Create a binary ubus message
	res = 0;
	memset(&blob, 0, sizeof(blob));
	if(blob_buf_init(&blob, 0)) {
		res = -1;
		goto err1;
	}
	if(terminal >= 0) blobmsg_add_u32(&blob, ubusCallKeys[CALL_TERM].name, terminal);
	if(add >= 0) blobmsg_add_u32(&blob, ubusCallKeys[CALL_ADD].name, add);
	if(release >= 0) blobmsg_add_u32(&blob, ubusCallKeys[CALL_REL].name, release);
	if(cid) blobmsg_add_string(&blob, ubusCallKeys[CALL_CID].name, cid);
ast_verbose("Sending ubus request %d %d %d\n", terminal, add, release);

	/* In the event we are called from a thread which
	 * commuicate with ubus for the first time we need
	 * to init ubus first. */
	ctx = ubus_connect(NULL);
	if (!ctx || !ctx->sock.fd) {
		ast_verbose("Failed to connect to ubus\n");
		res = -1;
		goto err2;
	}

// TODO
//ctx->connection_lost = my_custom_cb_to_replace_the_default;

	// Find id number for ubus "path"
	res = ubus_lookup_id(ctx, ubusIdDectmngr, &id);
	if(res != UBUS_STATUS_OK) {
		ast_verbose("Error searching for usbus path %s\n", ubusIdDectmngr);
		res = -1;
		goto out;
	}

	// Call remote method
	req = calloc(1, sizeof(struct ubus_request));
	if(!req) return -1;
	res = ubus_invoke_async(ctx, id, ubusMethods[0].name, blob.head, req);
	if(res != UBUS_STATUS_OK) {
		ast_verbose("Error invoking method: %s %d\n", ubusMethods[0].name, res);
		res = -1;
		goto out;
	}

	/* Mark the call as non blocking. When
	 * it completes we get "called back". */
	req->data_cb = call_answer;
	req->complete_cb = call_complete;
	req->priv = NULL;
	ubus_complete_request_async(ctx, req);
	res = ubus_poll(ctx, 1);

out:
	ubus_free(ctx);
err2:
	blob_buf_free(&blob);
err1:
	// In case of suspicious error above, terminate call
	if(res && !bad_handsetnr(terminal)) {
		vrgEndptSendCasEvtToEndpt((ENDPT_STATE*) &(endptObjState[terminal]),
			CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_ONHOOK);
	}
	
	return res;
}



//-------------------------------------------------------------
// Thread main
void *brcm_monitor_dect(void *data) { 
	struct ubus_context *ctx;

	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	hasEpDectProcStarted = 0;

	/* Initialize ubus connecton */
	ctx = ubus_connect(NULL);
	if (!ctx) {
		ast_verbose("Failed to connect to ubus\n");
		return (void*) -1;
	}

	ast_ubus_listen(ctx);
	ubus_free(ctx);
	ctx = 0;

	return 0;
}

