
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

#include <libubox/blobmsg_json.h>
#include <libubus.h>

#define R_KEY 0x15

extern VRG_ENDPT_STATE endptObjState[MAX_NUM_LINEID];
extern const DTMF_CHARNAME_MAP dtmf_to_charname[];
extern struct brcm_pvt *iflist;

struct dect_handset {
	enum channel_state state;
	char cid[CID_MAX_LEN];
};

struct dect_handset handsets[MAX_NR_HANDSETS];


const struct brcm_channel_tech dect_tech = {
	.signal_ringing = dect_signal_ringing,
	.signal_ringing_callerid_pending = dect_signal_ringing_callerid_pending,
	.signal_callerid = dect_signal_callerid,
	.stop_ringing = dect_release,
	.stop_ringing_callerid_pending = dect_release,
	.release = dect_release,
};



//-------------------------------------------------------------
static int bad_handsetnr(int handset) {
	if ((handset < 0) || (handset >= MAX_NR_HANDSETS)) {
		ast_verbose("Bad handset nr: %d\n", handset);
		return 1;
	}
	return 0;
}



//-------------------------------------------------------------
int dect_signal_ringing_callerid_pending(struct brcm_pvt *p) {
	dect_signal_ringing(p);
	return 0;
}



//-------------------------------------------------------------
int dect_signal_callerid(const struct ast_channel *chan, struct brcm_subchannel *s) {
	
	int handset = s->parent->line_id + 1;
	ast_verbose("Caller id: %s\n", chan->connected.id.number.str);
	
	if (bad_handsetnr(handset))
		return 1;
	
	strncpy(handsets[handset].cid, chan->connected.id.number.str, CID_MAX_LEN);

	return 0;
}



//-------------------------------------------------------------
int dect_signal_ringing(struct brcm_pvt *p)
{
	ast_verbose("dect_signal_ringing\n");
	ast_verbose("line_id: %d\n", p->line_id); 

	dect_ring_handset(p->line_id + 1);
	return 0;
}



//-------------------------------------------------------------
void dect_ring_handset(int handset) {

	if (bad_handsetnr(handset))
		return;


	ast_verbose("dect_ring_handset: %d\n", handset);
}



//-------------------------------------------------------------
EPSTATUS
vrgEndptSendCasEvtToEndpt(ENDPT_STATE *endptState, 
				   CAS_CTL_EVENT_TYPE eventType, 
				   CAS_CTL_EVENT event)
{
	ENDPOINTDRV_SENDCASEVT_CMD_PARM tCasCtlEvtParm;
	int fd;

	tCasCtlEvtParm.epStatus      = EPSTATUS_DRIVER_ERROR;
	tCasCtlEvtParm.casCtlEvtType = eventType;
	tCasCtlEvtParm.casCtlEvt     = event;
	tCasCtlEvtParm.lineId        = endptState->lineId;
	tCasCtlEvtParm.size          = sizeof(ENDPOINTDRV_SENDCASEVT_CMD_PARM);

	fd = open("/dev/bcmendpoint0", O_RDWR);

	if ( ioctl( fd, ENDPOINTIOCTL_SEND_CAS_EVT, &tCasCtlEvtParm ) != IOCTL_STATUS_SUCCESS )
		ast_verbose("%s: error during ioctl", __FUNCTION__);

	close(fd);
	return( tCasCtlEvtParm.epStatus );
}



//-------------------------------------------------------------
int dect_release(struct brcm_pvt * p) {
	int handset = p->line_id + 1;

	ast_verbose("dect_releaseQ: %d\n", handset);

	if (bad_handsetnr(handset)) {
		return 1;
	}
	
	return 0;
}



//-------------------------------------------------------------
void ast_ubus_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	char *str = NULL;
	if (msg)
		str = blobmsg_format_json(msg, true);

	if (type && str) {
		ast_verbose("{ \"%s\": %s }\n", type, str);

	}
	
	if (str)
		free(str);
}



//-------------------------------------------------------------
void info_ind(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	struct json_object *obj, *val;
	char *json, *dialed_nr;
	int terminal, endpt, i, j;
	struct brcm_pvt *p;
	struct brcm_subchannel *sub;

	ast_verbose("info_ind\n");
	json = blobmsg_format_json(msg, true);
	obj = json_tokener_parse(json);

	if( (json_object_object_get_ex(obj, "terminal", &val)) == true) {
		terminal = json_object_get_int(val);
		
		if (bad_handsetnr(terminal))
			return;
		
		ast_verbose("terminal: %d\n", terminal);
	} else {
		ast_verbose("no terminal id\n");
		return;
	}

	if( (json_object_object_get_ex(obj, "dialed_nr", &val)) == true) {
		dialed_nr = json_object_get_string(val);
	} else {
		ast_verbose("no dialed nr\n");
		return;
	}
	
	ast_verbose("dialed_nr: %s\n", dialed_nr);
	endpt = terminal;
	p = brcm_get_pvt_from_lineid(iflist, endpt);
	
	if (!p) {
		ast_verbose("no pvt!\n");
		return;
	} else {
		ast_verbose("got pvt!\n");
	}

	
	/* Abandon all hope ye who enter here. */
	for (i = 0; i < strlen(dialed_nr); i++) {

		const DTMF_CHARNAME_MAP *dtmfMap = dtmf_to_charname;
		int rDetected = 0;


		while (dtmfMap->c != dialed_nr[i]) {
			
			dtmfMap++;
			if (dtmfMap->event == EPEVT_LAST) {

				if (R_KEY == dialed_nr[i]) {
					rDetected = 1;
					break;
				}

				/* DTMF not found. Should not be reached. */
				ast_log(LOG_WARNING, "Failed to handle DTMF. Event not found.\n");
				return;
			}
		}

		/* Get locks in correct order */
		ast_mutex_lock(&p->lock);

		struct brcm_subchannel *sub = brcm_get_active_subchannel(p);
		struct brcm_subchannel *sub_peer = brcm_subchannel_get_peer(sub);
		struct ast_channel *owner = sub->owner;
		struct ast_channel *peer_owner = sub_peer->owner;
		
		if (sub->owner) {
			ast_channel_ref(owner);
		}
		if (sub_peer->owner) {
			ast_channel_ref(peer_owner);
		}
		ast_mutex_unlock(&p->lock);

		if (owner && peer_owner) {
			if (owner < peer_owner) {
				ast_channel_lock(owner);
				ast_channel_lock(peer_owner);
			}
			else {
				ast_channel_lock(peer_owner);
				ast_channel_lock(owner);
			}
		}
		else if (owner) {
			ast_channel_lock(owner);
		}
		else if (peer_owner) {
			ast_channel_lock(peer_owner);
		}
		ast_mutex_lock(&p->lock);
		
		
		if (sub) {
			if (!rDetected) {

				/* DTMF */
				for (j = 0; j < 2; j++) { // we need to send two events: press and depress

					/* Interdigit timeout is scheduled for both press and depress */
					brcm_cancel_dialing_timeouts(p);

					unsigned int old_state = sub->channel_state;
					handle_dtmf(dtmfMap->event, sub, sub_peer, owner, peer_owner);
					if (sub->channel_state == DIALING && old_state != sub->channel_state) {

						/* DTMF event took channel state to DIALING. Stop dial tone. */
						ast_log(LOG_DEBUG, "Dialing. Stop dialtone.\n");
						brcm_stop_dialtone(p);
					}

					if (sub->channel_state == DIALING) {
						ast_log(LOG_DEBUG, "Handle DTMF calling\n");
						handle_dtmf_calling(sub);
					}
				}

				if (brcm_should_relay_dtmf(sub)) {
					switch (get_dtmf_relay_type(sub)) {
					case EPDTMFRFC2833_DISABLED:
						ast_debug(5, "Generating inband DTMF for DECT\n");
						brcm_signal_dtmf_ingress(sub, dtmfMap->i);
						break;
					case EPDTMFRFC2833_ENABLED:
					case EPDTMFRFC2833_SUBTRACT: {
						struct ast_frame f = { 0, };
						f.subclass.integer = dtmfMap->c;
						f.src = "BRCM";
						f.frametype = AST_FRAME_DTMF_END;
						if (owner) {
							ast_queue_frame(owner, &f);
						}
						break;
					}
					default:
						ast_log(LOG_WARNING, "DTMF mode unknown\n");
						break;
					}
				}
			}
			else {
				/* Hookflash */
				p->hf_detected = 1;
				handle_hookflash(sub, sub_peer, owner, peer_owner);
			}
		}
		ast_mutex_unlock(&p->lock);

		if (owner) {
			ast_channel_unlock(owner);
			ast_channel_unref(owner);
		}
		if (peer_owner) {
			ast_channel_unlock(peer_owner);
			ast_channel_unref(peer_owner);
		}
	}

}



//-------------------------------------------------------------
void setup_ind(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	struct json_object *obj, *val;
	char *json;
	int terminal, endpt;

	ast_verbose("setup_ind\n");	
	json = blobmsg_format_json(msg, true);
	obj = json_tokener_parse(json);

	if( (json_object_object_get_ex(obj, "terminal", &val)) == true) {
		terminal = json_object_get_int(val);
		
		if (bad_handsetnr(terminal))
			return;
		
		ast_verbose("terminal: %d\n", terminal);
		
		/* Signal offhook to endpoint driver */
		endpt = terminal;
		vrgEndptSendCasEvtToEndpt( (ENDPT_STATE *)&(endptObjState[endpt]), CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_OFFHOOK );
	}
}



//-------------------------------------------------------------
void release_ind(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	struct json_object *obj, *val;
	char *json;
	int terminal, endpt;

	ast_verbose("release_ind\n");	
	json = blobmsg_format_json(msg, true);
	obj = json_tokener_parse(json);

	if( (json_object_object_get_ex(obj, "terminal", &val)) == true) {
		terminal = json_object_get_int(val);
		
		if (bad_handsetnr(terminal))
			return;
		
		ast_verbose("terminal: %d\n", terminal);
		
		/* Signal onhook to endpoint driver */
		endpt = terminal;
		vrgEndptSendCasEvtToEndpt( (ENDPT_STATE *)&(endptObjState[endpt]), CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_ONHOOK );
	}
}



//-------------------------------------------------------------
int ast_ubus_listen(struct ubus_context *ctx) {

	static struct ubus_event_handler listener, svej, hej, info;
	const char *event, *svej_event, *hej_event, *info_event;
	int ret = 0;

	/* all */
	memset(&listener, 0, sizeof(listener));
	listener.cb = ast_ubus_event;
	event = "*";

	ret = ubus_register_event_handler(ctx, &listener, event);
	if (ret) {
		ast_verbose("\n\nError while registering for event '%s': %s\n\n\n",
			    event, ubus_strerror(ret));
		return -1;
	}

	/* dect.api.setup_ind */
	memset(&hej, 0, sizeof(hej));
	hej.cb = setup_ind;
	hej_event = "dect.api.setup_ind";

	ret = ubus_register_event_handler(ctx, &hej, hej_event);
	if (ret) {
		ast_verbose("\n\n\nError while registering for event '%s': %s\n\n\n",
			    hej_event, ubus_strerror(ret));
		return -1;
	}


	/* dect.api.release_ind */
	memset(&svej, 0, sizeof(svej));
	svej.cb = release_ind;
	svej_event = "dect.api.release_ind";

	ret = ubus_register_event_handler(ctx, &svej, svej_event);
	if (ret) {
		ast_verbose("Error while registering for event '%s': %s\n",
			    svej_event, ubus_strerror(ret));
		return -1;
	}


	/* dect.api.info_ind */
	memset(&info, 0, sizeof(info));
	info.cb = info_ind;
	info_event = "dect.api.info_ind";

	ret = ubus_register_event_handler(ctx, &info, info_event);
	if (ret) {
		ast_verbose("Error while registering for event '%s': %s\n",
			    info_event, ubus_strerror(ret));
		return -1;
	}


	ast_verbose("\n\n\nubus handlers registered\n\n\n");

	uloop_init();
	ubus_add_uloop(ctx);


	ast_verbose("\n\n\nuloop run\n\n\n");
	uloop_run();
	ast_verbose("\n\n\nuloop done 1\n\n\n");


	uloop_done();
	ast_verbose("\n\n\nuloop done 2\n\n\n");	

	return 0;
}


//-------------------------------------------------------------
// Thread main
void *brcm_monitor_dect(void *data) { 
	static struct ubus_context *ctx;

	/* Initialize ubus connecton */
	ctx = ubus_connect(NULL);
	if (!ctx) {
		ast_verbose("Failed to connect to ubus\n");
		return (void*) -1;
	}

	ast_ubus_listen(ctx);
	ubus_free(ctx);

	return 0;
}

