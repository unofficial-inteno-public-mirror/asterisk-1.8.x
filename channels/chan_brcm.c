/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Broadcom Slic endpoint driver
 *
 * \author Benjamin Larsson <benjamin@southpole.se>
 * \author Jonas Höglund <jonash@southpole.se>
 * 
 * \ingroup channel_drivers
 */

/* TODO:
 * Prefered codec order mulaw/alaw/g729/g723.1/g726_24/g726_32
 * Enable T38 support
 * Enable V18 support
 */

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

/*** DOCUMENTATION
	<manager name="BRCMPortsShow" language="en_US">
		<synopsis>
			Show detected BRCM ports.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
		</syntax>
		<description>
		</description>
	</manager>
 ***/

static void brcm_dialtone_init(struct brcm_pvt *p);
static void brcm_dialtone_set(struct brcm_pvt *p, dialtone_state state);
static int brcm_extension_state_register(struct brcm_pvt *p);
static void brcm_extension_state_unregister(struct brcm_pvt *p);
static dialtone_state extension_state2dialtone_state(int state);
static int extension_state_cb(char *context, char* exten, int state, void *data);

/* Global brcm channel parameters */

static const char tdesc[] = "Brcm SLIC Driver";
static const char config[] = "brcm.conf";

VRG_ENDPT_STATE endptObjState[MAX_NUM_LINEID];
static line_settings line_config[MAX_NUM_LINEID];
static int current_connection_id = 0;
static int num_fxs_endpoints = -1;
static int num_fxo_endpoints = -1;
static int num_dect_endpoints = -1;
static int num_endpoints = -1;
static int endpoint_fd = NOT_INITIALIZED;
static int endpoint_country = VRG_COUNTRY_NORTH_AMERICA;
static int clip = 1; // Caller ID presentation
static const format_t default_capability = AST_FORMAT_ALAW | AST_FORMAT_ULAW | AST_FORMAT_G729A | AST_FORMAT_G726; // AST_FORMAT_G723_1 breaks stuff
struct ast_sched_thread *sched; //Scheduling thread
static int pcmShimFile = -1;

/* Call waiting */
static int cw = 1;
static int cwtimeout = DEFAULT_CALL_WAITING_TIMEOUT;

/* R4 transfer */
static int r4hanguptimeout = DEFAULT_R4_HANGUP_TIMEOUT;

/* Maximum allowed delay between early on and early off hook for detecting hookflash */
static int hfmaxdelay = DEFAULT_MAX_HOOKFLASH_DELAY;

/* Global jitterbuffer configuration */
static struct ast_jb_conf global_jbconf;

/* Boolean value whether the monitoring thread shall continue. */
static unsigned int monitor;
static unsigned int dect;
static unsigned int packets;

static pthread_t monitor_thread = AST_PTHREADT_NULL;
static pthread_t dect_thread = AST_PTHREADT_NULL;
static pthread_t packet_thread = AST_PTHREADT_NULL;

static struct ast_channel_tech *cur_tech;

const DTMF_CHARNAME_MAP dtmf_to_charname[] =
{
	{EPEVT_DTMF0, "EPEVT_DTMF0", '0'},
	{EPEVT_DTMF1, "EPEVT_DTMF1", '1'},
	{EPEVT_DTMF2, "EPEVT_DTMF2", '2'},
	{EPEVT_DTMF3, "EPEVT_DTMF3", '3'},
	{EPEVT_DTMF4, "EPEVT_DTMF4", '4'},
	{EPEVT_DTMF5, "EPEVT_DTMF5", '5'},
	{EPEVT_DTMF6, "EPEVT_DTMF6", '6'},
	{EPEVT_DTMF7, "EPEVT_DTMF7", '7'},
	{EPEVT_DTMF8, "EPEVT_DTMF8", '8'},
	{EPEVT_DTMF9, "EPEVT_DTMF9", '9'},
	{EPEVT_DTMFA, "EPEVT_DTMFA", 'A'},
	{EPEVT_DTMFB, "EPEVT_DTMFB", 'B'},
	{EPEVT_DTMFC, "EPEVT_DTMFC", 'C'},
	{EPEVT_DTMFD, "EPEVT_DTMFD", 'D'},
	{EPEVT_DTMFH, "EPEVT_DTMFH", 0x23}, //#
	{EPEVT_DTMFS, "EPEVT_DTMFS", 0x2A}, //*
	{EPEVT_LAST,  "EPEVT_LAST", '-'}
};


static COUNTRY_MAP country_map[] =
{
	{VRG_COUNTRY_AUSTRALIA,			"AUS"},
	{VRG_COUNTRY_BELGIUM,			"BEL"},
	{VRG_COUNTRY_BRAZIL,			"BRA"},
	{VRG_COUNTRY_CHILE,			"CHL"},
	{VRG_COUNTRY_CHINA,	 		"CHN"},
	{VRG_COUNTRY_CZECH, 			"CZE"},
	{VRG_COUNTRY_DENMARK, 			"DNK"},
	{VRG_COUNTRY_ETSI, 			"ETS"}, //Not really an iso code
	{VRG_COUNTRY_FINLAND, 			"FIN"},
	{VRG_COUNTRY_FRANCE, 			"FRA"},
	{VRG_COUNTRY_GERMANY, 			"DEU"},
	{VRG_COUNTRY_HUNGARY,			"HUN"},
	{VRG_COUNTRY_INDIA,			"IND"},
	{VRG_COUNTRY_ITALY, 			"ITA"},
	{VRG_COUNTRY_JAPAN,	 		"JPN"},
	{VRG_COUNTRY_NETHERLANDS, 		"NLD"},
	{VRG_COUNTRY_NEW_ZEALAND, 		"NZL"},
	{VRG_COUNTRY_NORTH_AMERICA, 		"USA"},
	{VRG_COUNTRY_SPAIN, 			"ESP"},
	{VRG_COUNTRY_SWEDEN,			"SWE"},
	{VRG_COUNTRY_SWITZERLAND, 		"CHE"},
	{VRG_COUNTRY_NORWAY, 			"NOR"},
	{VRG_COUNTRY_TAIWAN,	 		"TWN"},
	{VRG_COUNTRY_UK,		 	"GBR"},
	{VRG_COUNTRY_UNITED_ARAB_EMIRATES,	"ARE"},
	{VRG_COUNTRY_CFG_TR57, 			"T57"}, //Not really an iso code
	{VRG_COUNTRY_MAX, 			"-"}
};

/* Linked list of pvt:s */
struct brcm_pvt *iflist;

extern struct brcm_channel_tech dect_tech;

/* Protect the interface list (of brcm_pvt's) */
AST_MUTEX_DEFINE_STATIC(iflock);

/* Protect the monitoring thread, so only one process can kill or start it, and not
   when it's doing something critical. */
AST_MUTEX_DEFINE_STATIC(monlock);
AST_MUTEX_DEFINE_STATIC(ioctl_lock);

static int load_settings(struct ast_config **cfg);
static void load_endpoint_settings(struct ast_config *cfg);
static char *state2str(enum channel_state state);

/* exported capabilities */
static const struct ast_channel_tech brcm_tech = {
	.type = "BRCM",
	.description = tdesc,
	.capabilities = AST_FORMAT_ALAW | AST_FORMAT_ULAW | AST_FORMAT_G729A | AST_FORMAT_G726 | AST_FORMAT_G723_1,
	.requester = brcm_request,			//No lock held (no channel yet)
	.call = brcm_call,				//Channel is locked
	.hangup = brcm_hangup,				//Channel is locked
	.answer = brcm_answer,				//Channel is locked
	.read = brcm_read,				//Channel is locked
	.write = brcm_write,				//Channel is locked
	.send_digit_begin = brcm_senddigit_begin,	//Channel is NOT locked
	.send_digit_continue = brcm_senddigit_continue,	//Channel is NOT locked
	.send_digit_end = brcm_senddigit_end,		//Channel is NOT locked
	.indicate = brcm_indicate,			//Channel is locked
};

static struct brcm_channel_tech fxs_tech = {
	.signal_ringing = brcm_signal_ringing,
	.signal_ringing_callerid_pending = brcm_signal_ringing_callerid_pending,
	.signal_callerid = brcm_signal_callerid,
	.stop_ringing = brcm_stop_ringing,
	.stop_ringing_callerid_pending = brcm_stop_ringing_callerid_pending,
};

/* Tries to lock 10 timees, then gives up */
static int pvt_trylock(struct brcm_pvt *pvt, const char *reason)
{
	int i = 10;
	while (i--) {
		if (!ast_mutex_trylock(&pvt->lock)) {
			ast_debug(9, "----> Successfully locked pvt port %d - reason %s\n", pvt->line_id, reason);
			return 1;
		}
	}
	ast_debug(9, "----> Failed to lock port %d - %s\n", pvt->line_id, reason);
	return 0;
}

static int pvt_lock(struct brcm_pvt *pvt, const char *reason)
{
	ast_debug(9, "----> Trying to lock port %d - %s\n", pvt->line_id, reason);
	ast_mutex_lock(&pvt->lock);
	ast_debug(9, "----> Locked pvt port %d - reason %s\n", pvt->line_id, reason);
	return 1;
}

static int pvt_lock_silent(struct brcm_pvt *pvt)
{
	ast_mutex_lock(&pvt->lock);
	return 1;
}


static int pvt_unlock(struct brcm_pvt *pvt)
{
	ast_mutex_unlock(&pvt->lock);
	ast_debug(10, "----> Unlocking pvt port %d\n", pvt->line_id);
	return 1;
}

static int pvt_unlock_silent(struct brcm_pvt *pvt)
{
	ast_mutex_unlock(&pvt->lock);
	return 1;
}


static int brcm_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen)
{
	struct brcm_subchannel *sub = ast->tech_pvt;
	int res = 0;
	pvt_lock(sub->parent, "indicate");
	//ast_mutex_lock(&sub->parent->lock);
	switch(condition) {
	case AST_CONTROL_SRCUPDATE:
	case AST_CONTROL_UNHOLD:
		//Asterisk (adaptive) jitter buffer causes one way audio
		//This is a workaround until jitter buffer is handled by DSP.
		res = 0; //We still want asterisk core to play tone
		ast_jb_destroy(ast);
		break;
	case AST_CONTROL_RINGING:
		brcm_subchannel_set_state(sub, RINGBACK);
		res = 1; //We still want asterisk core to play tone
		break;
	case AST_CONTROL_TRANSFER:
		res = -1;
		if (datalen != sizeof(enum ast_control_transfer)) {
			ast_log(LOG_ERROR, "Invalid datalen for AST_CONTROL_TRANSFER. Expected %d, got %d\n", (int) sizeof(enum ast_control_transfer), (int) datalen);
		} else {
			enum ast_control_transfer *message = (enum ast_control_transfer *) data;
			brcm_finish_transfer(ast, sub, *message);
		}
		break;
	default:
		res = -1;
		break;
	}
	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);
	return res;
}

static int brcm_finish_transfer(struct ast_channel *owner, struct brcm_subchannel *p, int result)
{
	struct brcm_subchannel* peer_sub;
	/*
	 * We have received the result of a transfer operation.
	 * This could be:
	 * - Result of a Transfer-On-Hangup (Remote Transfer), in which case
	 *   we should hangup the subchannel, no matter the result
	 * - Result of a R4 Attended Transfer (Remote Transfer), in which case
	 *   we should wait for hangup on both subchannels, or resume calls if failed
	 *   Hangup should be received immediately, but we start a timer to hangup
	 *   everythin ourselfs just to be sure.
	 * - Probably nothing else - the builtin transfer should never let this
	 *   control frame propagate to here
	 */

	if (p->channel_state != TRANSFERING) {
		ast_log(LOG_WARNING, "Received AST_CONTROL_TRANSFER while in state %s\n", state2str(p->channel_state));
		return -1;
	}

	peer_sub = brcm_subchannel_get_peer(p);
	if (!peer_sub) {
		ast_log(LOG_ERROR, "Failed to get peer subchannel\n");
		return -1;
	}

	// In the case of Transfer-On-Hangup peer sub should be a idle
	if (brcm_subchannel_is_idle(peer_sub)) {
		if (result == AST_TRANSFER_SUCCESS) {
			ast_log(LOG_NOTICE, "Remote transfer completed successfully, hanging up\n");
		}
		else {
			ast_log(LOG_NOTICE, "Remote transfer failed, hanging up\n");
		}

		ast_queue_control(owner, AST_CONTROL_HANGUP);
		brcm_subchannel_set_state(p, CALLENDED);

	// In the case of R4 transfer peer sub should be on hold
	} else if (peer_sub->channel_state == ONHOLD) {
		if (result == AST_TRANSFER_SUCCESS) {
			ast_log(LOG_NOTICE, "Remote transfer completed successfully, wait for remote hangup\n");
			p->r4_hangup_timer_id = ast_sched_thread_add(sched, r4hanguptimeout, r4hanguptimeout_cb, p);
		} else {
			//Do nothing. Let calls be up as they were before R4 was attempted (first call on hold, second call active)
			ast_log(LOG_NOTICE, "Remote transfer failed\n");
			brcm_subchannel_set_state(p, INCALL);

			//Asterisk jitter buffer causes one way audio when going from unhold.
			//This is a workaround until jitter buffer is handled by DSP.
			ast_jb_destroy(owner);
		}

	} else {
		ast_log(LOG_WARNING, "AST_CONTROL_TRANSFER received in unexpected state\n");
		return -1;
	}

	return 0;
}

static int brcm_send_dtmf(struct ast_channel *ast, char digit, unsigned int duration, int status) {
	EPPACKET epPacket_send;
	ENDPOINTDRV_PACKET_PARM tPacketParm_send;
	struct brcm_subchannel *sub = ast->tech_pvt;
   	UINT8 pdata[PACKET_BUFFER_SIZE] = {0};

	if (ast->_state != AST_STATE_UP && ast->_state != AST_STATE_RING) {
		/* Silently ignore packets until channel is up */
		ast_debug(5, "error: channel not up\n");
		return 0;
	}

	/* Ignore if on hold */
	if (sub->channel_state == ONHOLD) {
		return 0;
	}
	/* send rtp packet to the endpoint */
	epPacket_send.mediaType   = 0;

	/* copy frame data to local buffer */
	// memcpy(packet_buffer + 12, frame->data.ptr, frame->datalen);
	
	/* add buffer to outgoing packet */
	epPacket_send.packetp = pdata;

	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "brcm_send_dtmf");

	/* generate the rtp header */
	brcm_generate_rtp_packet(sub, pdata, DTMF_PAYLOAD, (status==BEGIN)?1:0, 1);

	// generate payload FIXME
	// [3,16] |80|80|FC|52|94|2C|D1|F4|F0|B5|F8|3E|01 |8F |09|38|
	// [3,16] |80|80|E4|54|79|60|0E|5A|1A|23|A1|EC|06 |0F |00|F0|
	//        |80|80|03|4E|00|02|10|C0|68|42|D5|53|31 |08 |00|08|
	
	pdata[12]  = digit-48;
	pdata[13]  = 0x8; //Volume
	pdata[13] |= (status==END)?0x80:0x00; // End of Event
	if (status==BEGIN) 
		duration = 1;
	duration = duration * 8; // based on 8kHz sample rate
	pdata[14]  = (duration>>8)&0xFF;
	pdata[15]  = duration&0xFF;
	
	ast_debug(5, "[%d,%d] |%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|\n", DTMF_PAYLOAD, digit, pdata[0], pdata[1], pdata[2], pdata[3], pdata[4], pdata[5], pdata[6], pdata[7], pdata[8], pdata[9], pdata[10], pdata[11], pdata[12], pdata[13], pdata[14], pdata[15]);

	
	/* set rtp id sent to endpoint */
	//sub->codec = map_ast_codec_id_to_rtp(frame->subclass.codec);

	tPacketParm_send.cnxId       = sub->connection_id;
	tPacketParm_send.state       = (ENDPT_STATE*)&endptObjState[sub->parent->line_id];
	tPacketParm_send.length      = 16;
	tPacketParm_send.bufDesc     = (int)&epPacket_send;
	tPacketParm_send.epPacket    = &epPacket_send;
	tPacketParm_send.epStatus    = EPSTATUS_DRIVER_ERROR;
	tPacketParm_send.size        = sizeof(ENDPOINTDRV_PACKET_PARM);

	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);

	if (sub->connection_init) {
		if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_PACKET, &tPacketParm_send ) != IOCTL_STATUS_SUCCESS )
			ast_verbose("%s: error during ioctl", __FUNCTION__);
	}

	return 0;

}

static int brcm_senddigit_continue(struct ast_channel *ast, char digit, unsigned int duration)
{
	int res;
	struct brcm_subchannel *sub;
	line_settings* s;

	sub = ast->tech_pvt;
	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "DTMF senddigit_begin");

	res = 0;
	s = &line_config[sub->parent->line_id];
	switch (s->dtmf_relay) {
		case EPDTMFRFC2833_DISABLED:
			res = -1;
			break;
		case EPDTMFRFC2833_ENABLED:
			brcm_send_dtmf(ast, digit, duration, CONT);
			break;
		case EPDTMFRFC2833_SUBTRACT:
			{
			unsigned int ts;
			struct timeval tim;
			gettimeofday(&tim, NULL);
			ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;
			ast_debug(9, "DTMF %d start %lu detected\n", digit, ts);
			if (brcm_signal_dtmf(sub, digit) != EPSTATUS_SUCCESS) {
				res = -1;
			}
			break;
			}
		default:
			res = -1;
			break;
	}

	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);
	return res;
}

/*! \brief Incoming DTMF begin event */
static int brcm_senddigit_begin(struct ast_channel *ast, char digit)
{
	int res;
	struct brcm_subchannel *sub;
	line_settings* s;

	sub = ast->tech_pvt;
	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "DTMF senddigit_begin");

	/* save away timestamp */
	sub->dtmf_timestamp = sub->time_stamp;
	
	res = 0;
	s = &line_config[sub->parent->line_id];
	switch (s->dtmf_relay) {
		case EPDTMFRFC2833_DISABLED:
			res = -1;
			break;
		case EPDTMFRFC2833_ENABLED:
			brcm_send_dtmf(ast, digit, 0, BEGIN);
			break;
		case EPDTMFRFC2833_SUBTRACT:
			{
			unsigned int ts;
			struct timeval tim;
			gettimeofday(&tim, NULL);
			ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;
			ast_debug(9, "DTMF %d start %lu detected\n", digit, ts);
			if (brcm_signal_dtmf(sub, digit) != EPSTATUS_SUCCESS) {
				res = -1;
			}
			break;
			}
		default:
			res = -1;
			break;
	}

	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);
	return res;
}

/*! \brief Incoming DTMF end */
static int brcm_senddigit_end(struct ast_channel *ast, char digit, unsigned int duration)
{
	int res;
	struct brcm_subchannel *sub;
	line_settings* s;

	sub = ast->tech_pvt;
	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "DTMF senddigit_end");

	res = 0;
	s = &line_config[sub->parent->line_id];
	switch (s->dtmf_relay) {
		case EPDTMFRFC2833_DISABLED:
			res = -1;
			break;
		case EPDTMFRFC2833_ENABLED:
			brcm_send_dtmf(ast, digit, duration, END);
			brcm_send_dtmf(ast, digit, duration, END);
			brcm_send_dtmf(ast, digit, duration, END);
			break;
		case EPDTMFRFC2833_SUBTRACT:
			{
			unsigned int ts;
			struct timeval tim;
			gettimeofday(&tim, NULL);
			ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;
			ast_debug(9, "DTMF %d stop %lu detected\n", digit, ts);
			if (brcm_stop_dtmf(sub, digit) != EPSTATUS_SUCCESS) {
				res = -1;
			}
			break;
			}
		default:
			res = -1;
			break;
	}

	//ast_mutex_unlock(&sub->parent->lock);

	pvt_unlock(sub->parent);
	return res;
}


static int brcm_call(struct ast_channel *chan, char *dest, int timeout)
{
	struct brcm_pvt *p;
	struct brcm_subchannel *sub;

	struct timeval UtcTime = ast_tvnow();
	struct ast_tm tm;
	
	sub = chan->tech_pvt;

	ast_log(LOG_WARNING, "BRCM brcm_call %d\n", sub->parent->line_id);
	ast_localtime(&UtcTime, &tm, NULL);

	if ((chan->_state != AST_STATE_DOWN) && (chan->_state != AST_STATE_RESERVED)) {
		ast_log(LOG_WARNING, "brcm_call called on %s, neither down nor reserved\n", chan->name);
		return -1;
	}

	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "brcm_call");

	p = sub->parent;
	if (cw && brcm_in_call(p)) {
		ast_log(LOG_WARNING, "Call waiting\n");
		brcm_subchannel_set_state(sub, CALLWAITING);
		brcm_signal_callwaiting(p);
		int cwtimeout_ms = cwtimeout * 1000;
		sub->cw_timer_id = ast_sched_thread_add(sched, cwtimeout_ms, cwtimeout_cb, sub);
	  	ast_setstate(chan, AST_STATE_RINGING);
		ast_queue_control(chan, AST_CONTROL_RINGING);
	}
	else if (brcm_in_call(p)) {
		ast_log(LOG_WARNING, "Line is busy\n");
		chan->hangupcause = AST_CAUSE_USER_BUSY;
		ast_queue_control(chan, AST_CONTROL_BUSY);
	}
	else {
		ast_log(LOG_WARNING, "Not call waiting\n");
		brcm_subchannel_set_state(sub, RINGING);
		if (!clip) {
			p->tech->signal_ringing(p);
		} else {
			p->tech->signal_ringing_callerid_pending(p);
			p->tech->signal_callerid(chan, sub);
		}
	  	ast_setstate(chan, AST_STATE_RINGING);
		ast_queue_control(chan, AST_CONTROL_RINGING);
	}
	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);

	return 0;
}

static int brcm_hangup(struct ast_channel *ast)
{
	struct brcm_pvt *p;
	struct brcm_subchannel *sub;
	sub = ast->tech_pvt;

	if (!ast->tech_pvt) {
		ast_log(LOG_WARNING, "Asked to hangup channel not connected\n");
		return 0;
	}
	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "BRCM hangup");

	p = sub->parent;
	ast_verbose("brcm_hangup(%s) line_id=%d connection_id=%d\n", ast->name, p->line_id, sub->connection_id);

	if (sub->channel_state == CALLWAITING) {
		ast_debug(2, "stop Call waiting\n");
		brcm_stop_callwaiting(p);
		if (ast_sched_thread_del(sched, sub->cw_timer_id)) {
			ast_log(LOG_WARNING, "Failed to remove scheduled call waiting timer");
		}
		sub->cw_timer_id = -1;
	} else {
		ast_debug(2, "Not call waiting\n");
		if (!clip) {
			p->tech->stop_ringing(p);
		} else {
			p->tech->stop_ringing_callerid_pending(p);
		}
	}

	if(sub->r4_hangup_timer_id != -1) {
		if (ast_sched_thread_del(sched, sub->r4_hangup_timer_id)) {
			ast_log(LOG_WARNING, "Failed to remove scheduled r4 hangup timer");
		}
		sub->r4_hangup_timer_id = -1;
	}
	ast_setstate(ast, AST_STATE_DOWN);

	p->lastformat = -1;
	p->lastinput = -1;
	p->hf_detected = 0;
	brcm_subchannel_set_state(sub, CALLENDED);
	struct brcm_subchannel *peer_sub = brcm_get_active_subchannel(p);
	if (peer_sub && peer_sub->channel_state == INCALL) {
		/* Switch still active call leg out of conference mode */
		brcm_stop_conference(peer_sub);
	}
	memset(p->ext, 0, sizeof(p->ext));
	sub->owner = NULL;
	ast_module_unref(ast_module_info->self);
	ast_verb(3, "Hungup '%s'\n", ast->name);
	ast->tech_pvt = NULL;
	brcm_close_connection(sub);
	//ast_mutex_unlock(&p->lock);
	pvt_unlock(p);
	return 0;
}


static int brcm_answer(struct ast_channel *ast)
{
	ast_debug(1, "brcm_answer(%s)\n", ast->name);

	struct brcm_subchannel *sub = ast->tech_pvt;
	pvt_lock(sub->parent, "BRCM answer");
	//ast_mutex_lock(&sub->parent->lock);
	if (ast->_state != AST_STATE_UP) {
		ast_setstate(ast, AST_STATE_UP);
		ast_debug(2, "brcm_answer(%s) set state to up\n", ast->name);
	}
	ast->rings = 0;
	brcm_subchannel_set_state(sub, INCALL);
	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);
	return 0;
}

/*
* Map RTP data header value to a codec name
*/
static char* brcm_get_codec_string(int id) {
	switch (id) {
			case PCMA:		return "alaw"; break;
			case PCMU:		return "ulaw"; break;
			case G723:		return "g723.1"; break;
			case G726:		return "g726"; break;
			case G729:		return "g729"; break;
			case -1:		return "none set"; break;
			default: 		return "unknown id"; break;
	}
}

/*
* Map rtp packet header value to corresponding asterisk codec
*/
static int map_rtp_to_ast_codec_id(int id) {
	switch (id) {
		case PCMU: return AST_FORMAT_ULAW;
		case G726: return AST_FORMAT_G726;
		case G723: return AST_FORMAT_G723_1;
		case PCMA: return AST_FORMAT_ALAW;
		case G729: return AST_FORMAT_G729A;
		default:
		{
			ast_verbose("Unknown rtp codec id [%d]\n", id);
			return AST_FORMAT_ALAW;
		}
	}
}

static int brcm_classify_rtp_packet(int id) {
	switch (id) {
		case PCMU: return BRCM_AUDIO;
		case G726: return BRCM_AUDIO;
		case G723: return BRCM_AUDIO;
		case PCMA: return BRCM_AUDIO;
		case G729: return BRCM_AUDIO;
		case DTMF_PAYLOAD: return BRCM_DTMF;
		case RTCP: return BRCM_RTCP;
		default:
			ast_verbose("Unknown rtp packet id %d\n", id);
			return BRCM_UNKNOWN;
	}
}

static int map_ast_codec_id_to_rtp(int id) {
	switch (id) {
		case AST_FORMAT_ULAW: return PCMU;
		case AST_FORMAT_G726: return G726;
		case AST_FORMAT_G723_1: return G723;
		case AST_FORMAT_ALAW: return PCMA;
		case AST_FORMAT_G729A: return G729;
		default:
		{
			ast_verbose("Unknown asterisk format/codec id [%d]\n", id);
			return PCMA;
		}
	}
}

/*
* Map brcm codec enum to asterisk codec enum
*/
static format_t map_codec_brcm_to_ast(int id) {
	switch (id) {
		case CODEC_PCMU:		return AST_FORMAT_ULAW;
		case CODEC_PCMA:		return AST_FORMAT_ALAW;
		case CODEC_G7231_53:	return AST_FORMAT_G723_1;
		case CODEC_G7231_63:	return AST_FORMAT_G723_1;
		case CODEC_G726_32:		return AST_FORMAT_G726;
		case CODEC_G729A:		return AST_FORMAT_G729A;
		default:				return -1;
	}
}

static int map_codec_ast_to_brcm(int id) {
	switch (id) {
		case AST_FORMAT_ULAW:	return CODEC_PCMU;
		case AST_FORMAT_ALAW:	return CODEC_PCMA;
		case AST_FORMAT_G723_1:	return CODEC_G7231_63; //Asterisk does not indicate which bitrate to use
		case AST_FORMAT_G726:	return CODEC_G726_32; //32 is the only supported bitrate in asterisk
		case AST_FORMAT_G729A:	return CODEC_G729A;
		default:				return -1;
	}
}

static struct ast_frame  *brcm_read(struct ast_channel *ast)
{
	return &ast_null_frame;
}

static int map_codec_ast_to_brcm_rtp(int id) {
	switch (id) {
		case AST_FORMAT_ULAW:	return RTP_PAYLOAD_PCMU;
		case AST_FORMAT_ALAW:	return RTP_PAYLOAD_PCMA;
		case AST_FORMAT_G723_1:	return RTP_PAYLOAD_G723;
		case AST_FORMAT_G726:	return RTP_PAYLOAD_G726_32; //32 is the only supported bitrate in asterisk
		case AST_FORMAT_G729A:	return RTP_PAYLOAD_G729;
		default:				return -1;
	}
}

static char* brcm_codec_to_string(int id) {
	switch (id) {
		case CODEC_NULL: return "NULL";
		case CODEC_PCMU: return "G.711 ulaw";
		case CODEC_PCMA: return "G.711 alaw";
		case CODEC_G726_16: return "G.726 - 16 kbps";
		case CODEC_G726_24: return "G.726 - 24 kbps";
		case CODEC_G726_32: return "G.726 - 32 kbps";
		case CODEC_G726_40: return "G.726 - 40 kbps";
		case CODEC_G7231_53: return "G.723.1 - 5.3 kbps";
		case CODEC_G7231_63: return "G.723.1 - 6.3 kbps";
		case CODEC_G7231A_53: return "G.723.1A - 5.3 kbps";
		case CODEC_G7231A_63: return "G.723.1A - 6.3 kbps";
		case CODEC_G729A: return "G.729A";
		case CODEC_G729B: return "G.729B";
		case CODEC_G711_LINEAR: return "Linear media queue data";
		case CODEC_G728: return "G.728";
		case CODEC_G729: return "G.729";
		case CODEC_G729E: return "G.729E";
		case CODEC_BV16: return "BRCM Broadvoice - 16 kbps";
		case CODEC_BV32: return "BRCM Broadvoice - 32 kbps";
		case CODEC_NTE: return "Named telephone events";
		case CODEC_ILBC_20: return "iLBC speech coder - 20 ms frame / 15.2 kbps";
		case CODEC_ILBC_30: return "iLBC speech coder - 30 ms frame / 13.3 kbps";
		case CODEC_G7231_53_VAR: return "G723.1 variable rates (preferred=5.3)";
		case CODEC_G7231_63_VAR: return "G723.1 variable rates (preferred=6.3)";
		case CODEC_G7231_VAR: return "G723.1 variable rates";
		case CODEC_T38: return "T.38 fax relay";
		case CODEC_T38_MUTE: return "Mute before switching to T.38 fax relay";
		case CODEC_RED: return "Redundancy - RFC 2198";
		case CODEC_G722_MODE_1: return "G.722 Mode 1 64 kbps";
		case CODEC_LINPCM128: return "Narrowband linear PCM @ 128 Kbps";
		case CODEC_LINPCM256: return "Wideband linear PCM @ 256 Kbps";
		case CODEC_DYNAMIC: return "Dynamic";
		default: return "Unknown";
	}
}

static char* brcm_rtppayload_to_string(int id) {
	switch (id) {
		case RTP_PAYLOAD_PCMU: return "G.711 mu-law 64 kbps";
		case RTP_PAYLOAD_G726_32: return "G.726-32";
		case RTP_PAYLOAD_G723: return "G.723";
		case RTP_PAYLOAD_PCMA: return "G.711 A-law 64 kbps";
		case RTP_PAYLOAD_CNA: return "Comfort noise";
		case RTP_PAYLOAD_G728: return "G.728";
		case RTP_PAYLOAD_G729: return "G.729";
		case RTP_PAYLOAD_CN: return "Comfort noise";
		case RTP_PAYLOAD_INVALID: return "Invalid payload";
		default: return "Unknown payload";
	}
}

static int brcm_write(struct ast_channel *ast, struct ast_frame *frame)
{
	EPPACKET epPacket_send;
	ENDPOINTDRV_PACKET_PARM tPacketParm_send;
	struct brcm_subchannel *sub = ast->tech_pvt;
   	UINT8 packet_buffer[PACKET_BUFFER_SIZE] = {0};

	if (ast->_state != AST_STATE_UP && ast->_state != AST_STATE_RING) {
		/* Silently ignore packets until channel is up */
		ast_debug(5, "error: channel not up\n");
		return 0;
	}

	/* Ignore if on hold */
	if (sub->channel_state == ONHOLD) {
		return 0;
	}

	if(frame->frametype == AST_FRAME_VOICE) {

		/* send rtp packet to the endpoint */
		epPacket_send.mediaType   = 0;

		/* copy frame data to local buffer */
		memcpy(packet_buffer + 12, frame->data.ptr, frame->datalen);
	    
		/* add buffer to outgoing packet */
		epPacket_send.packetp = packet_buffer;

		//ast_mutex_lock(&sub->parent->lock);
		pvt_lock(sub->parent, "BRCM write frame");

		/* generate the rtp header */
		brcm_generate_rtp_packet(sub, epPacket_send.packetp, map_ast_codec_id_to_rtp(frame->subclass.codec), 0, 0);

		/* set rtp id sent to endpoint */
		sub->codec = map_ast_codec_id_to_rtp(frame->subclass.codec);

		tPacketParm_send.cnxId       = sub->connection_id;
		tPacketParm_send.state       = (ENDPT_STATE*)&endptObjState[sub->parent->line_id];
		tPacketParm_send.length      = 12 + frame->datalen;
		tPacketParm_send.bufDesc     = (int)&epPacket_send;
		tPacketParm_send.epPacket    = &epPacket_send;
		tPacketParm_send.epStatus    = EPSTATUS_DRIVER_ERROR;
		tPacketParm_send.size        = sizeof(ENDPOINTDRV_PACKET_PARM);

		//ast_mutex_unlock(&sub->parent->lock);
		pvt_unlock(sub->parent);

		if (sub->connection_init) {
			if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_PACKET, &tPacketParm_send ) != IOCTL_STATUS_SUCCESS )
				ast_verbose("%s: error during ioctl", __FUNCTION__);
		}

	}

	return 0;
}

static void brcm_reset_dtmf_buffer(struct brcm_pvt *p)
{
	memset(p->dtmfbuf, 0, sizeof(p->dtmfbuf));
	p->dtmf_len = 0;
	p->dtmf_first = -1;
	p->dtmfbuf[p->dtmf_len] = '\0';
}

static char *state2str(enum channel_state state)
{
	switch (state) {
	case ONHOOK:		return "ONHOOK";
	case OFFHOOK:		return "OFFHOOK";
	case DIALING:		return "DIALING";
	case CALLING:		return "CALLING";
	case INCALL:		return "INCALL";
	case ANSWER:		return "ANSWER";
	case CALLENDED:		return "CALLENDED";
	case RINGING:		return "RINGING";
	case CALLWAITING:	return "CALLWAITING";
	case ONHOLD:		return "ONHOLD";
	case TRANSFERING:	return "TRANSFERING";
	case RINGBACK:		return "RINGBACK";
	default:			return "UNKNOWN";
	}
}

static int brcm_subchannel_is_idle(const struct brcm_subchannel const * const sub)
{
	if (sub->channel_state == ONHOOK || sub->channel_state == CALLENDED) {
		return 1;
	}
	return 0;
}

struct brcm_subchannel *brcm_subchannel_get_peer(const struct brcm_subchannel const * const sub)
{
	struct brcm_subchannel *peer_sub;
	peer_sub = (sub->parent->sub[0] == sub) ? sub->parent->sub[1] : sub->parent->sub[0];
	return peer_sub;
}

/*
 * Set sub channel state and send manager event.
 * Assume parent lock is held.
 */
static void brcm_subchannel_set_state(struct brcm_subchannel *sub, enum channel_state state)
{
	sub->channel_state = state;
	manager_event(EVENT_FLAG_SYSTEM, "BRCM", "State: %s %d %d\r\n",
			state2str(state),
			sub->parent->line_id,
			sub->id);
}

/* Tell endpoint to play country specific dialtone. */
int brcm_signal_dialtone(struct brcm_pvt *p) {
	EPSIG signal;
	switch (p->dialtone) {
		case DIALTONE_OFF:
			return EPSTATUS_SUCCESS;
		case DIALTONE_ON:
			signal = EPSIG_DIAL;
			break;
		case DIALTONE_CONGESTION:
			signal = EPSIG_STUTTER;
			break;
		default:
			ast_log(LOG_ERROR, "Requested to signal unknown dialtone\n");
			return EPSTATUS_ERROR;
	}
	return ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, signal, 1, -1, -1 , -1);
}

int brcm_stop_dialtone(struct brcm_pvt *p) {
	return ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_DIAL, 0, -1, -1 , -1) ||
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_NETBUSY, 0, -1, -1 , -1);
}

static struct ast_channel *brcm_new(struct brcm_subchannel *i, int state, char *cntx, const char *linkedid, format_t format)
{
	struct ast_channel *tmp;

	tmp = ast_channel_alloc(1, state, i->parent->cid_num, i->parent->cid_name, "", i->parent->ext, i->parent->context, linkedid, 0, "BRCM/%d/%d", i->parent->line_id, i->connection_id);

	if (tmp) {

		tmp->tech = cur_tech;
		/* ast_channel_set_fd(tmp, 0, i->fd); */

		/* find out which codec to use */
		format_t fmt = format;
		line_settings *s = &line_config[i->parent->line_id];
		if (fmt == 0) {
			tmp->nativeformats = map_codec_brcm_to_ast(s->codec_list[0]);
			fmt = tmp->nativeformats;
			ast_debug(1, "Selected codec: %s\n", ast_getformatname(fmt));
		} else {
			tmp->nativeformats = fmt;
			ast_debug(1, "Forced codec: %s\n", ast_getformatname(fmt));
		}

		/* set codecs */
		tmp->writeformat = fmt;
		tmp->rawwriteformat = fmt;
		tmp->readformat = fmt;
		tmp->rawreadformat = fmt;

		/* no need to call ast_setstate: the channel_alloc already did its job */
		if (state == AST_STATE_RING)
			tmp->rings = 1;
		tmp->tech_pvt = i;
		ast_copy_string(tmp->context, cntx, sizeof(tmp->context));
		if (!ast_strlen_zero(i->parent->ext))
			ast_copy_string(tmp->exten, i->parent->ext, sizeof(tmp->exten));
		else
			strcpy(tmp->exten, "s");

		if (!ast_strlen_zero(i->parent->language))
			ast_string_field_set(tmp, language, i->parent->language);

		/* Don't use ast_set_callerid() here because it will
		 * generate a NewCallerID event before the NewChannel event */
		if (!ast_strlen_zero(i->parent->cid_num)) {
			tmp->caller.ani.number.valid = 1;
			tmp->caller.ani.number.str = ast_strdup(i->parent->cid_num);
		}

		//Setup jitter buffer
		ast_jb_configure(tmp, &global_jbconf);
		i->owner = tmp;

		ast_module_ref(ast_module_info->self);

		if (state != AST_STATE_DOWN) {
			if (ast_pbx_start(tmp)) {
				ast_log(LOG_WARNING, "Unable to start PBX on %s\n", tmp->name);
				ast_hangup(tmp);
				return NULL;
			}
		}


	} else
		ast_log(LOG_WARNING, "Unable to allocate channel structure\n");

	return tmp;
}


static struct brcm_pvt* brcm_get_next_pvt(struct brcm_pvt *p) {
	if (p->next)
		return p->next;
	else
		return NULL;
}

struct brcm_pvt* brcm_get_pvt_from_lineid(struct brcm_pvt *p, int line_id)
{
	struct brcm_pvt *tmp = p;
	if (p->line_id == line_id) return p;

	tmp = brcm_get_next_pvt(tmp);

	while(tmp) {
		if (tmp->line_id == line_id) return tmp;
		tmp = brcm_get_next_pvt(tmp);
	}
	return NULL;
}

static struct brcm_subchannel* brcm_get_subchannel_from_connectionid(struct brcm_pvt *p, int connection_id)
{
	int i;
	struct brcm_pvt *tmp = p;

	while (tmp) {
		for (i=0; i<NUM_SUBCHANNELS; i++) {
			if (tmp->sub[i]->connection_id == connection_id) {
				return tmp->sub[i];
			}
		}
		tmp = brcm_get_next_pvt(tmp);
	}
	return NULL;
}

struct brcm_subchannel* brcm_get_active_subchannel(const struct brcm_pvt *p)
{
	struct brcm_subchannel *sub = NULL;
	int i;
	for (i=0; i<NUM_SUBCHANNELS; i++) {
		switch (p->sub[i]->channel_state) {
			case INCALL:
			case DIALING:
			case CALLING:
			case OFFHOOK:
			case RINGING:
			case TRANSFERING:
			case RINGBACK:
				sub = p->sub[i];
				return sub;
			case CALLWAITING:
			case ONHOLD:
				break;
			case ONHOOK:
			case ANSWER: //Remove this state
			case CALLENDED:
				if (!sub) {
					sub = p->sub[i];
				}
				break;
			default:
				ast_log(LOG_WARNING, "Unhandled channel state %d\n", sub->channel_state);
				break;
		}
	}

	return sub;
}

static struct brcm_subchannel *brcm_get_callwaiting_subchannel(const struct brcm_pvt *p)
{
	struct brcm_subchannel *sub;
	int i;
	for(i=0; i<NUM_SUBCHANNELS; i++) {
			sub = p->sub[i];
			if (sub->channel_state == CALLWAITING) {
				return sub;
			}
	}
	return NULL;
}

static struct brcm_subchannel *brcm_get_onhold_subchannel(const struct brcm_pvt *p)
{
	struct brcm_subchannel *sub;
	int i;
	for(i=0; i<NUM_SUBCHANNELS; i++) {
			sub = p->sub[i];
			if (sub->channel_state == ONHOLD) {
				return sub;
			}
	}
	return NULL;
}

/* Hangup incoming call after call waiting times out */
static int cwtimeout_cb(const void *data)
{
	struct brcm_subchannel *sub;
	struct ast_channel *owner = NULL;

	ast_debug(2, "No response to call waiting, hanging up\n");

	sub = (struct brcm_subchannel *) data;
	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "Cwtimeout callback");
	sub->cw_timer_id = -1;
	if (sub->owner) {
		ast_channel_ref(sub->owner);
		owner = sub->owner;
	}
	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);

	if (owner) {
		ast_channel_lock(owner);
		owner->hangupcause = AST_CAUSE_USER_BUSY;
		ast_queue_control(owner, AST_CONTROL_BUSY);
		ast_channel_unlock(owner);
		ast_channel_unref(owner);
	}

	return 0;
}

/* Hangup calls if not done by remote after R4 transfer */
static int r4hanguptimeout_cb(const void *data)
{
	struct brcm_subchannel *sub;
	struct brcm_subchannel *peer_sub;

	struct ast_channel *sub_owner = NULL;
	struct ast_channel *peer_sub_owner = NULL;

	ast_debug(2, "No hangup from remote after remote transfer using R4, hanging up\n");

	sub = (struct brcm_subchannel *) data;
	peer_sub = brcm_subchannel_get_peer(sub);

	//ast_mutex_lock(&sub->parent->lock);
	pvt_lock(sub->parent, "r4hanguptimeout callback");

	sub->r4_hangup_timer_id = -1;
	brcm_subchannel_set_state(peer_sub, CALLENDED);
	brcm_subchannel_set_state(sub, CALLENDED);

	if (sub->owner) {
		ast_channel_ref(sub->owner);
		sub_owner = sub->owner;
	}
	if (peer_sub->owner) {
		ast_channel_ref(peer_sub->owner);
		peer_sub_owner = peer_sub->owner;
	}
	//ast_mutex_unlock(&sub->parent->lock);
	pvt_unlock(sub->parent);

	if (sub_owner) {
		ast_queue_control(sub_owner, AST_CONTROL_HANGUP);
		ast_channel_unref(sub_owner);
	}

	if (peer_sub_owner) {
		ast_queue_control(peer_sub_owner, AST_CONTROL_HANGUP);
		ast_channel_unref(peer_sub_owner);
	}

	return 0;
}

static int dialtone_init_cb(const void *data)
{
	struct brcm_pvt *p = (struct brcm_pvt *) data;
	pvt_lock(p, "dialtone init callback");
	//ast_mutex_lock(&p->lock);
	brcm_dialtone_init(p);
	//ast_mutex_unlock(&p->lock);
	pvt_unlock(p);
	return 0;
}

/*
 * Helper function that tells asterisk to start a call on the provided pvt/sub/context
 * using the content of the dtmf buffer.
 */
static void brcm_start_calling(struct brcm_pvt *p, struct brcm_subchannel *sub, char* context)
{
	ast_verbose("Starting pbx in context %s with cid: %s ext: %s\n", context, p->cid_num, p->ext);
	sub->channel_state = DIALING;
	ast_copy_string(p->ext, p->dtmfbuf, sizeof(p->dtmfbuf));

	/* Reset the dtmf buffer */
	brcm_reset_dtmf_buffer(p);

	/* Reset hook flash state */
	p->hf_detected = 0;

	/* Start the pbx */
	if (!sub->connection_init) {
		sub->connection_id = ast_atomic_fetchadd_int((int *)&current_connection_id, +1);
		brcm_create_connection(sub);
	}

	/* Changed state from AST_STATE_UP to AST_STATE_RING ito get the brcm_answer callback
	 * which is needed for call waiting. */
	brcm_new(sub, AST_STATE_RING, context, NULL, 0);
}

/*
 * Start calling if we have a (partial) match in asterisks dialplan after an interdigit timeout.
 * Called on scheduler thread.
 */
static int handle_interdigit_timeout(const void *data)
{
	ast_debug(9, "Interdigit timeout\n");
	struct brcm_pvt *p = (struct brcm_pvt *) data;
	//ast_mutex_lock(&p->lock);
	pvt_lock(p, "interdigit callback");
	p->interdigit_timer_id = -1;
	struct brcm_subchannel *sub = brcm_get_active_subchannel(p);

	if (ast_exists_extension(NULL, p->context, p->dtmfbuf, 1, p->cid_num))
	{
		//We have at least one matching extension in "normal" context,
		//and interdigit timeout has passed, so have asterisk start calling.
		//Asterisk will select the best matching extension if there are more than one possibility.
		ast_debug(9, "Interdigit timeout, extension(s) matching %s found\n", p->dtmfbuf);
		brcm_start_calling(p, sub, p->context);
	}
	//ast_mutex_unlock(&p->lock);
	pvt_unlock(p);
	return 0;
}

/*
 * Start autodialing if we have an autodial extension.
 * Called on scheduler thread.
 */
static int handle_autodial_timeout(const void *data)
{
	ast_debug(9, "Autodial timeout\n");
	struct brcm_pvt *p = (struct brcm_pvt *) data;
	pvt_lock(p, "autodial timeout");
	//ast_mutex_lock(&p->lock);
	p->autodial_timer_id = -1;
	struct brcm_subchannel *sub = brcm_get_active_subchannel(p);
	line_settings *s = &line_config[p->line_id];

	if (ast_exists_extension(NULL, p->context, s->autodial_ext, 1, p->cid_num))
	{
		brcm_stop_dialtone(p);
		ast_copy_string(p->dtmfbuf, s->autodial_ext, sizeof(p->dtmfbuf));
		ast_debug(9, "Autodialing extension: %s\n", p->dtmfbuf);
		brcm_start_calling(p, sub, p->context);
	}
	//ast_mutex_unlock(&p->lock);
	pvt_unlock(p);
	return 0;
}

/*
 * Start calling if we have a match in asterisks dialplan.
 * Called after each new DTMF event, from monitor_events thread,
 * with the required locks already held.
 */
void handle_dtmf_calling(const struct brcm_subchannel *sub)
{
	struct brcm_pvt *p = sub->parent;
	int dtmfbuf_len = strlen(p->dtmfbuf);
	char dtmf_last_char = p->dtmfbuf[(dtmfbuf_len - 1)];

	if (ast_exists_extension(NULL, p->context_direct, p->dtmfbuf, 1, p->cid_num) && !ast_matchmore_extension(NULL, p->context_direct, p->dtmfbuf, 1, p->cid_num))
	{
		//We have a full match in the "direct" context, so have asterisk place a call immediately
		ast_debug(9, "Direct extension matching %s found\n", p->dtmfbuf);
		brcm_start_calling(p, sub, p->context_direct);
	}
	else if (ast_exists_extension(NULL, p->context, p->dtmfbuf, 1, p->cid_num) && dtmf_last_char == 0x23) {
		//We have a match in the "normal" context, and user ended the dialling sequence with a #,
		//so have asterisk place a call immediately
		ast_debug(9, "Pound-key pressed during dialling, extension %s found\n", p->dtmfbuf);
		brcm_start_calling(p, sub, p->context);
	}
	else if (ast_exists_extension(NULL, p->context, p->dtmfbuf, 1, p->cid_num) && !ast_matchmore_extension(NULL, p->context, p->dtmfbuf, 1, p->cid_num))
	{
		//We have a full match in the "normal" context, so have asterisk place a call immediately,
		//since no more digits can be added to the number
		//(this is unlikely to happen since there is probably a "catch-all" extension)
		ast_debug(9, "Unique extension matching %s found\n", p->dtmfbuf);
		brcm_start_calling(p, sub, p->context);
	}
	else {
		//No matches. We schedule a (new) interdigit timeout to occur
		int timeoutmsec = line_config[p->line_id].timeoutmsec;
		ast_debug(9, "Scheduling new interdigit timeout in %d msec\n", timeoutmsec);
		p->interdigit_timer_id = ast_sched_thread_add(sched, timeoutmsec, handle_interdigit_timeout, p);
	}
}

/* 
 * Perform actions for hook flash.
 * Preconditions: One subchannel should be in CALLWAITING or ONHOLD,
 * 		  One subchannel should be in INCALL.
 * 		  channel locks are held
 *		  brcm_pvt->lock is held
 */
static void handle_hookflash(struct brcm_subchannel *sub, struct brcm_subchannel *sub_peer,
		struct ast_channel *owner, struct ast_channel *peer_owner)
{
	struct brcm_pvt *p = sub->parent;

	if (p->dtmf_first < 0) {
		/* If current subchannel is in call and peer subchannel is idle, provide dialtone */
		if (sub->channel_state == INCALL && (sub_peer->channel_state == ONHOOK || sub_peer->channel_state == CALLENDED)) {
			ast_debug(2, "R while in call and idle peer subchannel\n");

			brcm_reset_dtmf_buffer(p);
			p->hf_detected = 0;

			/* Put current call on hold */
			if (owner) {
				brcm_mute_connection(sub);
				brcm_subchannel_set_state(sub, ONHOLD);
				ast_queue_control(owner, AST_CONTROL_HOLD);
			}

			/* Provide new line */
			brcm_signal_dialtone(p);
			brcm_subchannel_set_state(sub_peer, OFFHOOK);

		/* If offhook/dialing/calling and peer subchannel is on hold, switch call */
		} else if ((sub->channel_state == DIALING || sub->channel_state == OFFHOOK || sub->channel_state == CALLING || sub->channel_state == RINGBACK)
				&& sub_peer->channel_state == ONHOLD) {

			ast_debug(2, "R while offhook/dialing and peer subchannel on hold\n");

			brcm_reset_dtmf_buffer(p);
			p->hf_detected = 0;

			if (sub->channel_state == OFFHOOK) {
				brcm_stop_dialtone(p);
			}
			brcm_subchannel_set_state(sub, ONHOOK);

			/* Hang up current */
			if(owner) {
				ast_queue_control(owner, AST_CONTROL_HANGUP);
			}

			/* Pick up old */
			if (peer_owner) {
				brcm_unmute_connection(sub_peer);

				//Asterisk jitter buffer causes one way audio when going from unhold.
				//This is a workaround until jitter buffer is handled by DSP.
				ast_jb_destroy(peer_owner);

				ast_queue_control(peer_owner, AST_CONTROL_UNHOLD);
				brcm_subchannel_set_state(sub_peer, INCALL);
			}

		/* Switch back to old call (remote hung up) */
		} else if ((sub->channel_state == ONHOOK || sub->channel_state == CALLENDED)
				&& sub_peer->channel_state == ONHOLD) {

			ast_debug(2, "R when idle and peer subchannel on hold\n");

			p->hf_detected = 0;

			/* Hang up current */
			if (owner) {
				ast_queue_control(owner, AST_CONTROL_HANGUP);
			}

			/* Pick up old */
			if (peer_owner) {
				brcm_unmute_connection(sub_peer);

				//Asterisk jitter buffer causes one way audio when going from unhold.
				//This is a workaround until jitter buffer is handled by DSP.
				ast_jb_destroy(peer_owner);

				ast_queue_control(peer_owner, AST_CONTROL_UNHOLD);
				brcm_subchannel_set_state(sub_peer, INCALL);
			}
		}

		return;
	}

	switch (p->dtmf_first) {
		/* Force busy on waiting call or hang up call on hold */
		case '0':
			if (sub->channel_state == INCALL && sub_peer->channel_state == CALLWAITING) {
				ast_debug(2, "Sending busy to waiting call\n");

				if (ast_sched_thread_del(sched, sub_peer->cw_timer_id)) {
					ast_log(LOG_WARNING, "Failed to remove scheduled call waiting timer\n");
				}
				sub_peer->cw_timer_id = -1;

				peer_owner->hangupcause = AST_CAUSE_USER_BUSY;
				ast_queue_control(peer_owner, AST_CONTROL_BUSY);
			} else if (sub->channel_state == INCALL && sub_peer->channel_state == ONHOLD) {
				ast_debug(2, "Hanging up call on hold\n");

				sub_peer = brcm_get_onhold_subchannel(p);

				brcm_close_connection(sub_peer);
				ast_queue_control(peer_owner, AST_CONTROL_HANGUP);
				brcm_subchannel_set_state(sub_peer, CALLENDED);
			}
			break;

		/* Hangup current call and answer waiting call */
		case '1':
			if (sub->channel_state == INCALL && (sub_peer->channel_state == CALLWAITING || sub_peer->channel_state == ONHOLD)) {

				/* Close connection and hangup active subchannel */
				brcm_close_connection(sub);
				if (owner) {
					ast_queue_control(owner, AST_CONTROL_HANGUP);
				}
				brcm_subchannel_set_state(sub, CALLENDED);

				if (sub_peer->channel_state == CALLWAITING) {
					ast_log(LOG_WARNING, "R1 call waiting\n");
					/* Stop call waiting tone on current call */
					brcm_stop_callwaiting(p);

					if (ast_sched_thread_del(sched, sub_peer->cw_timer_id)) {
						ast_log(LOG_WARNING, "Failed to remove scheduled call waiting timer\n");
					}
					sub_peer->cw_timer_id = -1;

					/* Pick up call waiting */
					if (!sub_peer->connection_init) {
						ast_debug(9, "create_connection()\n");
						brcm_create_connection(sub_peer);
					}
					if (peer_owner) {
						ast_queue_control(peer_owner, AST_CONTROL_ANSWER);
						brcm_subchannel_set_state(sub_peer, INCALL);
					}
				} else if (sub_peer->channel_state == ONHOLD) {
					ast_log(LOG_WARNING, "R1 Unholding\n");

					/* Unhold inactive subchannel */
					if (peer_owner) {
						brcm_unmute_connection(sub_peer);

						//Asterisk jitter buffer causes one way audio when going from unhold.
						//This is a workaround until jitter buffer is handled by DSP.
						ast_jb_destroy(peer_owner);

						ast_queue_control(peer_owner, AST_CONTROL_UNHOLD);
						brcm_subchannel_set_state(sub_peer, INCALL);
					}
				}
			}
			break;

		/* Answer waiting call and put other call on hold (switch calls) */
		case '2':
			if (sub->channel_state == INCALL && (sub_peer->channel_state == CALLWAITING || sub_peer->channel_state == ONHOLD)) {

				brcm_mute_connection(sub);
				if (owner) {
					ast_queue_control(owner, AST_CONTROL_HOLD);
				}

				if (sub_peer->channel_state == CALLWAITING) {
					ast_log(LOG_WARNING, "R2 Call waiting\n");

					/* Stop call waiting tone on current call */
					brcm_stop_callwaiting(p);

					/* Cancel timer */
					if (ast_sched_thread_del(sched, sub_peer->cw_timer_id)) {
						ast_log(LOG_WARNING, "Failed to remove scheduled call waiting timer\n");
					}
					sub_peer->cw_timer_id = -1;

					/* Pick up call waiting */
					if (!sub_peer->connection_init) {
						ast_debug(9, "create_connection()\n");
						brcm_create_connection(sub_peer);
					}
					if (peer_owner) {
						ast_queue_control(peer_owner, AST_CONTROL_ANSWER);
						brcm_subchannel_set_state(sub_peer, INCALL);
					}
				} else if (sub_peer->channel_state == ONHOLD) {
					ast_log(LOG_WARNING, "R2 on hold\n");

					/* Unhold inactive subchannel */
					if (peer_owner) {
						brcm_unmute_connection(sub_peer);

						//Asterisk jitter buffer causes one way audio when going from unhold.
						//This is a workaround until jitter buffer is handled by DSP.
						ast_jb_destroy(peer_owner);

						ast_queue_control(peer_owner, AST_CONTROL_UNHOLD);
						brcm_subchannel_set_state(sub_peer, INCALL);
					}
				}

				brcm_subchannel_set_state(sub, ONHOLD);
			}

			break;

		/* Connect waiting call to existing call to create 3-way */
		case '3':
			if (sub->channel_state == INCALL && sub_peer->channel_state == ONHOLD) {
				ast_debug(2, "DTMF3 after HF\n");

				/* Unhold inactive subchannel */
				if (peer_owner) {
					brcm_unmute_connection(sub_peer);

					//Asterisk jitter buffer causes one way audio when going from unhold.
					//This is a workaround until jitter buffer is handled by DSP.
					ast_jb_destroy(peer_owner);

					ast_queue_control(peer_owner, AST_CONTROL_UNHOLD);
					brcm_subchannel_set_state(sub_peer, INCALL);
				}

				/* Switch all connections to conferencing mode */
				brcm_create_conference(p);
			}
			break;

		/* Remote transfer held call to active call */
		case '4':
			ast_debug(2, "R4 Transfer\n");
			if (sub->channel_state == INCALL && sub_peer->channel_state == ONHOLD) {

				if (owner && peer_owner) {
					struct ast_channel *bridged_chan = ast_bridged_channel(peer_owner);
					if (bridged_chan) {
						ast_verbose("Performing R4 transfer to %s, replacing call on %s\n", sub->parent->ext, bridged_chan->name);

						struct ast_transfer_remote_data data;
						strcpy(data.exten, sub->parent->ext);
						strcpy(data.replaces, bridged_chan->name);

						ast_queue_control_data(owner, AST_CONTROL_TRANSFER_REMOTE, &data, sizeof(data));
						brcm_subchannel_set_state(sub, TRANSFERING);
					}
					else {
						ast_log(LOG_ERROR, "Failed to fetch bridged channel\n");
					}
				}
				else {
					ast_log(LOG_ERROR, "Sub and/or peer sub had no owner\n");
				}
			}
			break;

		default:
			ast_log(LOG_NOTICE, "Unhandled DTMF %c\n", p->dtmfbuf[0]);
			break;
	}

	brcm_reset_dtmf_buffer(p);
}

void handle_dtmf(EPEVT event,
		struct brcm_subchannel *sub, struct brcm_subchannel *sub_peer,
		struct ast_channel *owner, struct ast_channel *peer_owner)
{
	struct brcm_pvt *p;
	const DTMF_CHARNAME_MAP *dtmfMap = dtmf_to_charname;
	struct timeval tim;

	/* Lookup event to find corresponding DTMF */
	while (dtmfMap->event != event) {
		dtmfMap++;
		if (dtmfMap->event == EPEVT_LAST) {
			/* DTMF not found. Should not be reached. */
			ast_log(LOG_WARNING, "Failed to handle DTMF. Event not found.\n");
			return;
		}
	}

	char dtmf_button = dtmfMap->c;
	gettimeofday(&tim, NULL);
	p = sub->parent;

	if (p->dtmf_first < 0) {
		p->dtmf_first = dtmf_button;
		ast_debug(9,"Pressed DTMF %s\n", dtmfMap->name);
		/* Do not send AST_FRAME_DTMF_BEGIN to allow DSP-generated tone to pass through */
	}
	else if (p->dtmf_first == dtmf_button) {
		ast_debug(9,"Depressed DTMF %s\n", dtmfMap->name);
		if (p->hf_detected) {
			ast_debug(2, "DTMF after HF\n");
			p->hf_detected = 0;
			/* HF while not in a call doesn't make sense */
			if (sub->channel_state == INCALL &&
				(brcm_in_callwaiting(p) || brcm_in_onhold(p))) {
				handle_hookflash(sub, sub_peer, owner, peer_owner);
			} else {
				ast_debug(2, "DTMF after HF while not in call. state: %d, callwaiting: %d, onhold: %d\n",
					sub->channel_state,
					brcm_in_callwaiting(p),
					brcm_in_onhold(p));
			}
		} else {
			p->dtmfbuf[p->dtmf_len] = dtmf_button;
			p->dtmf_len++;
			p->dtmfbuf[p->dtmf_len] = '\0';
			p->dtmf_first = -1;
			if (sub->channel_state == OFFHOOK) {
				brcm_subchannel_set_state(sub, DIALING);
			}
		}
	}
	else {
		p->dtmf_first = -1;
	}
}

static char phone_2digit(char c)
{
	if (c == 11)
		return '#';
	else if (c == 10)
		return '*';
	else if (c == 12)
		return 'A';
	else if (c == 13)
		return 'B';
	else if (c == 14)
		return 'C';
	else if (c == 15)
		return 'D';
	else if ((c < 10) && (c >= 0))
		return '0' + c;
	else
		return '?';
}

static void *brcm_monitor_packets(void *data)
{
	struct brcm_subchannel *sub;
	UINT8 pdata[PACKET_BUFFER_SIZE] = {0};
	EPPACKET epPacket;
	ENDPOINTDRV_PACKET_PARM tPacketParm;
	int rtp_packet_type  = BRCM_UNKNOWN;
	RTPPACKET *rtp;
	int current_dtmf_digit = -1;
	
	rtp = (RTPPACKET *)pdata;
	
	ast_verbose("Packets thread starting\n");

	while(packets) {
		int drop_frame = 0;
		struct ast_frame fr  = {0};
		fr.src = "BRCM";

		epPacket.mediaType   = 0;
		epPacket.packetp     = pdata;
		tPacketParm.epPacket = &epPacket;
		tPacketParm.cnxId    = 0;
		tPacketParm.length   = 0;

		if (ioctl(endpoint_fd, ENDPOINTIOCTL_ENDPT_GET_PACKET, &tPacketParm) == IOCTL_STATUS_SUCCESS) {

			if (tPacketParm.length <= 2) {
				ast_log(LOG_WARNING, "Ignoring RTP package - too short\n");
				continue;
			}

			/* Classify the rtp packet */
			rtp_packet_type = brcm_classify_rtp_packet(pdata[1]);

			sub = brcm_get_subchannel_from_connectionid(iflist, tPacketParm.cnxId);
			if (sub == NULL) {
				ast_log(LOG_ERROR, "Failed to find subchannel for connection id %d\n", tPacketParm.cnxId);
				continue;
			}

			pvt_lock(sub->parent, "brcm monitor packets");
			//ast_mutex_lock(&sub->parent->lock);
			struct ast_channel *owner = NULL;
			if (sub->owner) {
				ast_channel_ref(sub->owner);
				owner = sub->owner;
			}

			/* We seem to get packets from DSP even if connection is muted (perhaps muting only affects packet callback).
			 * Drop packets if subchannel is on hold. */
			/* Handle rtp packet according to classification */
			if (sub->channel_state != ONHOLD && rtp_packet_type == BRCM_AUDIO && sub && pdata[0] == 0x80) {
				fr.frametype = AST_FRAME_VOICE;
				fr.offset = 0;
				fr.data.ptr =  (pdata + 12);
				fr.datalen = tPacketParm.length - 12;

				switch (pdata[1]) {
					case PCMU:
						fr.subclass.codec = AST_FORMAT_ULAW;
						fr.samples = 160;
						break;
					case PCMA:
						fr.subclass.codec = AST_FORMAT_ALAW;
						fr.samples = 160;
						break;
					case G726:
						fr.subclass.codec = AST_FORMAT_G726;
						fr.samples = 160; //for 20 ms frame size
						break;
					case G723:
						fr.subclass.codec = AST_FORMAT_G723_1;
						fr.samples = 240;
						break;
					case G729:
						fr.subclass.codec = AST_FORMAT_G729A;
						fr.samples = 80; //for 10 ms frame size
						break;
					default:
						ast_log(LOG_WARNING, "Unknown rtp codec id [%d]\n", pdata[1]);
						break;
				}
			} else if  (rtp_packet_type == BRCM_DTMF) {
				
				unsigned int duration = (pdata[14] << 8 | pdata[15]);
				unsigned int dtmf_end = pdata[13] & 128;
				unsigned int event = phone_2digit(pdata[12]);

				/* Use DTMFBE instead */
				ast_debug(5, "[%d,%d] |%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|\n", rtp_packet_type, tPacketParm.length, pdata[0], pdata[1], pdata[2], pdata[3], pdata[4], pdata[5], pdata[6], pdata[7], pdata[8], pdata[9], pdata[10], pdata[11], pdata[12], pdata[13], pdata[14], pdata[15]);
				ast_log(LOG_DTMF, " === Event %d Duration (samples) %d End? %s\n",  event, duration, dtmf_end ? "Yes" : "no");

				if (dtmf_end && sub->dtmf_lastwasend) {
					/* We correctly get a series of END messages. We should skip the
					   copies */
					ast_debug(5, "---> Skipping DTMF_END duplicate \n");
					drop_frame = 1;

				} else {
					if (dtmf_end) {
						fr.frametype = AST_FRAME_DTMF_END;
						sub->dtmf_lastwasend = 1;
						sub->dtmf_sending = 0;
					} else {
						sub->dtmf_lastwasend = 0;
						if (sub->dtmf_sending == 0) { /* DTMF starts here */
							fr.frametype = AST_FRAME_DTMF_BEGIN;
							sub->dtmf_sending = 1;
						} else {
							fr.frametype = AST_FRAME_DTMF_CONTINUE;
						}
					}
					sub->dtmf_duration = duration;
					fr.subclass.integer = phone_2digit(pdata[12]);
					if (fr.frametype == AST_FRAME_DTMF_END || fr.frametype == AST_FRAME_DTMF_CONTINUE) {
						fr.samples = duration;
						/* Assuming 8000 samples/second - narrowband alaw or ulaw */
						fr.len = ast_tvdiff_ms(ast_samp2tv(duration, 8000), ast_tv(0, 0));
					}
					ast_debug(2, "Sending DTMF [%c, Len %d] (%s)\n", fr.subclass.integer, fr.len, (fr.frametype==AST_FRAME_DTMF_END) ? "AST_FRAME_DTMF_END" : (fr.frametype == AST_FRAME_DTMF_BEGIN) ? "AST_FRAME_DTMF_BEGIN" : "AST_FRAME_DTMF_CONTINUE");
				}
			}
			//ast_mutex_unlock(&sub->parent->lock);
			pvt_unlock(sub->parent);

			if (owner) {
				if (!drop_frame && owner->_state == AST_STATE_UP || owner->_state == AST_STATE_RING) {
					ast_queue_frame(owner, &fr);
				}
				ast_channel_unref(owner);
			}
		}
	} /* while */

	ast_verbose("Packets thread ended\n");
	/* Never reached */
	return NULL;
}

void brcm_cancel_dialing_timeouts(struct brcm_pvt *p)
{
	//If we have interdigit timeout, cancel it
	if (p->interdigit_timer_id > 0) {
		p->interdigit_timer_id = ast_sched_thread_del(sched, p->interdigit_timer_id);
	}

	//If we have a autodial timeout, cancel it
	if (p->autodial_timer_id > 0) {
		p->autodial_timer_id = ast_sched_thread_del(sched, p->autodial_timer_id);
	}
}

static void *brcm_monitor_events(void *data)
{
	ENDPOINTDRV_EVENT_PARM tEventParm = {0};
	int rc = IOCTL_STATUS_FAILURE;
	struct timeval tim;

	while (monitor) {
		struct brcm_pvt *p = NULL;
		struct brcm_subchannel *sub = NULL;

		tEventParm.size = sizeof(ENDPOINTDRV_EVENT_PARM);
		tEventParm.length = 0;
		p = iflist;

		ast_verbose("Waiting for event\n");
		/* Get the event from the endpoint driver. */
		rc = ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_GET_EVENT, &tEventParm);
		if( rc != IOCTL_STATUS_SUCCESS ) {
			ast_verbose("ENDPOINTIOCTL_ENDPT_GET_EVENT failed, endpoint_fd = %x\n", endpoint_fd);
			continue;
		}

		ast_debug(9, "Event %d detected\n", tEventParm.event);
		p = brcm_get_pvt_from_lineid(iflist, tEventParm.lineId);
		if (!p) {
			ast_verbose("No pvt with the correct line_id %d found!\n", tEventParm.lineId);
			continue;
		}

		/* Get locks in correct order */
		//ast_mutex_lock(&p->lock);
		pvt_lock(p, "brcm monitor events");
		sub = brcm_get_active_subchannel(p);
		struct brcm_subchannel *sub_peer = brcm_subchannel_get_peer(sub);
		struct ast_channel *owner = NULL;
		struct ast_channel *peer_owner = NULL;
		if (sub->owner) {
			ast_channel_ref(sub->owner);
			owner = sub->owner;
		}
		if (sub_peer->owner) {
			ast_channel_ref(sub_peer->owner);
			peer_owner = sub_peer->owner;
		}
		pvt_unlock(p);
		//ast_mutex_unlock(&p->lock);

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
		pvt_lock(p, "brcm monitor events");
		//ast_mutex_lock(&p->lock);

		ast_verbose("me: got mutex\n");
		if (sub) {

			switch (tEventParm.event) {
				case EPEVT_OFFHOOK: {
					ast_debug(9, "EPEVT_OFFHOOK detected\n");

					/* Reset the dtmf buffer */
					memset(p->dtmfbuf, 0, sizeof(p->dtmfbuf));
					p->dtmf_len          = 0;
					p->dtmf_first        = -1;
					p->dtmfbuf[p->dtmf_len] = '\0';
					brcm_subchannel_set_state(sub, OFFHOOK);
					ast_verbose("Sending manager event\n");
					manager_event(EVENT_FLAG_SYSTEM, "BRCM", "Status: OFF %d\r\n", p->line_id);

					if (owner) {
						if (!sub->connection_init) {
							ast_debug(9, "create_connection()\n");
							brcm_create_connection(sub);
						}

						brcm_subchannel_set_state(sub, INCALL);
						ast_queue_control(owner, AST_CONTROL_ANSWER);
					}
					else if (sub->channel_state == OFFHOOK) {
						/* EPEVT_OFFHOOK changed enpoint state to OFFHOOK, apply dialtone */
						brcm_signal_dialtone(p);
						line_settings *s = &line_config[p->line_id];
						p->autodial_timer_id = ast_sched_thread_add(sched, s->autodial_timeoutmsec, handle_autodial_timeout, p);
					}
					break;
				}
				case EPEVT_ONHOOK: {
					ast_debug(9, "EPEVT_ONHOOK detected\n");

					int perform_remote_transfer = 0;

					if (sub->channel_state == OFFHOOK) {
						/* Received EPEVT_ONHOOK in state OFFHOOK, stop dialtone */
						brcm_stop_dialtone(p);
					}
					else if (sub->channel_state == RINGBACK) {
						line_settings *s = &line_config[sub->parent->line_id];
						ast_debug(2, "Semi-attended transfer active\n");
						perform_remote_transfer = s->hangup_xfer;
					}

					brcm_subchannel_set_state(sub, ONHOOK);
					ast_verbose("Sending manager event\n");
					manager_event(EVENT_FLAG_SYSTEM, "BRCM", "Status: ON %d\r\n", p->line_id);

					brcm_cancel_dialing_timeouts(p);

					/* Reset the dtmf buffer */
					memset(p->dtmfbuf, 0, sizeof(p->dtmfbuf));
					p->dtmf_len          = 0;
					p->dtmf_first        = -1;
					p->dtmfbuf[p->dtmf_len] = '\0';
					brcm_close_connection(sub);

					if (owner) {
						ast_queue_control(owner, AST_CONTROL_HANGUP);
					}

					//TRANSFER_REMOTE
					if (perform_remote_transfer) {
						if (sub_peer->channel_state == ONHOLD && peer_owner) {
							ast_verbose("Performing transfer-on-hangup to %s\n", sub_peer->parent->ext);

							struct ast_transfer_remote_data data;
							strcpy(data.exten, sub_peer->parent->ext);
							data.replaces[0] = '\0'; //Not replacing any call
							ast_queue_control_data(peer_owner, AST_CONTROL_TRANSFER_REMOTE, &data, sizeof(data));
							brcm_subchannel_set_state(sub_peer, TRANSFERING);
						}
					}

					//TODO: possible bug below - we don't change the channel_state when hanging up

					/* Hangup peer subchannels in call, on hold or in call waiting */
					if (sub_peer->channel_state == CALLWAITING) {
						if (ast_sched_thread_del(sched, sub_peer->cw_timer_id)) {
							ast_log(LOG_WARNING, "Failed to remove scheduled call waiting timer\n");
						}
						sub_peer->cw_timer_id = -1;

						if (peer_owner) {
							peer_owner->hangupcause = AST_CAUSE_USER_BUSY;
							ast_queue_control(peer_owner, AST_CONTROL_BUSY);
						}
					}
					else if (peer_owner && sub_peer->channel_state != TRANSFERING) {
						ast_debug(2, "Hanging up call (not transfering)\n");
						ast_queue_control(peer_owner, AST_CONTROL_HANGUP);
					}
					break;
				}
				case EPEVT_DTMF0:
				case EPEVT_DTMF1:
				case EPEVT_DTMF2:
				case EPEVT_DTMF3:
				case EPEVT_DTMF4:
				case EPEVT_DTMF5:
				case EPEVT_DTMF6:
				case EPEVT_DTMF7:
				case EPEVT_DTMF8:
				case EPEVT_DTMF9:
				case EPEVT_DTMFA:
				case EPEVT_DTMFB:
				case EPEVT_DTMFC:
				case EPEVT_DTMFD:
				case EPEVT_DTMFS:
				case EPEVT_DTMFH:
				{
					brcm_cancel_dialing_timeouts(p);

					unsigned int old_state = sub->channel_state;
					ast_debug(2, "====> GOT DTMF %d\n", tEventParm.event-1);
					handle_dtmf(tEventParm.event, sub, sub_peer, owner, peer_owner);
					if (sub->channel_state == DIALING && old_state != sub->channel_state) {
						/* DTMF event took channel state to DIALING. Stop dial tone. */
						ast_debug(2, "Dialing. Stop dialtone.\n");
						brcm_stop_dialtone(p);
					}

					if (sub->channel_state == DIALING) {
						ast_debug(2, "Handle DTMF calling\n");
						handle_dtmf_calling(sub);
					}

					break;
				}
				case EPEVT_DTMFL:
					ast_verbose("EPEVT_DTMFL\n");
					break;
				case EPEVT_FLASH:
					//Ignore, handle via early off/on hook
					break;
				case EPEVT_EARLY_OFFHOOK:
					ast_verbose("EPEVT_EARLY_OFFHOOK\n");
					gettimeofday(&tim, NULL);
					unsigned int now = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;
					if (now - p->last_early_onhook_ts < hfmaxdelay) {
						p->last_early_onhook_ts = 0;
						if (p->hf_detected == 1) {
							p->hf_detected = 0;
						} else {
							p->hf_detected = 1;
							handle_hookflash(sub, sub_peer, owner, peer_owner);
						}
					}
					break;
				case EPEVT_EARLY_ONHOOK:
					ast_verbose("EPEVT_EARLY_ONHOOK\n");
					gettimeofday(&tim, NULL);
					p->last_early_onhook_ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;
					break;
				case EPEVT_MEDIA: ast_verbose("EPEVT_MEDIA\n"); break;
				case EPEVT_VBD_START:
					ast_verbose("EPEVT_VBD_START\n");
					if (owner) {
						ast_jb_destroy(owner);
					}
					break;
				default:
					ast_verbose("UNKNOWN event %d detected\n", tEventParm.event);
					break;
			}
		}

		//ast_mutex_unlock(&p->lock);
		pvt_unlock(p);
		ast_debug(9, "me: unlocked mutex\n");

		if (owner) {
			ast_channel_unlock(owner);
			ast_channel_unref(owner);
		}

		if (peer_owner) {
			ast_channel_unlock(peer_owner);
			ast_channel_unref(peer_owner);
		}
	}

	ast_verbose("Monitor thread ended\n");
	/* Never reached */
	return NULL;
}




static int start_threads(void)
{
	/* If we're supposed to be stopped -- stay stopped */
	if (monitor_thread == AST_PTHREADT_STOP)
		return 0;

	if (ast_mutex_lock(&monlock)) {
		ast_log(LOG_WARNING, "Unable to lock monitor\n");
		return -1;
	}

	if (monitor_thread == pthread_self()) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_WARNING, "Cannot kill myself\n");
		return -1;
	}

	if (monitor_thread != AST_PTHREADT_NULL) {
		if (ast_mutex_lock(&iflock)) {
			ast_mutex_unlock(&monlock);
			ast_log(LOG_WARNING, "Unable to lock the interface list\n");
			return -1;
		}

		monitor = 0;
		while (pthread_kill(monitor_thread, SIGURG) == 0)
			sched_yield();
		pthread_join(monitor_thread, NULL);
		ast_mutex_unlock(&iflock);
	}

	monitor = 1;

	/* Start an event polling thread */
	/* This thread blocks on ioctl and wakes up when an event is avaliable from the endpoint  */
	if (ast_pthread_create_background(&monitor_thread, NULL, brcm_monitor_events, NULL) < 0) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_ERROR, "Unable to start monitor thread.\n");
		return -1;
	}


	/* Start a dect event polling thread */
	/* This thread blocks on ioctl and wakes up when an event is avaliable from the endpoint  */
	dect = 1;
	if (ast_pthread_create_background(&dect_thread, NULL, brcm_monitor_dect, NULL) < 0) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_ERROR, "Unable to start dect thread.\n");
		return -1;
	}

	/* Start a new sound polling thread */
	/* This thread blocks on ioctl and wakes up when an rpt packet is avaliable from the endpoint  */
	/* It then enques the packet on the channel which owns the pvt   */
	packets = 1;
	if (ast_pthread_create_background(&packet_thread, NULL, brcm_monitor_packets, NULL) < 0) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_ERROR, "Unable to start event thread.\n");
		return -1;
	}


	ast_mutex_unlock(&monlock);
	return 0;
}

/* Load settings for each line */
static void brcm_initialize_pvt(struct brcm_pvt *p)
{
	line_settings *s = &line_config[p->line_id];

	ast_copy_string(p->language, s->language, sizeof(p->language));
	ast_copy_string(p->context, s->context, sizeof(p->context));
	ast_copy_string(p->context_direct, s->context_direct, sizeof(p->context_direct));
	ast_copy_string(p->cid_num, s->cid_num, sizeof(p->cid_num));
	ast_copy_string(p->cid_name, s->cid_name, sizeof(p->cid_name));
	ast_copy_string(p->dialtone_extension_hint_context, s->dialtone_extension_hint_context, sizeof(p->dialtone_extension_hint_context));
	ast_copy_string(p->dialtone_extension_hint, s->dialtone_extension_hint, sizeof(p->dialtone_extension_hint));
}

static struct brcm_pvt *brcm_allocate_pvt(const char *iface, int endpoint_type)
{
	/* Make a brcm_pvt structure for this interface */
	struct brcm_pvt *tmp;
	
	tmp = ast_calloc(1, sizeof(*tmp));
	if (tmp) {
		struct brcm_subchannel *sub;
		int i;

		for (i=0; i<NUM_SUBCHANNELS; i++) {
			sub = ast_calloc(1, sizeof(*sub));
			if (sub) {
				sub->id = i;
				sub->owner = NULL;
				sub->connection_id = -1;
				sub->connection_init = 0;
				sub->channel_state = ONHOOK;
				sub->time_stamp = 0;
				sub->sequence_number = 0;
				sub->ssrc = 0;
				sub->codec = -1;
				sub->parent = tmp;
				sub->cw_timer_id = -1;
				sub->r4_hangup_timer_id = -1;
				tmp->sub[i] = sub;
				ast_debug(2, "subchannel created\n");
			} else {
				ast_log(LOG_ERROR, "no subchannel created\n");
			}
		}
		tmp->line_id = -1;
		tmp->dtmf_len = 0;
		tmp->dtmf_first = -1;
		tmp->lastformat = -1;
		tmp->lastinput = -1;
		memset(tmp->ext, 0, sizeof(tmp->ext));
		tmp->next = NULL;
		tmp->last_early_onhook_ts = 0;
		tmp->endpoint_type = endpoint_type;
		tmp->dialtone = DIALTONE_UNKNOWN;
		tmp->dialtone_extension_cb_id = -1;
		tmp->dialtone_extension_cb_data = NULL;
		tmp->interdigit_timer_id = -1;
		tmp->autodial_timer_id = -1;
		ast_mutex_init(&tmp->lock);
		
		/* Low level signaling */
		if (endpoint_type == FXS) {
			tmp->tech = &fxs_tech;
		} else if (endpoint_type == DECT) {
			tmp->tech = &dect_tech;
		}
	}
	return tmp;
}


static void brcm_create_pvts(struct brcm_pvt *p, int mode) {
	int i;
	struct brcm_pvt *tmp = iflist;
	struct brcm_pvt *tmp_next;

	for (i=0 ; i<num_dect_endpoints ; i++) {
		tmp_next = brcm_allocate_pvt("", DECT);
		if (tmp == NULL) {
			iflist = tmp_next; //First loop round, set iflist to point at first pvt
			tmp    = tmp_next;
			tmp->next = NULL;
		} else {
			tmp->next = tmp_next;
			tmp_next->next = NULL;
			tmp = tmp_next;
		}
	}

	for (i=0; i<num_fxs_endpoints ; i++) {
		tmp_next = brcm_allocate_pvt("", FXS);
		if (tmp == NULL) {
			iflist = tmp_next; //First loop round, set iflist to point at first pvt
			tmp    = tmp_next;
			tmp->next = NULL;
		} else {
			tmp->next = tmp_next;
			tmp_next->next = NULL;
			tmp = tmp_next;
		}
	}
}


static void brcm_assign_line_id(struct brcm_pvt *p)
{
	struct brcm_pvt *tmp = p;
	int i;

	/* Assign line_id's */
	for (i=0 ; i<num_endpoints ; i++) {
		tmp->line_id = endptObjState[i].lineId;
		brcm_initialize_pvt(tmp);
		brcm_dialtone_init(tmp);
		int j;
		for (j=0; j<NUM_SUBCHANNELS; j++) {
			brcm_subchannel_set_state(tmp->sub[j], ONHOOK);
		}
		tmp = tmp->next;
	}
}


static int brcm_in_call(const struct brcm_pvt *p)
{
	int i;
	for (i=0; i<NUM_SUBCHANNELS; i++) {
		if (p->sub[i]->channel_state == INCALL) {
			return 1;
		}
	}

	return 0;
}

static int brcm_in_callwaiting(const struct brcm_pvt *p)
{
	int i;
	for (i=0; i<NUM_SUBCHANNELS; i++) {
		if (p->sub[i]->channel_state == CALLWAITING) {
			return 1;
		}
	}

	return 0;
}

static int brcm_in_onhold(const struct brcm_pvt *p)
{
	int i;
	for (i=0; i<NUM_SUBCHANNELS; i++) {
		if (p->sub[i]->channel_state == ONHOLD) {
			return 1;
		}
	}

	return 0;
}

static int brcm_active(const struct brcm_pvt *p)
{
	int i;
	for (i=0; i<NUM_SUBCHANNELS; i++) {
		if (p->sub[i]->channel_state != ONHOOK &&
		    p->sub[i]->channel_state != CALLENDED) {
			return 1;
		}
	}

	return 0;
}

/*
 * Return idle subchannel
 */
struct brcm_subchannel *brcm_get_idle_subchannel(const struct brcm_pvt *p)
{
	int i;
	for (i=0; i<NUM_SUBCHANNELS; i++) {
		if (p->sub[i]->channel_state == ONHOOK || p->sub[i]->channel_state == CALLENDED) {
			return p->sub[i];
		}
	}
	return NULL;
}

/*
 * Return free subchannel if conditions are met.
 */
static struct brcm_subchannel *brcm_get_idle_subchannel_incomingcall(const struct brcm_pvt *p)
{
	struct brcm_subchannel *sub = NULL;
	int i;

	for (i=0; i<NUM_SUBCHANNELS; i++) {
		if (p->sub[i]->channel_state == ONHOOK || p->sub[i]->channel_state == CALLENDED) {
			/* There is an idle subchannel */
			if (!sub) {
				/* which may be used */
				sub = p->sub[i];
				if (cw) {
					/* for call waiting or 'ordinary' call */
					if (brcm_active(p) && !brcm_in_call(p)) {
						/* if there had been a 'busy' subchannel in state INCALL */
						sub = NULL;
					}
					break;
				}
			}
		} else {
			/* There is a 'busy' subchannel */
			if (!cw) {
				/* and call waiting is disabled */
				sub = NULL;
				break;
			}
		}
	}

	if (sub) {
		ast_debug(2, "Got subchannel at %p\n", sub);
	}
	return sub;
}

static struct ast_channel *brcm_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause)
{
	format_t oldformat;
	struct brcm_pvt *p;
	struct brcm_subchannel *sub;
	struct ast_channel *tmp = NULL;
	int line_id = -1;

	char buf[256];
	ast_debug(1, "Asked to create a BRCM channel with formats: %s\n", ast_getformatname_multiple(buf, sizeof(buf), format));

	/* Search for an unowned channel */
	if (ast_mutex_lock(&iflock)) {
		ast_log(LOG_ERROR, "Unable to lock interface list???\n");
		return NULL;
	}
	
	/* Get line id */
	line_id = atoi((char*)data);
	ast_verbose("brcm_request = %s, line_id=%d, format %x\n", (char*) data, line_id, format);

	/* Map id to the correct pvt */
	p = brcm_get_pvt_from_lineid(iflist, line_id);

	/* If the id doesn't exist (p==NULL) use 0 as default */
	if (!p) {
		ast_log(LOG_ERROR, "Port id %s not found using default 0 instead.\n", (char*) data);
		p = iflist;
	}

	pvt_lock(p, "brcm request");
	//ast_mutex_lock(&p->lock);

	sub = brcm_get_idle_subchannel_incomingcall(p);

	/* Check that the request has an allowed format */
	format_t allowedformat = format & (AST_FORMAT_ALAW | AST_FORMAT_ULAW | AST_FORMAT_G729A | AST_FORMAT_G726 | AST_FORMAT_G723_1);

	if (!allowedformat) {
		ast_log(LOG_NOTICE, "Asked to get a channel of unsupported format %s\n", ast_getformatname(format));
		*cause = AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
	} else if (sub) {
		sub->connection_id = ast_atomic_fetchadd_int((int *)&current_connection_id, +1);
		tmp = brcm_new(sub, AST_STATE_DOWN, p->context, requestor ? requestor->linkedid : NULL, format);
	} else {
		*cause = AST_CAUSE_BUSY;
	}

	//ast_mutex_unlock(&p->lock);
	pvt_unlock(p);
	ast_mutex_unlock(&iflock);

	return tmp;
}


static void brcm_lock_pvts(void)
{
	struct brcm_pvt *p = iflist;
	while(p) {
		pvt_lock(p, "brcm lock pvts");
		//ast_mutex_lock(&p->lock);
		p = brcm_get_next_pvt(p);
	}
}

static void brcm_unlock_pvts(void)
{
	struct brcm_pvt *p = iflist;
	while(p) {
		pvt_unlock(p);
		//ast_mutex_unlock(&p->lock);
		p = brcm_get_next_pvt(p);
	}
}

/* parse gain value from config file */
static int parse_gain_value(const char *gain_type, const char *value)
{
	//Gain can be between -96 and 32 dB
	int gain = atoi(value);

	if (gain < GAIN_MIN) {
		ast_log(LOG_WARNING, "%s is a too low value for '%s' in '%s' config\n",
						value, gain_type, config);
		gain = GAIN_MIN;
	}

	if (gain > GAIN_MAX) {
		ast_log(LOG_WARNING, "%s is a too high value for '%s' in '%s' config\n",
							value, gain_type, config);
		gain = GAIN_MAX;
	}
	return gain;
}


static void brcm_show_subchannels(struct ast_cli_args *a, struct brcm_pvt *p)
{
	struct brcm_subchannel *sub;

	/* Output status for sub channels */
	int i;
	for (i=0; i<NUM_SUBCHANNELS; i++) {
		sub = p->sub[i];
		ast_cli(a->fd, "Subchannel: %d\n", sub->id);
		ast_cli(a->fd, "  Connection id       : %d\n", sub->connection_id);

		ast_cli(a->fd, "  Owner               : %d\n", sub->owner);
		ast_cli(a->fd, "  Channel state       : ");
		switch (sub->channel_state) {
			case ONHOOK: 	ast_cli(a->fd, "ONHOOK\n");  break;
			case OFFHOOK:	ast_cli(a->fd, "OFFHOOK\n"); break;
			case DIALING:	ast_cli(a->fd, "DIALING\n"); break;
			case INCALL:	ast_cli(a->fd, "INCALL\n");  break;
			case ANSWER:	ast_cli(a->fd, "ANSWER\n");  break;
			case CALLENDED: ast_cli(a->fd, "CALLENDED\n");  break;
			case RINGING:	ast_cli(a->fd, "RINGING\n"); break;
			case CALLWAITING:	ast_cli(a->fd, "CALLWAITING\n"); break;
			case ONHOLD:	ast_cli(a->fd, "ONHOLD\n"); break;
			case RINGBACK:	ast_cli(a->fd, "RINGBACK\n"); break;
			default:	ast_cli(a->fd, "UNKNOWN\n"); break;
		}
		ast_cli(a->fd, "  Connection init     : %d\n", sub->connection_init);
		ast_cli(a->fd, "  Codec used          : %s\n", brcm_get_codec_string(sub->codec));
		ast_cli(a->fd, "  RTP sequence number : %d\n", sub->sequence_number);
		ast_cli(a->fd, "  RTP SSRC            : %d\n", sub->ssrc);
		ast_cli(a->fd, "  RTP timestamp       : %d\n", sub->time_stamp);
		ast_cli(a->fd, "  CW Timer id         : %d\n", sub->cw_timer_id);
		ast_cli(a->fd, "  R4 Hangup Timer id  : %d\n", sub->r4_hangup_timer_id);
	}
}

static void brcm_show_pvts(struct ast_cli_args *a)
{
	struct brcm_pvt *p = iflist;
	int i = 0;
	
	while(p) {
		pvt_lock(p, "brcm show pvts");
		//ast_mutex_lock(&p->lock);
		ast_cli(a->fd, "\nPvt nr: %d\n",i);
		ast_cli(a->fd, "Line id             : %d\n", p->line_id);
		ast_cli(a->fd, "Pvt next ptr        : 0x%x\n", (unsigned int) p->next);
		ast_cli(a->fd, "Endpoint type       : ");
		switch (p->endpoint_type) {
			case FXS:  ast_cli(a->fd, "FXS\n");  break;
			case FXO:  ast_cli(a->fd, "FXO\n");  break;
			case DECT: ast_cli(a->fd, "DECT\n"); break;
			default: ast_cli(a->fd, "Unknown\n");
		}
		ast_cli(a->fd, "DTMF buffer         : %s\n", p->dtmfbuf);
		ast_cli(a->fd, "Default context     : %s\n", p->context);
		ast_cli(a->fd, "Direct context      : %s\n", p->context_direct);
		ast_cli(a->fd, "Last early onhook   : %d\n", p->last_early_onhook_ts);
		line_settings* s = &line_config[p->line_id];

		ast_cli(a->fd, "Echocancel          : %s\n", s->echocancel ? "on" : "off");
		ast_cli(a->fd, "Ringsignal          : %s\n", s->ringsignal ? "on" : "off");	
		ast_cli(a->fd, "DTMF compatibility  : %s\n", s->dtmf_compatibility ? "on" : "off");
		ast_cli(a->fd, "Dialout msecs       : %d\n", s->timeoutmsec);
		ast_cli(a->fd, "Autodial extension  : %s\n", s->autodial_ext);
		ast_cli(a->fd, "Autodial msecs      : %d\n", s->autodial_timeoutmsec);

		ast_cli(a->fd, "DTMF relay          : ");
		switch (s->dtmf_relay) {
			case EPDTMFRFC2833_DISABLED:  ast_cli(a->fd, "InBand\n");  break;
			case EPDTMFRFC2833_ENABLED:   ast_cli(a->fd, "RFC2833\n");  break;
			case EPDTMFRFC2833_SUBTRACT:  ast_cli(a->fd, "RFC2833_SUBTRACT\n"); break;
			default: ast_cli(a->fd, "Unknown\n");
		}

		ast_cli(a->fd, "Silence supr.       : ");
		switch (s->silence) {
			case 0: ast_cli(a->fd, "off\n"); break;
			case 1: ast_cli(a->fd, "transparent\n"); break;
			case 2: ast_cli(a->fd, "conservative\n"); break;
			case 3: ast_cli(a->fd, "aggressive\n"); break;
			default: ast_cli(a->fd, "unknown\n"); break;
		}

		ast_cli(a->fd, "Comfort Noise       : ");
		switch (s->comfort_noise) {
		    case 0: ast_cli(a->fd, "off\n"); break;
            case 1: ast_cli(a->fd, "white\n"); break;
            case 2: ast_cli(a->fd, "hot\n"); break;
            case 3: ast_cli(a->fd, "estimate\n"); break;
            default: ast_cli(a->fd, "unknown\n"); break;
		}

		int j;
		ast_cli(a->fd, "Codec list          : ");
		for (j = 0 ; j < s->codec_nr ; j++) {
			switch (s->codec_list[j]) {
				case CODEC_PCMA:        ast_cli(a->fd, "alaw, ");  break;
				case CODEC_PCMU:        ast_cli(a->fd, "ulaw, ");  break;
				case CODEC_G7231_63:    ast_cli(a->fd, "g723.1, "); break;
				case CODEC_G726_24:     ast_cli(a->fd, "g726_24, "); break;
				case CODEC_G726_32:     ast_cli(a->fd, "g726_32, "); break;
				case CODEC_G729A:        ast_cli(a->fd, "g729A, "); break;
				default: ast_cli(a->fd, "[%d] config error, ", s->codec_list[j]); break;
			}
		}
		ast_cli(a->fd, "\n");

		/* Print Gain settings */
		VRG_UINT32 txgain, rxgain;
		vrgEndptProvGet(i, EPPROV_TxGain, &txgain, sizeof(VRG_UINT32));
		vrgEndptProvGet(i, EPPROV_RxGain, &rxgain, sizeof(VRG_UINT32));
		ast_cli(a->fd, "Tx Gain             : %d\n", txgain);
		ast_cli(a->fd, "Rx Gain             : %d\n", rxgain);

		/* Print Jitterbuffer settings */
		VRG_UINT32 jbfixed, jbmin, jbmax, jbtarget;
		vrgEndptProvGet(i, EPPROV_VoiceJitterBuffFixed, &jbfixed, sizeof(VRG_UINT32));
		vrgEndptProvGet(i, EPPROV_VoiceJitterBuffMin, &jbmin, sizeof(VRG_UINT32));
		vrgEndptProvGet(i, EPPROV_VoiceJitterBuffMax, &jbmax, sizeof(VRG_UINT32));
		vrgEndptProvGet(i, EPPROV_VoiceJitterBuffTarget, &jbtarget, sizeof(VRG_UINT32));
		ast_cli(a->fd, "Brcm JitterBuf fix  : %d\n", jbfixed);
		ast_cli(a->fd, "Brcm JitterBuf min  : %d\n", jbmin);
		ast_cli(a->fd, "Brcm JitterBuf max  : %d\n", jbmax);
		ast_cli(a->fd, "Brcm JitterBuf trg  : %d\n", jbtarget);
		ast_cli(a->fd, "Ast JitterBuf impl  : %s\n", global_jbconf.impl);
		ast_cli(a->fd, "Ast JitterBuf max   : %d\n", global_jbconf.max_size);

		ast_cli(a->fd, "Dialtone            : ");
		const DIALTONE_MAP *dialtone = dialtone_map;
		while (dialtone->state != DIALTONE_LAST) {
			if (dialtone->state == p->dialtone) {
				break;
			}
			dialtone++;
		}
		ast_cli(a->fd, "%s\n", dialtone->str);

		/* Print status for subchannels */
		brcm_show_subchannels(a, p);

		ast_cli(a->fd, "\n");

		i++;
		pvt_unlock(p);
		//ast_mutex_unlock(&p->lock);
		p = brcm_get_next_pvt(p);
	}
}

/*! \brief CLI for showing brcm status.
 * This is a new-style CLI handler so a single function contains
 * the prototype for the function, the 'generator' to produce multiple
 * entries in case it is required, and the actual handler for the command.
 */

static char *brcm_show_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	if (cmd == CLI_INIT) {
		e->command = "brcm show status";
		e->usage =
			"Usage: brcm show status\n"
			"       Shows the current chan_brcm status.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

	/* print chan brcm status information */
	ast_cli(a->fd, "Channel version: %s\n\n", CHANNEL_VERSION);
	ast_cli(a->fd, "FXS  endpoints: %d\n", num_fxs_endpoints);
	ast_cli(a->fd, "FXO  endpoints: %d\n", num_fxo_endpoints);
	ast_cli(a->fd, "DECT endpoints: %d\n", num_dect_endpoints);
	ast_cli(a->fd, "Endpoint fd   : 0x%x\n", endpoint_fd);
	ast_cli(a->fd, "Country       : %d\n", endpoint_country);
	ast_cli(a->fd, "Monitor thread: 0x%x[%d]\n", (unsigned int) monitor_thread, monitor);
	ast_cli(a->fd, "Packet thread : 0x%x[%d]\n", (unsigned int) packet_thread, packets);

	/* print status for individual pvts */
	brcm_show_pvts(a);

	return CLI_SUCCESS;
}

/*! \brief CLI for showing brcm dialtone status. */
static char *brcm_show_dialtone_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	if (cmd == CLI_INIT) {
		e->command = "brcm show dialtone status";
		e->usage =
			"Usage: brcm show dialtone status\n"
			"       Shows the current chan_brcm dialtone status.\n";
		return NULL;
	}
	else if (cmd == CLI_GENERATE) {
		return NULL;
	}

	struct brcm_pvt *p = iflist;
	int i = 0;

	ast_cli(a->fd, "Pvt nr\tDialtone\n\n");
	while(p) {
		const DIALTONE_MAP *dialtone = dialtone_map;
		while (dialtone->state != DIALTONE_LAST) {
			if (dialtone->state == p->dialtone) {
				break;
			}
			dialtone++;
		}
		ast_cli(a->fd, "%d\t%s\n", i, dialtone->str);

		i++;
		p = brcm_get_next_pvt(p);
	}

	return CLI_SUCCESS;
}

/*! \brief CLI for reloading brcm config.
 * Note that the contry setting will not be reloaded. In order to do that the following
 * sequence must be carried out: vrgEndptDeinit(), vrgEndptDriverClose(), vrgEndptDriverOpen()
 * and then vrgEndptInit(). This is the same actions as for unload_module() followed by
 * load_module() which causes the instability that we're trying to avoid using the reolad feature.
 */
static char *brcm_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct ast_config *cfg = NULL;

	if (cmd == CLI_INIT) {
		e->command = "brcm reload";
		e->usage =
			"Usage: brcm reload\n"
			"       Reload chan_brcm configuration.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		return NULL;
	}

	ast_mutex_lock(&iflock);

	/* Acquire locks for all pvt:s to prevent nasty things from happening */
	brcm_lock_pvts();

	/* Reload configuration */
	if (load_settings(&cfg)) {
		brcm_unlock_pvts();
		ast_mutex_unlock(&iflock);
		return CLI_FAILURE;
	}

	/* Provision endpoints */
	load_endpoint_settings(cfg);
	struct brcm_pvt *p = iflist;
	while(p) {
		brcm_initialize_pvt(p);
		brcm_dialtone_init(p);
		p = brcm_get_next_pvt(p);
	}

	brcm_unlock_pvts();
	ast_mutex_unlock(&iflock);

	ast_verbose("BRCM reload done\n");

	return CLI_SUCCESS;
}

static int manager_brcm_ports_show(struct mansession *s, const struct message *m)
{
	char response[64];
	snprintf(response, 64, "\r\nFXS %d\r\nDECT %d\r\n",
		num_fxs_endpoints,
		num_dect_endpoints);

	astman_send_ack(s, m, response);
	return 0;
}

static char *brcm_set_parameters_on_off(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int on_off = 0;

	if (cmd == CLI_INIT) {
		e->command = "brcm set {echocancel|ringsignal} {on|off}";
		e->usage =
			"Usage: brcm set {echocancel|ringsignal} {on|off} PvtNr\n"
			"       echocancel, echocancel mode.\n"
			"       ringsignal, ring signal mode.\n"
			"       PvtNr, the Pvt to modify.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		return NULL;
	}

	if (a->argc <= 4) {
		return CLI_SHOWUSAGE; //Too few arguments
	}
	
	int pvt_id = atoi(a->argv[4]);
	if (pvt_id >= num_endpoints || pvt_id < 0) {
		return CLI_SHOWUSAGE;
	}
	line_settings *s = &line_config[pvt_id];

	if (!strcasecmp(a->argv[3], "on")) {
		on_off = 1;
	} else {
		on_off = 0;
	}

	if (!strcasecmp(a->argv[2], "echocancel")) {
		s->echocancel = on_off;
	} else if (!strcasecmp(a->argv[2], "ringsignal")) {
		s->ringsignal = on_off;
	}	
	return CLI_SUCCESS;
}

/*
 * Set Voice Activity Detection (a.k.a silence suppression) from CLI
 */
static char *brcm_set_vad(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	if (cmd == CLI_INIT) {
		e->command = "brcm set silence {off|transparent|conservative|aggressive}";
		e->usage =
			"Usage: brcm set silence {off|transparent|conservative|aggressive} PvtNr\n"
			"       control Voice Activity Detection.\n"
			"       PvtNr, the Pvt to modify.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		return NULL;
	}
	
	if (a->argc <= 4) {
		return CLI_SHOWUSAGE;
	}

    int pvt_id = atoi(a->argv[4]);
    if (pvt_id >= num_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    line_settings *s = &line_config[pvt_id];

	if (!strcasecmp(a->argv[3], "off")) {
		s->silence = 0;
	} else if (!strcasecmp(a->argv[3], "transparent")) {
		s->silence = 1;
	} else if (!strcasecmp(a->argv[3], "conservative")) {
		s->silence = 2;
	} else if (!strcasecmp(a->argv[3], "aggressive")) {
		s->silence = 3;
	}

	return CLI_SUCCESS;
}

/*
 * Set Comfort Noise Generation from CLI
 */
static char *brcm_set_cng(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
    if (cmd == CLI_INIT) {
        e->command = "brcm set comfortnoise {off|white|hot|estimate}";
        e->usage =
            "Usage: brcm set comfortnoise {off|white|hot|estimate} PvtNr\n"
            "       control Comfort Noise Generation.\n"
            "       PvtNr, the Pvt to modify.\n";
        return NULL;
    } else if (cmd == CLI_GENERATE) {
        return NULL;
    }

    if (a->argc <= 4) {
        return CLI_SHOWUSAGE;
    }

    int pvt_id = atoi(a->argv[4]);
    if (pvt_id >= num_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    line_settings *s = &line_config[pvt_id];

    if (!strcasecmp(a->argv[3], "off")) {
        s->comfort_noise = 0;
    } else if (!strcasecmp(a->argv[3], "white")) {
        s->comfort_noise = 1;
    } else if (!strcasecmp(a->argv[3], "hot")) {
        s->comfort_noise = 2;
    } else if (!strcasecmp(a->argv[3], "estimate")) {
        s->comfort_noise = 3;
    }

    return CLI_SUCCESS;
}

static char *brcm_set_dtmf_mode(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	if (cmd == CLI_INIT) {
		e->command = "brcm set dtmf_relay {inband|rfc2833|info}";
		e->usage =
			"Usage: brcm set dtmf_relay {inband|rfc2833|info} PvtNr\n"
			"       dtmf_relay, dtmf relay mode.\n"
			"       PvtNr, the Pvt to modify.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

    if (a->argc <= 4) {
        return CLI_SHOWUSAGE;
    }

    int pvt_id = atoi(a->argv[4]);
    if (pvt_id >= num_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    line_settings *s = &line_config[pvt_id];

	if        (!strcasecmp(a->argv[3], "inband")) {
		s->dtmf_relay = EPDTMFRFC2833_DISABLED;
	} else if (!strcasecmp(a->argv[3], "rfc2833")) {
		s->dtmf_relay = EPDTMFRFC2833_ENABLED;
	} else if (!strcasecmp(a->argv[3], "info")) {
		s->dtmf_relay = EPDTMFRFC2833_SUBTRACT;
	}

	/* Force inband mode, since this is what seems to be working best with Asterisk */
	/* OEJ  s->dtmf_relay = EPDTMFRFC2833_DISABLED;		*/

	return CLI_SUCCESS;
}

static char *brcm_set_parameters_value(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	if (cmd == CLI_INIT) {
		e->command = "brcm set dialout_msecs";
		e->usage =
			"Usage: brcm set dialout_msecs 4000 PvtNr\n"
			"       dialout_msecs, dialout delay in msecs.\n"
			"       PvtNr, the Pvt to modify.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

	if (a->argc <= 4)
		return CLI_SHOWUSAGE;

	int pvt_id = atoi(a->argv[4]);
    if (pvt_id >= num_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    line_settings *s = &line_config[pvt_id];

	s->timeoutmsec = atoi(a->argv[3]);

	return CLI_SUCCESS;
}

static char *brcm_set_autodial_extension(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct brcm_pvt *p;

	if (cmd == CLI_INIT) {
		e->command = "brcm set autodial";
		e->usage =
			"Usage: brcm set autodial 0 1234\n"
			"       brcm set autodial 0 \"\"\n"
			"       autodial, extension to autodial on of hook.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

	if (a->argc <= 4)
		return CLI_SHOWUSAGE;

//	ast_verbose("%d %s",(a->argv[3][0] -'0'), a->argv[4]);
	
	p = iflist;
	while(p) {
		if (p->line_id == (a->argv[3][0]-'0')) {
			line_settings *s = &line_config[p->line_id];
			ast_copy_string(s->autodial_ext, a->argv[4], sizeof(s->autodial_ext));
			break;
		}
		p = brcm_get_next_pvt(p);
	}
	
	return CLI_SUCCESS;
}


/*! \brief BRCM Cli commands definition */
static struct ast_cli_entry cli_brcm[] = {
	AST_CLI_DEFINE(brcm_show_status, "Show chan_brcm status"),
	AST_CLI_DEFINE(brcm_show_dialtone_status, "Show chan_brcm dialtone status"),
	AST_CLI_DEFINE(brcm_set_parameters_on_off,  "Set chan_brcm parameters"),
	AST_CLI_DEFINE(brcm_set_dtmf_mode,  "Set chan_brcm dtmf_relay parameter"),
	AST_CLI_DEFINE(brcm_set_parameters_value,  "Set chan_brcm dialout msecs"),
	AST_CLI_DEFINE(brcm_set_autodial_extension,  "Set chan_brcm autodial extension"),
	AST_CLI_DEFINE(brcm_set_vad, "Set chan_brcm Voice Activity Detection"),
	AST_CLI_DEFINE(brcm_set_cng, "Set chan_brcm Comfort Noice Generation"),
	AST_CLI_DEFINE(brcm_reload, "Reload chan_brcm configuration"),
};


static int unload_module(void)
{
	struct brcm_pvt *p, *pl;

	//ast_sched_dump(sched);

	/* Unregister manager commands */
	ast_manager_unregister("BRCMDialtoneSet");
	ast_manager_unregister("BRCMPortsShow");

	manager_event(EVENT_FLAG_SYSTEM, "BRCM", "Module unload\r\n");

	/* First, take us out of the channel loop */
	if (cur_tech)
		ast_channel_unregister(cur_tech);
	if (!ast_mutex_lock(&iflock)) {
		/* Hangup all interfaces if they have an owner */
		p = iflist;
		while(p) {
			int i;
			pvt_lock(p, "brcm unload module");
			//ast_mutex_lock(&p->lock);
			for (i=0; i<NUM_SUBCHANNELS; i++) {
				struct ast_channel *owner = p->sub[i]->owner;
				if (owner) {
					ast_channel_ref(owner);
					ast_mutex_unlock(&p->lock);
					ast_softhangup(owner, AST_SOFTHANGUP_APPUNLOAD);
					ast_channel_unref(owner);
					ast_mutex_lock(&p->lock);
				}
			}
			brcm_extension_state_unregister(p);
			pvt_unlock(p);
			//ast_mutex_unlock(&p->lock);
			p = p->next;
		}
		iflist = NULL;
		ast_mutex_unlock(&iflock);
	} else {
		ast_log(LOG_WARNING, "Unable to lock the monitor\n");
		return -1;
	}
	if (!ast_mutex_lock(&monlock)) {
		ast_verbose("Stopping threads...\n");
		if (monitor) {
			monitor = 0;
			while (pthread_kill(monitor_thread, SIGURG) == 0)
				sched_yield();
			pthread_join(monitor_thread, NULL);
		}
		monitor_thread = AST_PTHREADT_STOP;
		
		if (packets) {
			packets = 0;
			while (pthread_kill(packet_thread, SIGURG) == 0)
				sched_yield();
			pthread_join(packet_thread, NULL);
		}
		packet_thread = AST_PTHREADT_STOP;

		ast_mutex_unlock(&monlock);
	} else {
		ast_log(LOG_WARNING, "Unable to lock the monitor\n");
		return -1;
	}
	ast_verbose("[%d, %d,]\n",monitor, packets);

	if (!ast_mutex_lock(&iflock)) {
		/* Destroy all the interfaces and free their memory */
		p = iflist;
		while(p) {
			/* Close the socket, assuming it's real */
			pl = p;
			p = p->next;
			/* Free associated memory */
			ast_free(pl);
		}
		iflist = NULL;
		ast_mutex_unlock(&iflock);
	} else {
		ast_log(LOG_WARNING, "Unable to lock the monitor\n");
		return -1;
	}

	/* Unregister CLI commands */
	ast_cli_unregister_multiple(cli_brcm, ARRAY_LEN(cli_brcm));

	ast_verbose("Deinitializing endpoint...\n");
	endpt_deinit();
	ast_verbose("Endpoint deinited...\n");

	ast_sched_thread_destroy(sched);

	return 0;
}


#define         SIGN_BIT        (0x80)      /* Sign bit for a A-law byte. */
#define         QUANT_MASK      (0xf)       /* Quantization field mask. */
#define         NSEGS           (8)         /* Number of A-law segments. */
#define         SEG_SHIFT       (4)         /* Left shift for segment number. */
#define         SEG_MASK        (0x70)      /* Segment field mask. */
#define         BIAS            (0x84)      /* Bias for linear code. */

static int alaw2linear(unsigned char a_val)
{
        int t;
        int seg;

        a_val ^= 0x55;

        t = a_val & QUANT_MASK;
        seg = ((unsigned)a_val & SEG_MASK) >> SEG_SHIFT;
        if(seg) t= (t + t + 1 + 32) << (seg + 2);
        else    t= (t + t + 1     ) << 3;

        return (a_val & SIGN_BIT) ? t : -t;
}

static uint8_t linear_to_alaw[16384];

static void build_xlaw_table(uint8_t *linear_to_xlaw,
                             int (*xlaw2linear)(unsigned char),
                             int mask)
{
    int i, j, v, v1, v2;

    j = 0;
    for(i=0;i<128;i++) {
        if (i != 127) {
            v1 = xlaw2linear(i ^ mask);
            v2 = xlaw2linear((i + 1) ^ mask);
            v = (v1 + v2 + 4) >> 3;
        } else {
            v = 8192;
        }
        for(;j<v;j++) {
            linear_to_xlaw[8192 + j] = (i ^ mask);
            if (j > 0)
                linear_to_xlaw[8192 - j] = (i ^ (mask ^ 0x80));
        }
    }
    linear_to_xlaw[0] = linear_to_xlaw[1];
}

/*
 * Create a EPZCNXPARAM, which is used to specify configuration
 * parameters for a media connection. The parameters are taken
 * from the configuration for the specific fxs port. This is 
 * useful when configuring a connection in preparation for an
 * outgoing call.
 */
static EPZCNXPARAM brcm_get_epzcnxparam(struct brcm_subchannel *sub)
{
	EPZCNXPARAM epCnxParms = {0};
	line_settings *s = &line_config[sub->parent->line_id];

	epCnxParms.mode = EPCNXMODE_SNDRX;

	if (sub->owner) {
		//sub is owned by a ast_channel, so we need to configure endpoint with the settings from there
		epCnxParms.cnxParmList.send.codecs[0].type		= map_codec_ast_to_brcm(sub->owner->readformat);
		epCnxParms.cnxParmList.send.codecs[0].rtpPayloadType	= map_codec_ast_to_brcm_rtp(sub->owner->readformat);
		epCnxParms.cnxParmList.send.numCodecs = 1;
		epCnxParms.cnxParmList.send.period[0] = s->period;
		epCnxParms.cnxParmList.send.numPeriods = 1;
	}
	else {
		//Select our preferred codec. This may result in asterisk transcoding if remote SIP peer doesn't support this codec,
		//which is of course not optimal in the case where we actually support the negotiated codec.
		format_t fmt = map_codec_brcm_to_ast(s->codec_list[0]);

		epCnxParms.cnxParmList.send.codecs[0].type              = map_codec_ast_to_brcm(fmt);
		epCnxParms.cnxParmList.send.codecs[0].rtpPayloadType    = map_codec_ast_to_brcm_rtp(fmt); 
		epCnxParms.cnxParmList.send.numCodecs					= 1;
		epCnxParms.cnxParmList.send.period[0]					= s->period; //Use same packetization period for all codecs TODO: bad idea?
	}

	/* Add Named Telephone Events codec. Without this codec RTP events will not be sent. 
	 * It's not really needed now since we only use inband between DSP and Asterisk.
	 * Keeping it since it may be needed in the future with a less buggy
	 * DTMF-implemntation in Asterisk */
	epCnxParms.cnxParmList.send.codecs[1].type              = CODEC_NTE;
	epCnxParms.cnxParmList.send.codecs[1].rtpPayloadType    = DTMF_PAYLOAD;
	epCnxParms.cnxParmList.send.numCodecs			= 2;
	epCnxParms.namedPhoneEvts = CODEC_NTE_DTMF;

	/* Configure endpoint receiving, should be able to receive any of our supported formats */
	epCnxParms.cnxParmList.recv.numCodecs = s->codec_nr+1;
	int i;
	for (i = 0; i < s->codec_nr; i++) {
		epCnxParms.cnxParmList.recv.codecs[i].type = s->codec_list[i]; //Locally supported codecs
		epCnxParms.cnxParmList.recv.codecs[i].rtpPayloadType = s->rtp_payload_list[i];
		epCnxParms.cnxParmList.recv.period[i] = CODEC_PTIME_ANY;
	}
	epCnxParms.cnxParmList.recv.codecs[i].type = CODEC_NTE; //Locally supported codecs
	epCnxParms.cnxParmList.recv.codecs[i].rtpPayloadType = DTMF_PAYLOAD;
	//epCnxParms.cnxParmList.recv.period[i+1] = CODEC_PTIME_ANY;
	
	epCnxParms.echocancel = s->echocancel;
	epCnxParms.silence = s->silence; //Value 0 - 3
	epCnxParms.comfortNoise = s->comfort_noise; //Value 0-3
	//epCnxParms.preserveFaxMode
	//epCnxParms.secHdrSize
	//epCnxParms.dataMode
	//epCnxParms.autoEncoder
	//epCnxParms.t38param
	//epCnxParms.rtcpXRMode
	//epCnxParms.vbdparam
	epCnxParms.digitRelayType = s->dtmf_relay;
	//epCnxParms.localSsrc
	return epCnxParms;
}

/*
 * Create a line_settings struct with default values.
 */
static line_settings line_settings_create(void)
{
	line_settings line_conf = (line_settings){
		.language = "",
		.cid_num = "",
		.cid_name = "",
		.context_direct = "default-direct",
		.context = "default",
		.silence = 0,
		.autodial_ext = "",
		.echocancel = 1,
		.txgain = GAIN_DEFAULT,
		.rxgain = GAIN_DEFAULT,
		.dtmf_relay = EPDTMFRFC2833_DISABLED,
		.dtmf_compatibility = 1,
		.codec_list = {CODEC_PCMA, CODEC_PCMU, -1, -1, -1, -1},
		.codec_nr = 2,
		.rtp_payload_list = {RTP_PAYLOAD_PCMA, RTP_PAYLOAD_PCMU, -1, -1, -1, -1},
		.capability = default_capability,
		.ringsignal = 1,
		.timeoutmsec = 4000,
		.autodial_timeoutmsec = 60000,
		.period = CODEC_PTIME_20,
		.comfort_noise = 0,
		.jitterFixed = 0,
		.jitterMin = 0,
		.jitterMax = 0,
		.jitterTarget = 0,
		.hangup_xfer = 0,
		.dialtone_extension_hint_context = "",
		.dialtone_extension_hint = "",
	};
	return line_conf;
}

/*
 * Load config file settings into the specified line_settings struct.
 * Can be called multiple times in order to load from multiple ast_variables.
 */
static void line_settings_load(line_settings *line_config, struct ast_variable *v)
{
	int config_codecs = 0;
	int capability_set = 0;

	while(v) {
		if (!strcasecmp(v->name, "silence")) {
			line_config->silence = atoi(v->value);
		} else if (!strcasecmp(v->name, "language")) {
			ast_copy_string(line_config->language, v->value, sizeof(line_config->language));
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_callerid_split(v->value, line_config->cid_name, sizeof(line_config->cid_name), line_config->cid_num, sizeof(line_config->cid_num));
		} else if (!strcasecmp(v->name, "context")) {
			ast_copy_string(line_config->context, v->value, sizeof(line_config->context));
		} else if (!strcasecmp(v->name, "context_direct")) {
			ast_copy_string(line_config->context_direct, v->value, sizeof(line_config->context_direct));
		} else if (!strcasecmp(v->name, "autodial")) {
			ast_copy_string(line_config->autodial_ext, v->value, sizeof(line_config->autodial_ext));
		} else if (!strcasecmp(v->name, "echocancel")) {
			line_config->echocancel = ast_true(v->value)?1:0;
		} else if (!strcasecmp(v->name, "txgain")) {
			if (!ast_strlen_zero(v->value)) {
				line_config->txgain = parse_gain_value(v->name, v->value);
			}
		} else if (!strcasecmp(v->name, "rxgain")) {
			if (!ast_strlen_zero(v->value)) {
				line_config->rxgain = parse_gain_value(v->name, v->value);
			}
		} else if (!strcasecmp(v->name, "dtmfrelay")) {
			if (!strcasecmp(v->value, "info")) {
				line_config->dtmf_relay = EPDTMFRFC2833_SUBTRACT;
			} else if (!strcasecmp(v->value, "rfc2833")) {
				line_config->dtmf_relay = EPDTMFRFC2833_ENABLED;
			} else {
				line_config->dtmf_relay = EPDTMFRFC2833_DISABLED;
			}
			/* Force inband mode, since this is what seems to be working best with Asterisk */
			/* line_config->dtmf_relay = EPDTMFRFC2833_DISABLED; */
		} else if (!strcasecmp(v->name, "dtmfcompatibility")) {
			line_config->dtmf_compatibility = ast_true(v->value)?1:0;
		} else if (!strcasecmp(v->name, "allow")) {
			if (!capability_set) {
				line_config->capability = 0; //Clear default capability
				capability_set = 1;
			}

			if (!strcasecmp(v->value, "alaw")) {
				line_config->codec_list[config_codecs] = CODEC_PCMA;
				line_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_PCMA;
				line_config->capability = line_config->capability | AST_FORMAT_ALAW;
			} else if (!strcasecmp(v->value, "ulaw")) {
				line_config->codec_list[config_codecs] = CODEC_PCMU;
				line_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_PCMU;
				line_config->capability = line_config->capability | AST_FORMAT_ULAW;
			} else if (!strcasecmp(v->value, "g729")) {
				line_config->codec_list[config_codecs] = CODEC_G729A;
				line_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_G729;
				line_config->capability = line_config->capability | AST_FORMAT_G729A;
			} else if (!strcasecmp(v->value, "g723")) {
				line_config->codec_list[config_codecs] = CODEC_G7231_63;
				line_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_G723;
				line_config->capability = line_config->capability | AST_FORMAT_G723_1;
			} else if (!strcasecmp(v->value, "g726")) {
				line_config->codec_list[config_codecs] = CODEC_G726_32;
				line_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_G726_32;
				line_config->capability = line_config->capability | AST_FORMAT_G726;
			} else {
				ast_log(LOG_WARNING, "Unknown codec: %s\n", v->value);
			}
		} else if (!strcasecmp(v->name, "ringsignal")) {
			line_config->ringsignal = ast_true(v->value)?1:0;
		} else if (!strcasecmp(v->name, "dialoutmsec")) {
			line_config->timeoutmsec = atoi(v->value);
		} else if (!strcasecmp(v->name, "autodial_timeoutmsec")) {
			line_config->autodial_timeoutmsec = atoi(v->value);
		} else if (!strcasecmp(v->name, "period")) {
			switch(atoi(v->value)) {
				case 5:
					line_config->period = CODEC_PTIME_5;
					break;
				case 10:
					line_config->period = CODEC_PTIME_10;
					break;
				case 20:
					line_config->period = CODEC_PTIME_20;
					break;
				case 30:
					line_config->period = CODEC_PTIME_30;
					break;
				case 40:
					line_config->period = CODEC_PTIME_40;
					break;
				default:
					line_config->period = CODEC_PTIME_20;
					break;
			}
		} else if (!strcasecmp(v->name, "comfortnoise")) {
			line_config->comfort_noise = atoi(v->value);
		}
		else if (!strcasecmp(v->name, "jitter_fixed")) {
			line_config->jitterFixed = strtoul(v->value, NULL, 0);
		}
		else if (!strcasecmp(v->name, "jitter_min")) {
			line_config->jitterMin = strtoul(v->value, NULL, 0);
		}
		else if (!strcasecmp(v->name, "jitter_max")) {
			line_config->jitterMax = strtoul(v->value, NULL, 0);
		}
		else if (!strcasecmp(v->name, "jitter_target")) {
			line_config->jitterTarget = strtoul(v->value, NULL, 0);
		}
		else if (!strcasecmp(v->name, "hangup_xfer")) {
			line_config->hangup_xfer = ast_true(v->value)?1:0;
		}
		else if (!strcasecmp(v->name, "dialtone_extension_hint_context")) {
			strncpy(line_config->dialtone_extension_hint_context, v->value, AST_MAX_EXTENSION);
		}
		else if (!strcasecmp(v->name, "dialtone_extension_hint")) {
			strncpy(line_config->dialtone_extension_hint, v->value, AST_MAX_EXTENSION);
		}

		if (config_codecs > 0)
			line_config->codec_nr = config_codecs;

		v = v->next;
	}
}

static int load_settings(struct ast_config **cfg)
{
	struct ast_flags config_flags = { 0 };

	if ((*cfg = ast_config_load(config, config_flags)) == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Config file %s is in an invalid format.  Aborting.\n", config);
		return AST_MODULE_LOAD_DECLINE;
	}

	/* We *must* have a config file otherwise stop immediately */
	if (!(*cfg)) {
		ast_log(LOG_ERROR, "Unable to load config %s\n", config);
		return AST_MODULE_LOAD_DECLINE;
	}

	/* Load jitterbuffer defaults, Copy the default jb config over global_jbconf */
	memcpy(&global_jbconf, &default_jbconf, sizeof(struct ast_jb_conf));

	/* Load global settings */
	struct ast_variable *v;
	v = ast_variable_browse(*cfg, "default");

	while(v) {
		if (!ast_jb_read_conf(&global_jbconf, v->name, v->value)) {
			ast_debug(2, "Loaded jitterbuffer settings '%s'\n", v->value);
			v = v->next;
			continue;
		}

		if (!strcasecmp(v->name, "country")) {
			const COUNTRY_MAP *countryMap = country_map;
			for (;;) {
				ast_debug(2, "cmp: [%s] [%s]\n", v->value, countryMap->isoCode);
				if (!strcmp(v->value, countryMap->isoCode)) {
					ast_debug(2, "Found country '%s'\n", v->value);
					endpoint_country = countryMap->vrgCountry; 
					break;
				}

				if (countryMap->vrgCountry == VRG_COUNTRY_MAX) {
					ast_log(LOG_WARNING, "Unknown country '%s'\n", v->value);
					break;
				}

				countryMap++;
			}
		} else if (!strcasecmp(v->name, "cwtimeout")) {
			cwtimeout = atoi(v->value);
			if (cwtimeout > 60 || cwtimeout < 0) {
				cwtimeout = DEFAULT_CALL_WAITING_TIMEOUT;
				ast_log(LOG_WARNING, "Incorrect cwtimeout '%s', defaulting to '%d'\n", v->value, cwtimeout);
			}
		} else if (!strcasecmp(v->name, "cw_enable")) {
			ast_debug(2, "Setting call waiting enabled to %s\n", v->value);
			cw = ast_true(v->value)?1:0;
		}
		else if (!strcasecmp(v->name, "hfmaxdelay")) {
			hfmaxdelay = atoi(v->value);
			if (hfmaxdelay > 1000 || hfmaxdelay < 0) {
				hfmaxdelay = DEFAULT_MAX_HOOKFLASH_DELAY;
				ast_log(LOG_WARNING, "Incorrect hfmaxdelay '%s', defaulting to '%d'\n", v->value, hfmaxdelay);
			}
		} else if (!strcasecmp(v->name, "r4hanguptimeout")) {
			r4hanguptimeout = atoi(v->value);
			if (r4hanguptimeout > 30000 || r4hanguptimeout < 0) {
				r4hanguptimeout = DEFAULT_R4_HANGUP_TIMEOUT;
				ast_log(LOG_WARNING, "Incorrect r4hanguptimeout '%s', defaulting to '%d'\n", v->value, r4hanguptimeout);
			}
		}

		v = v->next;
	}

	return 0;
}

static void load_endpoint_settings(struct ast_config *cfg)
{
	struct ast_variable *v;

	/* Load endpoint settings */
	int i;
	for (i = 0; i < num_endpoints; i++) {
		// Create and init a new settings struct
		line_config[i] = line_settings_create();
		// Load default settings
		v = ast_variable_browse(cfg, "default");
		line_settings_load(&line_config[i], v);
		// Load endpoint specific settings
		char config_section[64];
		snprintf(config_section, 64, "brcm%d", i);
		v = ast_variable_browse(cfg, config_section);
		if (!v) {
			ast_log(LOG_WARNING, "Unable to load endpoint specific config (missing config section?): %s\n", config_section);
		}
		line_settings_load(&line_config[i], v);
	}

	brcm_provision_endpoints();
}

static int load_module(void)
{
	struct ast_config *cfg;
	int result;

	/* Setup scheduler thread */
	if (!(sched = ast_sched_thread_create())) {
		ast_log(LOG_ERROR, "Unable to create scheduler thread/context. Aborting.\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	if (ast_mutex_lock(&iflock)) {
		/* It's a little silly to lock it, but we mind as well just to be sure */
		ast_log(LOG_ERROR, "Unable to lock interface list???\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Load settings file and read default section */
	if ((result = load_settings(&cfg)) != 0) {
		return result;
	}

	/* Initialize the endpoints */
	endpt_init();

	brcm_get_endpoints_count();
	load_endpoint_settings(cfg);

	brcm_create_endpoints();
	brcm_create_pvts(iflist, 0);
	brcm_assign_line_id(iflist);
	ast_mutex_unlock(&iflock);
	cur_tech = (struct ast_channel_tech *) &brcm_tech;

	/* Make sure we can register our Adtranphone channel type */
	if (ast_channel_register(cur_tech) || (endpoint_fd == NOT_INITIALIZED)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'Brcm'\n");
		ast_log(LOG_ERROR, "endpoint_fd = %x\n",endpoint_fd);
		ast_config_destroy(cfg);
		unload_module();
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Register all CLI functions for BRCM */
	ast_cli_register_multiple(cli_brcm, ARRAY_LEN(cli_brcm));
	ast_config_destroy(cfg);

	/* Register manager commands */
	ast_manager_register_xml("BRCMPortsShow", EVENT_FLAG_SYSTEM, manager_brcm_ports_show);

	/* Start channel threads */
	start_threads();

	manager_event(EVENT_FLAG_SYSTEM, "BRCM", "Module load\r\n");

	ast_verbose("BRCM init done\n");

	return AST_MODULE_LOAD_SUCCESS;
}


int endpt_deinit(void)
{
	int i, rc;
	/* Destroy Endpt */
	for ( i = 0; i < num_endpoints; i++ ) {
		rc = vrgEndptDestroy((VRG_ENDPT_STATE *)&endptObjState[i] );
	}
	if (!ast_mutex_lock(&ioctl_lock)) {
		ast_verbose("Endpoint deinit...\n");
		vrgEndptDeinit();
		vrgEndptDriverClose();
		ast_mutex_unlock(&ioctl_lock);
	} else {
		ast_log(LOG_WARNING, "Unable to lock the ioctl_lock\n");
		return -1;
	}

	return 0;
}


static int brcm_get_endpoints_count(void)
{
	ENDPOINTDRV_ENDPOINTCOUNT_PARM endpointCount;
	endpointCount.size = sizeof(ENDPOINTDRV_ENDPOINTCOUNT_PARM);

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_FXSENDPOINTCOUNT, &endpointCount ) != IOCTL_STATUS_SUCCESS ) {
		ast_verbose("ENDPOINTIOCTL_FXSENDPOINTCOUNT failed");
		return -1;
	} else {
		num_fxs_endpoints = endpointCount.endpointNum;
		ast_verbose("num_fxs_endpoints = %d\n", num_fxs_endpoints);
	}

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_FXOENDPOINTCOUNT, &endpointCount ) != IOCTL_STATUS_SUCCESS ) {
		ast_verbose("ENDPOINTIOCTL_FXOENDPOINTCOUNT failed");
		return -1;
	} else {
		num_fxo_endpoints = endpointCount.endpointNum;
		ast_verbose("num_fxo_endpoints = %d\n", num_fxo_endpoints);
	}

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_DECTENDPOINTCOUNT, &endpointCount ) != IOCTL_STATUS_SUCCESS ) {
		ast_verbose("ENDPOINTIOCTL_DECTENDPOINTCOUNT failed");
		return -1;
	} else {
		num_dect_endpoints = endpointCount.endpointNum;
		ast_verbose("num_dect_endpoints = %d\n", num_dect_endpoints);
	}

	num_endpoints = num_fxs_endpoints + num_fxo_endpoints + num_dect_endpoints;

	return 0;
}

static void brcm_provision_endpoints(void)
{
	int i;
	line_settings* s;

	//Provision endpoints
	for ( i = 0; i < num_endpoints; i++ )
	{
		EPSTATUS result;
		s = &line_config[i];

		/*
		 * Provision DSP Gain values according to configuration
		 */

		ast_debug(2, "Setting TxGain to %d for Endpoint %d\n", s->txgain, i);
		result = vrgEndptProvSet(i, EPPROV_TxGain, &s->txgain, sizeof(VRG_UINT32));
		if (result != EPSTATUS_SUCCESS) {
			ast_log(LOG_ERROR, "Setting TxGain to %d for Endpoint %d failed with EPSTATUS %d\n", s->txgain, i, result);
		}

		ast_debug(2, "Setting RxGain to %d for Endpoint %d\n", s->rxgain, i);
		result = vrgEndptProvSet(i, EPPROV_RxGain, &s->rxgain, sizeof(VRG_UINT32));
		if (result != EPSTATUS_SUCCESS) {
			ast_log(LOG_ERROR, "Setting RxGain to %d for Endpoint %d failed with EPSTATUS %d\n", s->rxgain, i, result);
		}

		/*
		 * Set DSP jitter buffer values accoring to configuration
		 * Should be set to zero if asterisk jitter buffer is used.
		 */

		result = vrgEndptProvSet(i, EPPROV_VoiceJitterBuffFixed, &s->jitterFixed, sizeof(VRG_UINT32));
		if (result != EPSTATUS_SUCCESS) {
			ast_log(LOG_ERROR, "Setting EPPROV_VoiceJitterBuffFixed to %d for Endpoint %d failed with EPSTATUS %d\n", s->jitterFixed, i, result);
		}

		result = vrgEndptProvSet(i, EPPROV_VoiceJitterBuffMax, &s->jitterMax, sizeof(VRG_UINT32));
		if (result != EPSTATUS_SUCCESS) {
			ast_log(LOG_ERROR, "Setting EPPROV_VoiceJitterBuffMax to %d for Endpoint %d failed with EPSTATUS %d\n", s->jitterMax, i, result);
		}

		result = vrgEndptProvSet(i, EPPROV_VoiceJitterBuffMin, &s->jitterMin, sizeof(VRG_UINT32));
		if (result != EPSTATUS_SUCCESS) {
			ast_log(LOG_ERROR, "Setting EPPROV_VoiceJitterBuffMin to %d for Endpoint %d failed with EPSTATUS %d\n", s->jitterMin, i, result);
		}

		result = vrgEndptProvSet(i, EPPROV_VoiceJitterBuffTarget, &s->jitterTarget, sizeof(VRG_UINT32));
		if (result != EPSTATUS_SUCCESS) {
			ast_log(LOG_ERROR, "Setting EPPROV_VoiceJitterBuffTarget to %d for Endpoint %d failed with EPSTATUS %d\n", s->jitterTarget, i, result);
		}
	}
}

static void brcm_create_endpoints(void)
{
	int i, rc;

	/* Creating Endpt */
	for ( i = 0; i < num_endpoints; i++ )
	{
		rc = vrgEndptCreate(i, i,(VRG_ENDPT_STATE *)&endptObjState[i]);
	}
}


static void brcm_destroy_endpoints(void)
{
	int i, rc;

	for ( i = 0; i < num_endpoints; i++ )
	{
		rc = vrgEndptDestroy((VRG_ENDPT_STATE *)&endptObjState[i]);
	}
}

int endpt_init(void)
{
	VRG_ENDPT_INIT_CFG   vrgEndptInitCfg;
	int rc;

	ast_verbose("Initializing endpoint interface\n");

	vrgEndptDriverOpen();

	vrgEndptInitCfg.country = endpoint_country;
	vrgEndptInitCfg.currentPowerSource = 0;

	/* Intialize endpoint */
	rc = vrgEndptInit( &vrgEndptInitCfg,
			   NULL,
			   NULL,
			   NULL,
			   NULL,
			   NULL,
			   NULL );

	
	return 0;
}


int brcm_signal_callwaiting(const struct brcm_pvt *p)
{
	ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_CALLWT, 1, -1, -1, -1);
	return 0;
}

int brcm_stop_callwaiting(const struct brcm_pvt *p)
{
	ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_CALLWT, 0, -1, -1, -1);
	return 0;
}



int brcm_signal_ringing(struct brcm_pvt *p)
{
	if (line_config[p->line_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_RINGING, 1, -1, -1 , -1);
	}
	return 0;
}


int brcm_stop_ringing(struct brcm_pvt *p)
{
	if (line_config[p->line_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_RINGING, 0, -1, -1 , -1);
	}

	return 0;
}

/* Prepare endpoint for ringing. Caller ID signal pending. */
int brcm_signal_ringing_callerid_pending(struct brcm_pvt *p)
{
	if (line_config[p->line_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_CALLID_RINGING, 1, -1, -1 , -1);
	}

	return 0;
}

int brcm_stop_ringing_callerid_pending(struct brcm_pvt *p)
{
	if (line_config[p->line_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->line_id], -1, EPSIG_CALLID_RINGING, 0, -1, -1 , -1);
	}

	return 0;
}

/*
 * Send caller id message to endpoint.
 * MMDDHHMM, number, name
 * 'O' in number or name => not available
 * 'P' in number or name => presentation not allowed
 */
int brcm_signal_callerid(const struct ast_channel *chan, struct brcm_subchannel *sub)
{
	if (line_config[sub->parent->line_id].ringsignal) {
		CLID_STRING clid_string;
		struct timeval utc_time;
		struct ast_tm local_time;
		char number[CLID_MAX_NUMBER];
		char name[CLID_MAX_NAME];

		/* Add datetime to caller id string, format: MMDDHHMM */
		utc_time = ast_tvnow();
		ast_localtime(&utc_time, &local_time, NULL);
		sprintf(clid_string.date,
			"%02d%02d%02d%02d, ",
			local_time.tm_mon + 1,
			local_time.tm_mday,
			local_time.tm_hour,
			local_time.tm_min);

		/* Get connected line identity if valid and presentation is allowed */
		if (chan) {
			if ((ast_party_id_presentation(&chan->connected.id) & AST_PRES_RESTRICTION) == AST_PRES_ALLOWED) {
				if (chan->connected.id.number.valid) {
					strncpy(number, chan->connected.id.number.str, CLID_MAX_NAME);
					number[CLID_MAX_NUMBER - 1] = '\0';
				} else {
					strcpy(number, "O\0");
				}

				if (chan->connected.id.name.valid) {
					strncpy(name, chan->connected.id.name.str, CLID_MAX_NAME);
					name[CLID_MAX_NAME - 1] = '\0';
				} else {
					strcpy(name, "O\0");
				}
			} else {
				/* Number and/or name available but presentation is not allowed */
				strcpy(number, "P\0");
				strcpy(name, "P\0");
			}
		} else {
			/* Name and number not available. Will probably not be reached */
			strcpy(number, "0\0");
			strcpy(name, "0\0");
		}

		/* Add number and name to caller id string, format: number,"name" */
		int str_length = 0;
		strncpy(&clid_string.number_name[str_length], number, CLID_MAX_NUMBER);
		str_length = strlen(number);
		clid_string.number_name[str_length++] = ',';
		clid_string.number_name[str_length++] = '"';
		strncpy(&clid_string.number_name[str_length], name, CLID_MAX_NAME);
		str_length = strlen(clid_string.number_name);
		clid_string.number_name[str_length++] = '"';
		clid_string.number_name[str_length++] = '\0';

		ast_debug(2, "CLID string: %s\n", (char *) &clid_string);

		return ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[sub->parent->line_id], -1, EPSIG_CALLID, (int)&clid_string, -1, -1 , -1);
	}

	return( EPSTATUS_SUCCESS );
}

static EPSIG map_dtmf_to_epsig(char digit)
{
	EPSIG signal;
	switch (digit) {
		case '0':
			signal = EPSIG_DTMF0;
			break;
		case '1':
			signal = EPSIG_DTMF1;
			break;
		case '2':
			signal = EPSIG_DTMF2;
			break;
		case '3':
			signal = EPSIG_DTMF3;
			break;
		case '4':
			signal = EPSIG_DTMF4;
			break;
		case '5':
			signal = EPSIG_DTMF5;
			break;
		case '6':
			signal = EPSIG_DTMF6;
			break;
		case '7':
			signal = EPSIG_DTMF7;
			break;
		case '8':
			signal = EPSIG_DTMF8;
			break;
		case '9':
			signal = EPSIG_DTMF9;
			break;
		case 'A':
			signal = EPSIG_DTMFA;
			break;
		case 'B':
			signal = EPSIG_DTMFB;
			break;
		case 'C':
			signal = EPSIG_DTMFC;
			break;
		case 'D':
			signal = EPSIG_DTMFD;
			break;
		case '*':
			signal = EPSIG_DTMFS;
			break;
		case '#':
			signal = EPSIG_DTMFH;
			break;
		default:
			ast_log(LOG_WARNING, "Can't signal unknown DTMF %c", digit);
			signal = EPSIG_LAST;
			break;
	}
	return signal;
}

int brcm_signal_dtmf(struct brcm_subchannel *sub, char digit)
{
	EPSIG signal = map_dtmf_to_epsig(digit);
	if (signal == EPSIG_LAST) {
		return EPSTATUS_ERROR;
	}
	return ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[sub->parent->line_id], -1, signal, 1, -1, -1 , -1);
}

int brcm_stop_dtmf(struct brcm_subchannel *sub, char digit)
{
	EPSIG signal = map_dtmf_to_epsig(digit);
	if (signal == EPSIG_LAST) {
		return EPSTATUS_ERROR;
	}
	return ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[sub->parent->line_id], -1, signal, 0, -1, -1 , -1);
}


EPSTATUS vrgEndptDriverOpen(void)
{
   /* Open the pcmShim driver  */
   if( ( pcmShimFile = open("/dev/pcmshim0", O_RDWR) ) == -1 )
   {
      printf("%s: pcmshim open error %d\n", __FUNCTION__, errno );
      return ( EPSTATUS_DRIVER_ERROR );
   }

   /* Open and initialize Endpoint driver */
   if( ( endpoint_fd = open("/dev/bcmendpoint0", O_RDWR) ) == -1 )
   {
      printf( "%s: open error %d\n", __FUNCTION__, errno );
      return ( EPSTATUS_DRIVER_ERROR );
   }
   else
   {
      printf( "%s: Endpoint driver open success\n", __FUNCTION__ );
   }

   return ( EPSTATUS_SUCCESS );
}


EPSTATUS vrgEndptDriverClose()
{
   if ( close( endpoint_fd ) == -1 )
   {
      printf("%s: close error %d", __FUNCTION__, errno);
      return ( EPSTATUS_DRIVER_ERROR );
   }

   if ( close( pcmShimFile ) == -1 )
   {
      printf("%s: close error %d", __FUNCTION__, errno);
      return ( EPSTATUS_DRIVER_ERROR );
   }

   endpoint_fd = -1;
   pcmShimFile = -1;

   return( EPSTATUS_SUCCESS );
}


EPSTATUS vrgEndptInit
(
 VRG_ENDPT_INIT_CFG        *endptInitCfg,
 endptEventCallback         notifyCallback,
 endptPacketCallback        packetCallback,
 endptGetProvCallback       getProvisionCallback,
 endptSetProvCallback       setProvisionCallback,
 endptPacketReleaseCallback packetReleaseCallback,
 endptTaskShutdownCallback  taskShutdownCallback
 )
{
	ENDPOINTDRV_INIT_PARAM tStartupParam;

	/* get the pcm dma pool address */
	if( ioctl( pcmShimFile, PCMSHIMIOCTL_GETBUF_CMD, &(endptInitCfg->dma_pool_buffer) ) != IOCTL_STATUS_SUCCESS ) {
		ast_verbose( "error getting dma pool buffers\n");
		return (EPSTATUS_DRIVER_ERROR);
	}

	tStartupParam.endptInitCfg = endptInitCfg;
	tStartupParam.epStatus     = EPSTATUS_DRIVER_ERROR;
	tStartupParam.size         = sizeof(ENDPOINTDRV_INIT_PARAM);

	/* Check if kernel driver is opened */
	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_INIT, &tStartupParam ) != IOCTL_STATUS_SUCCESS )
		return ( tStartupParam.epStatus );

	return ( tStartupParam.epStatus );
}


EPSTATUS vrgEndptDeinit( void )
{
	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_DEINIT, NULL ) != IOCTL_STATUS_SUCCESS )
		{
		}

	return( EPSTATUS_SUCCESS );
}

/*
*****************************************************************************
** FUNCTION:   vrgEndptProvSet
**
** PURPOSE:    Set a value to the endpoint provisioning database
**             The application would use this API to store a value
**             in the endpoint provisioning database so that the
**             parameter's value is directly available to the endpoint.
**
** PARAMETERS: line           -  [IN]  Line id
**             provItemId     -  [IN]  Provisioning item id
**             provItemValue  -  [IN]  Pointer to the variable whose value needs to be
**                                     stored in the endpoint provisioning database
**             provItemLength -  [IN]  Length/Size of the variable whose value needs to be
**                                     stored in the endpoint provisioning database.
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgEndptProvSet( int line, EPPROV provItemId, void* provItemValue, int provItemLength )
{
	ENDPOINTDRV_PROV_PARM provParm;

	provParm.size           = sizeof(ENDPOINTDRV_PROV_PARM);
	provParm.provItemId     = provItemId;
	provParm.provItemValue  = provItemValue;
	provParm.provItemLength = provItemLength;
	provParm.line           = line;
	provParm.epStatus       = EPSTATUS_DRIVER_ERROR;

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_PROV_SET, &provParm ) != IOCTL_STATUS_SUCCESS )
	{
		ast_log(LOG_ERROR, "error during ioctl EndptProvSet\n");
	}

	return( provParm.epStatus );
}

/*
*****************************************************************************
** FUNCTION:   vrgEndptProvGet
**
** PURPOSE:    Get a value from the endpoint provisioning database
**             The application would use this API to get a value
**             that is currently stored in the endpoint provisioning database.
**
** PARAMETERS: line           -  [IN]  Line id
**             provItemId     -  [IN]  Provisioning item id
**             provItemValue  -  [OUT] Pointer to the variable that will be
**                                     filled with the current value in the
**                                     endpoint provisioning database
**             provItemLength -  [IN]  Length/Size of the variable whose value needs to be
**                                     stored in the endpoint provisioning database.
**
** RETURNS:    EPSTATUS
**
** NOTE: The caller of this function should allocate memory for provItemValue
**
*****************************************************************************
*/
EPSTATUS vrgEndptProvGet( int line, EPPROV provItemId, void* provItemValue, int provItemLength )
{
	ENDPOINTDRV_PROV_PARM provParm;

	provParm.size           = sizeof(ENDPOINTDRV_PROV_PARM);
	provParm.provItemId     = provItemId;
	provParm.provItemValue  = provItemValue;
	provParm.provItemLength = provItemLength;
	provParm.line           = line;
	provParm.epStatus       = EPSTATUS_DRIVER_ERROR;

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_PROV_GET, &provParm ) != IOCTL_STATUS_SUCCESS )
	{
		ast_log(LOG_ERROR, "error during ioctl EndptProvSet\n");
	}

	return( provParm.epStatus );
}

EPSTATUS ovrgEndptSignal
(
 ENDPT_STATE   *endptState,
 int            cnxId,
 EPSIG          signal,
 unsigned int   value,
 int            duration,
 int            period,
 int            repetition
 )
{
	ENDPOINTDRV_SIGNAL_PARM tSignalParm;

	tSignalParm.cnxId    = cnxId;
	tSignalParm.state    = endptState;
	tSignalParm.signal   = signal;
	tSignalParm.value    = value;
	tSignalParm.epStatus = EPSTATUS_DRIVER_ERROR;
	tSignalParm.duration = duration;
	tSignalParm.period   = period;
	tSignalParm.repetition = repetition;
	tSignalParm.size     = sizeof(ENDPOINTDRV_SIGNAL_PARM);

	/* Check if kernel driver is opened */

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_SIGNAL, &tSignalParm ) != IOCTL_STATUS_SUCCESS )
		{
		}

	return( tSignalParm.epStatus );
}


EPSTATUS vrgEndptCreate( int physId, int lineId, VRG_ENDPT_STATE *endptState )
{
	ENDPOINTDRV_CREATE_PARM tInitParm;

	tInitParm.physId     = physId;
	tInitParm.lineId     = lineId;
	tInitParm.endptState = endptState;
	tInitParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tInitParm.size       = sizeof(ENDPOINTDRV_CREATE_PARM);

	/* Check if kernel driver is opened */

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_CREATE, &tInitParm ) != IOCTL_STATUS_SUCCESS )
		{
		}

	return( tInitParm.epStatus );
}


EPSTATUS vrgEndptDestroy( VRG_ENDPT_STATE *endptState )
{
	ENDPOINTDRV_DESTROY_PARM tInitParm;

	tInitParm.endptState = endptState;
	tInitParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tInitParm.size       = sizeof(ENDPOINTDRV_DESTROY_PARM);

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_DESTROY, &tInitParm ) != IOCTL_STATUS_SUCCESS ) {
	}

	return( tInitParm.epStatus );
}


int brcm_create_connection(struct brcm_subchannel *sub) {

	/* generate random nr for rtp header */
	sub->ssrc = rand();

	ENDPOINTDRV_CONNECTION_PARM tConnectionParm;
	EPZCNXPARAM epCnxParms = brcm_get_epzcnxparam(sub); //Create a parameter list for this pvt

	ast_verbose("Creating connection for pvt line_id=%i connection_id=%d\n", sub->parent->line_id, sub->connection_id);
	ast_verbose("Creating connection, send codec: %s\n", brcm_codec_to_string(epCnxParms.cnxParmList.send.codecs[0].type));
	ast_verbose("Configuring endpoint with send-RTPcodec: %s\n", brcm_rtppayload_to_string(epCnxParms.cnxParmList.send.codecs[0].rtpPayloadType));

	tConnectionParm.cnxId      = sub->connection_id;
	tConnectionParm.cnxParam   = &epCnxParms;
	tConnectionParm.state      = (ENDPT_STATE*)&endptObjState[sub->parent->line_id];
	tConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tConnectionParm.size       = sizeof(ENDPOINTDRV_CONNECTION_PARM);

	if (!sub->connection_init) {
		if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_CREATE_CONNECTION, &tConnectionParm ) != IOCTL_STATUS_SUCCESS ){
			ast_verbose("%s: error during ioctl", __FUNCTION__);
			return -1;
		} else {
			ast_verbose("Connection %d created\n", sub->connection_id);
			sub->connection_init = 1;
		}
	}

	return 0;
}

static int brcm_mute_connection(struct brcm_subchannel *sub)
{
	/* Workaround for AA. Unmuting is not working. Throw away packets in packets thread instead */
	return 0;

	ENDPOINTDRV_MUTECONNECTION_PARM tMuteConnectionParm;

	ast_verbose("Mute connection for pvt line_id=%i connection_id=%d\n", sub->parent->line_id, sub->connection_id);

	tMuteConnectionParm.state      = (ENDPT_STATE*)&endptObjState[sub->parent->line_id];
	tMuteConnectionParm.cnxId      = sub->connection_id;
	tMuteConnectionParm.mute       = VRG_TRUE;
	tMuteConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tMuteConnectionParm.size       = sizeof(ENDPOINTDRV_MUTECONNECTION_PARM);

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_MUTE_CONNECTION, &tMuteConnectionParm ) != IOCTL_STATUS_SUCCESS ){
		ast_verbose("%s: error during ioctl", __FUNCTION__);
		return -1;
	}

	return 0;
}

static int brcm_unmute_connection(struct brcm_subchannel *sub)
{
	/* Workaround for AA. Unmuting is not working. Throw away packets in packets thread instead */
	return 0;

	ENDPOINTDRV_MUTECONNECTION_PARM tMuteConnectionParm;

	ast_verbose("Unmute connection for pvt line_id=%i connection_id=%d\n", sub->parent->line_id, sub->connection_id);

	tMuteConnectionParm.state      = (ENDPT_STATE*)&endptObjState[sub->parent->line_id];
	tMuteConnectionParm.cnxId      = sub->connection_id;
	tMuteConnectionParm.mute       = VRG_FALSE;
	tMuteConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tMuteConnectionParm.size       = sizeof(ENDPOINTDRV_MUTECONNECTION_PARM);

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_MUTE_CONNECTION, &tMuteConnectionParm ) != IOCTL_STATUS_SUCCESS ){
		ast_verbose("%s: error during ioctl", __FUNCTION__);
		return -1;
	}

	return 0;
}

/* Put all subchannels in conferencing mode */
static int brcm_create_conference(struct brcm_pvt *p)
{
	int i;
	ENDPOINTDRV_CONNECTION_PARM tConnectionParm;
	EPZCNXPARAM epCnxParms;

	for (i=0; i<NUM_SUBCHANNELS; i++) {
		if (p->sub[i]->connection_init) {

			epCnxParms = brcm_get_epzcnxparam(p->sub[i]);
			epCnxParms.mode = EPCNXMODE_CONF;

			tConnectionParm.cnxId      = p->sub[i]->connection_id;
			tConnectionParm.cnxParam   = &epCnxParms;
			tConnectionParm.state      = (ENDPT_STATE*)&endptObjState[p->line_id];
			tConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
			tConnectionParm.size       = sizeof(ENDPOINTDRV_CONNECTION_PARM);

			if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_MODIFY_CONNECTION, &tConnectionParm ) != IOCTL_STATUS_SUCCESS ) {
				ast_verbose("%s: error during ioctl", __FUNCTION__);
			} else {
				ast_debug(2, "Put BRCM/%d/%d in conferencing mode\n", p->line_id, p->sub[i]->connection_id);
			}
		}
	}

	return 0;
}

/* Change EPZCNXPARAM.mode to EPCNXMODE_SNDRX */
static int brcm_stop_conference(struct brcm_subchannel *p)
{
	if (p->connection_init) {

		ENDPOINTDRV_CONNECTION_PARM tConnectionParm;
		EPZCNXPARAM epCnxParms;

		epCnxParms = brcm_get_epzcnxparam(p);

		tConnectionParm.cnxId      = p->connection_id;
		tConnectionParm.cnxParam   = &epCnxParms;
		tConnectionParm.state      = (ENDPT_STATE*)&endptObjState[p->parent->line_id];
		tConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
		tConnectionParm.size       = sizeof(ENDPOINTDRV_CONNECTION_PARM);

		if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_MODIFY_CONNECTION, &tConnectionParm ) != IOCTL_STATUS_SUCCESS ) {
			ast_verbose("%s: error during ioctl", __FUNCTION__);
			return -1;
		} else {
			ast_debug(2, "Put BRCM/%d/%d in send/recv mode\n", p->parent->line_id, p->connection_id);
		}
		return 0;
	}
	return -1;
}

static int brcm_close_connection(struct brcm_subchannel *p) {

	/* Close connection */
	ENDPOINTDRV_DELCONNECTION_PARM tDelConnectionParm;

	tDelConnectionParm.cnxId      = p->connection_id;
	tDelConnectionParm.state      = (ENDPT_STATE*)&endptObjState[p->parent->line_id];
	tDelConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tDelConnectionParm.size       = sizeof(ENDPOINTDRV_DELCONNECTION_PARM);

	if (p->connection_init) {
		if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_DELETE_CONNECTION, &tDelConnectionParm ) != IOCTL_STATUS_SUCCESS ) {
			ast_verbose("%s: error during ioctl", __FUNCTION__);
			return -1;
		} else {
			p->connection_init = 0;
			ast_verbose("Connection %d closed\n",p->connection_id);
		}
	}
	return 0;
}


/* Generate rtp payload, 12 bytes of header and 160 bytes of ulaw payload */
static void brcm_generate_rtp_packet(struct brcm_subchannel *sub, UINT8 *packet_buf, int type, int marker, int dtmf_timestamp) {
	unsigned short* packet_buf16 = (unsigned short*)packet_buf;
	unsigned int*   packet_buf32 = (unsigned int*)packet_buf;

	//Generate the rtp header, packet is zero from the start, that fact is used
	packet_buf[0] |= 0x80; //Set version 2 of header
	//Padding 0
	//Extension 0
	//CSRC count 0
	packet_buf[1] = type;
	packet_buf[1] |= marker?0x80:0x00;
	packet_buf16[1] = sub->sequence_number++; //Add sequence number
	if (sub->sequence_number > 0xFFFF) sub->sequence_number=0;
	packet_buf32[1] = dtmf_timestamp?sub->dtmf_timestamp:sub->time_stamp;	//Add timestamp
	sub->time_stamp += 160;
	packet_buf32[2] = sub->ssrc;	//Random SSRC
}

/* Initialize dialtone setting and register for events when extension state changes */
static void brcm_dialtone_init(struct brcm_pvt *p)
{
	char hint[AST_MAX_EXTENSION];
	dialtone_state state;
	enum ast_extension_states extension_state;

	if (!ast_test_flag(&ast_options, AST_OPT_FLAG_FULLY_BOOTED)) {
		/* Asterisk is not fully booted, wait for dialplan hints to be read */
		int id = ast_sched_thread_add(sched, 500, dialtone_init_cb, p);
		/* No need to store id */
		return;
	}

	if (ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, p->dialtone_extension_hint_context, p->dialtone_extension_hint)) {
		/* Check current extension state and register for future state changes */
		brcm_extension_state_register(p);
		extension_state = ast_extension_state(NULL, p->dialtone_extension_hint_context, p->dialtone_extension_hint);
		state = extension_state2dialtone_state(extension_state);
	}
	else {
		/* This means that current pvt was not configured to dial out on any provider */
		brcm_extension_state_unregister(p);
		ast_debug(2, "No dialtone hint for pvt %d found (%s@%s)\n", p->line_id, p->dialtone_extension_hint, p->dialtone_extension_hint_context);
		state = DIALTONE_OFF;
	}

	ast_debug(2, "Initializing dialtone for pvt %d to '%s'\n", p->line_id, dialtone_map[state].str);
	brcm_dialtone_set(p, state);
}

/* Subscribe for changes in "dialtone extension" state */
static int brcm_extension_state_register(struct brcm_pvt *p)
{
	int id;
	int *cb_data;

	if (p->dialtone_extension_cb_id != -1) {
		brcm_extension_state_unregister(p);
	}

	cb_data = ast_malloc(sizeof(int));
	*cb_data = p->line_id;

	if ((id = ast_extension_state_add(p->dialtone_extension_hint_context, p->dialtone_extension_hint, extension_state_cb, cb_data)) < 0) {
		ast_log(LOG_ERROR, "Failed to register for dialtone extension call back (%s@%s)\n", p->dialtone_extension_hint_context, p->dialtone_extension_hint);
		ast_free(cb_data);
		return -1;
	}

	p->dialtone_extension_cb_id = id;
	p->dialtone_extension_cb_data = cb_data;
	return 0;
}

/* Unsubscribe for changes in "dialtone extension" state */
static void brcm_extension_state_unregister(struct brcm_pvt *p)
{
	if (p->dialtone_extension_cb_id != -1) {
		ast_extension_state_del(p->dialtone_extension_cb_id, extension_state_cb);
		p->dialtone_extension_cb_id = -1;
		ast_free(p->dialtone_extension_cb_data);
		p->dialtone_extension_cb_data = NULL;
	}
}

static void brcm_dialtone_set(struct brcm_pvt *p, dialtone_state state)
{
	if (state != p->dialtone) {
		ast_debug(2, "Changing dialtone for pvt %d from '%s' to '%s'\n",
			p->line_id,
			dialtone_map[p->dialtone].str,
			dialtone_map[state].str);
		p->dialtone = state;
	}
}

static dialtone_state extension_state2dialtone_state(int extension_state)
{
	dialtone_state state;

	switch (extension_state) {
	case AST_EXTENSION_NOT_INUSE:
	case AST_EXTENSION_INUSE:
	case AST_EXTENSION_BUSY:
	case AST_EXTENSION_RINGING:
	case AST_EXTENSION_ONHOLD:
		state = DIALTONE_ON;
		break;
	case AST_EXTENSION_UNAVAILABLE:
		state = DIALTONE_CONGESTION;
		break;
	case AST_EXTENSION_REMOVED:
	case AST_EXTENSION_DEACTIVATED:
		state = DIALTONE_OFF;
		break;
	default:
		state = DIALTONE_UNKNOWN;
		break;
	}

	return state;
}

static int extension_state_cb(char *context, char *exten, int state, void *data)
{
	struct brcm_pvt *p;
	int line_id = *(int*) data;

	if ((p = brcm_get_pvt_from_lineid(iflist, line_id)) == NULL) {
		ast_log(LOG_ERROR, "Received extension_state_cb for unknown pvt %d '%s@%s'\n", line_id, exten, context);
		return -1;
	}

	pvt_lock(p, "extension state callback");
	//ast_mutex_lock(&p->lock);
	if (state == AST_EXTENSION_DEACTIVATED) {
		/* Hint for which this pvt was registered to was removed */
		p->dialtone_extension_cb_id = -1;
		ast_free(p->dialtone_extension_cb_data);
		p->dialtone_extension_cb_data = NULL;
	}
	ast_debug(2, "New extension state '%s' for '%s@%s' pvt: %d\n", ast_extension_state2str(state), exten, context, p->line_id);
	brcm_dialtone_set(p, extension_state2dialtone_state(state));
	//ast_mutex_unlock(&p->lock);
	pvt_unlock(p);
	return 0;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Brcm SLIC channel");
