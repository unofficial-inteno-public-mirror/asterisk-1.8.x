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
 * Locale support AUS/BEL/BRA/CHL/CHN/CZK/DKN/ETS/FIN/FRA/DEU/HUN/IND/ITA/JPN/
 *                NLD/NZL/USA/ESP/SWE/NOR/CHE/T57/GBR/TWN/UAR
 * Enable T38 support
 * Enable V18 support
 * Ingress/egress gain
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

#include "chan_brcm.h"


/* Global brcm channel parameters */

static const char tdesc[] = "Brcm SLIC Driver";
static const char config[] = "brcm.conf";

VRG_ENDPT_STATE endptObjState[MAX_NUM_LINEID];

static int num_fxs_endpoints = -1;
static int num_fxo_endpoints = -1;
static int num_dect_endpoints = -1;
static int endpoint_fd = NOT_INITIALIZED;
static int endpoint_country = VRG_COUNTRY_NORTH_AMERICA;
static int clip = 1; // Caller ID presentation

/* Dialtone variables */
struct ast_tone_zone_sound *tzs = NULL;
struct ast_tone_zone_part tone_data_g = {0};
static unsigned char dialtone_gen[2880] = {0};
static int dialtone_period = 0;

/* Caller ID */
#define CLID_MAX_DATE	10
#define CLID_MAX_NUMBER	16
#define CLID_MAX_NAME	16
typedef struct CLID_STRING
{
	char date[CLID_MAX_DATE];
	char number_name[CLID_MAX_NUMBER + CLID_MAX_NAME + 4]; // 4 = comma, quotation marks and null terminator
} CLID_STRING;

typedef struct {
	int		id;
	char	extension[AST_MAX_EXTENSION];
} autodial;

/* Struct for individual endpoint settings */
typedef struct {
	int silence;
	char language[MAX_LANGUAGE];
	char cid_num[AST_MAX_EXTENSION];
	char cid_name[AST_MAX_EXTENSION];
	char context[AST_MAX_EXTENSION]; //Default context for dialtone mode
	autodial autodial_ext[4];
	int autodial_nr;
	int echocancel;
	int txgain;
	int rxgain;
	int dtmf_relay;
	int dtmf_short;
	int codec_list[6];
	int codec_nr;
	int rtp_payload_list[6];
	int ringsignal;
	int timeoutmsec;
	CODEC_PKT_PERIOD period;
	int comfort_noise;
} fxs_settings;

static fxs_settings fxs_config[MAX_NUM_LINEID];

/* Boolean value whether the monitoring thread shall continue. */
static unsigned int monitor;
static unsigned int events;
static unsigned int packets;

static pthread_t monitor_thread = AST_PTHREADT_NULL;
static pthread_t event_thread = AST_PTHREADT_NULL;
static pthread_t packet_thread = AST_PTHREADT_NULL;

static struct ast_channel_tech *cur_tech;

/* Protect the interface list (of brcm_pvt's) */
AST_MUTEX_DEFINE_STATIC(iflock);

/* Protect the monitoring thread, so only one process can kill or start it, and not
   when it's doing something critical. */
AST_MUTEX_DEFINE_STATIC(monlock);
AST_MUTEX_DEFINE_STATIC(ioctl_lock);

/* exported capabilities */
static const struct ast_channel_tech brcm_tech = {
        .type = "BRCM",
	.description = tdesc,
	.capabilities = AST_FORMAT_ALAW | AST_FORMAT_ULAW | AST_FORMAT_G729A | AST_FORMAT_G726 | AST_FORMAT_G723_1,
	.requester = brcm_request,
	.call = brcm_call,
	.hangup = brcm_hangup,
	.answer = brcm_answer,
	.read = brcm_read,
	.write = brcm_write,
};

static int brcm_call(struct ast_channel *ast, char *dest, int timeout)
{
	struct brcm_pvt *p;

	struct timeval UtcTime = ast_tvnow();
	struct ast_tm tm;

	p = ast->tech_pvt;

	ast_log(LOG_WARNING, "BRCM brcm_call %d\n", p->connection_id);
	ast_localtime(&UtcTime, &tm, NULL);

	if ((ast->_state != AST_STATE_DOWN) && (ast->_state != AST_STATE_RESERVED)) {
		ast_log(LOG_WARNING, "brcm_call called on %s, neither down nor reserved\n", ast->name);
		return -1;
	}

	p->channel_state = RINGING;
	if (!clip) {
		brcm_signal_ringing(p);
	} else {
		brcm_signal_ringing_callerid_pending(p);
		brcm_signal_callerid(p);
	}

  	ast_setstate(ast, AST_STATE_RINGING);
	ast_queue_control(ast, AST_CONTROL_RINGING);
	return 0;
}

static int brcm_hangup(struct ast_channel *ast)
{
	struct brcm_pvt *p;
	p = ast->tech_pvt;

	ast_verbose("brcm_hangup(%s) id =%d\n", ast->name, p->connection_id);
	if (!ast->tech_pvt) {
		ast_log(LOG_WARNING, "Asked to hangup channel not connected\n");
		return 0;
	}

	if (!clip) {
		brcm_stop_ringing(p);
	} else {
		brcm_stop_ringing_callerid_pending(p);
	}
	ast_mutex_lock(&p->lock);
	ast_setstate(ast, AST_STATE_DOWN);

	p->lastformat = -1;
	p->lastinput = -1;
	p->channel_state = CALLENDED;
	memset(p->ext, 0, sizeof(p->ext));
	((struct brcm_pvt *)(ast->tech_pvt))->owner = NULL;
	ast_module_unref(ast_module_info->self);
	ast_verb(3, "Hungup '%s'\n", ast->name);
	ast->tech_pvt = NULL;
	brcm_close_connection(p);
	ast_mutex_unlock(&p->lock);

	return 0;
}


static int brcm_answer(struct ast_channel *ast)
{
	ast_debug(1, "brcm_answer(%s)\n", ast->name);
	ast->rings = 0;
	ast_setstate(ast, AST_STATE_UP);
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
		case DTMF: return BRCM_DTMF;
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
static int map_codec_brcm_to_ast(int id) {
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
	struct brcm_pvt *p = ast->tech_pvt;
   	UINT8 packet_buffer[PACKET_BUFFER_SIZE] = {0};

	if (ast->_state != AST_STATE_UP) {
		/* Silently ignore packets until channel is up */
		ast_debug(5, "error: channel not up\n");
		return 0;
	}

	if(frame->frametype == AST_FRAME_VOICE) {

		/* send rtp packet to the endpoint */
		epPacket_send.mediaType   = 0;

		/* copy frame data to local buffer */
		memcpy(packet_buffer + 12, frame->data.ptr, frame->datalen);
	    
		/* add buffer to outgoing packet */
		epPacket_send.packetp = packet_buffer;

		/* generate the rtp header */
		brcm_generate_rtp_packet(p, epPacket_send.packetp, map_ast_codec_id_to_rtp(frame->subclass.codec));
		
		/* set rtp id sent to endpoint */
		p->codec = map_ast_codec_id_to_rtp(frame->subclass.codec);

		tPacketParm_send.cnxId       = p->connection_id;
		tPacketParm_send.state       = (ENDPT_STATE*)&endptObjState[p->connection_id];
		tPacketParm_send.length      = 12 + frame->datalen;
		tPacketParm_send.bufDesc     = (int)&epPacket_send;
		tPacketParm_send.epPacket    = &epPacket_send;
		tPacketParm_send.epStatus    = EPSTATUS_DRIVER_ERROR;
		tPacketParm_send.size        = sizeof(ENDPOINTDRV_PACKET_PARM);

		if (p->connection_init) {
			if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_PACKET, &tPacketParm_send ) != IOCTL_STATUS_SUCCESS )
				ast_verbose("%s: error during ioctl", __FUNCTION__);
		}
	}
	return 0;
}


static void brcm_send_dialtone(struct brcm_pvt *p) {
	EPPACKET epPacket_send;
	ENDPOINTDRV_PACKET_PARM tPacketParm_send;
	UINT8 packet_buffer[PACKET_BUFFER_SIZE] = {0};

	/* send rtp packet to the endpoint */
	epPacket_send.mediaType   = 0;

	/* copy frame data to local buffer */
	memcpy(&packet_buffer[12], &dialtone_gen[p->dt_counter], 160);
	p->dt_counter += 160;
	if (p->dt_counter >=dialtone_period) p->dt_counter = 0;

	/* add buffer to outgoing packet */
	epPacket_send.packetp = packet_buffer;

	/* generate the rtp header */
	brcm_generate_rtp_packet(p, epPacket_send.packetp, PCMA);

	/* set rtp id sent to endpoint */
	p->codec = PCMU;

	tPacketParm_send.cnxId       = p->connection_id;
	tPacketParm_send.state       = (ENDPT_STATE*)&endptObjState[p->connection_id];
	tPacketParm_send.length      = 12 + 160;
	tPacketParm_send.bufDesc     = (int)&epPacket_send;
	tPacketParm_send.epPacket    = &epPacket_send;
	tPacketParm_send.epStatus    = EPSTATUS_DRIVER_ERROR;
	tPacketParm_send.size        = sizeof(ENDPOINTDRV_PACKET_PARM);

	if (p->connection_init) {
		if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_PACKET, &tPacketParm_send ) != IOCTL_STATUS_SUCCESS )
			ast_verbose("%s: error during ioctl", __FUNCTION__);
	}
}


static struct ast_channel *brcm_new(struct brcm_pvt *i, int state, char *cntx, const char *linkedid, format_t format)
{
	struct ast_channel *tmp;

	tmp = ast_channel_alloc(1, state, i->cid_num, i->cid_name, "", i->ext, i->context, linkedid, 0, "BRCM/%d", i->connection_id);

	if (tmp) {
		tmp->tech = cur_tech;
		/* ast_channel_set_fd(tmp, 0, i->fd); */

		/* find out which codec to use */
		format_t fmt = format;
		if (fmt == 0) {
			//We got free hands to choose codec, so take the first one from our list
			//This is exactly what is done in create_connection if no owner is speced
			fxs_settings *s = &fxs_config[i->connection_id];
			fmt = map_codec_brcm_to_ast(s->codec_list[0]);
		}

		/* set codecs */
		tmp->writeformat = fmt;
		tmp->rawwriteformat = fmt;
		tmp->readformat = fmt;
		tmp->rawreadformat = fmt;
		
		//TODO: should we set nativeformats according to conf? but the tech_pvt contains a hardcoded list...
		tmp->nativeformats  = AST_FORMAT_ALAW | AST_FORMAT_ULAW | AST_FORMAT_G729A | AST_FORMAT_G726 | AST_FORMAT_G723_1;

		/* no need to call ast_setstate: the channel_alloc already did its job */
		if (state == AST_STATE_RING)
			tmp->rings = 1;
		tmp->tech_pvt = i;
		ast_copy_string(tmp->context, cntx, sizeof(tmp->context));
		if (!ast_strlen_zero(i->ext))
			ast_copy_string(tmp->exten, i->ext, sizeof(tmp->exten));
		else
			strcpy(tmp->exten, "s");

		if (!ast_strlen_zero(i->language))
			ast_string_field_set(tmp, language, i->language);

		/* Don't use ast_set_callerid() here because it will
		 * generate a NewCallerID event before the NewChannel event */
		if (!ast_strlen_zero(i->cid_num)) {
			tmp->caller.ani.number.valid = 1;
			tmp->caller.ani.number.str = ast_strdup(i->cid_num);
		}

		i->owner = tmp;
		ast_module_ref(ast_module_info->self);
		if (state != AST_STATE_DOWN) {
			if (ast_pbx_start(tmp)) {
				ast_log(LOG_WARNING, "Unable to start PBX on %s\n", tmp->name);
				ast_hangup(tmp);
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


static struct brcm_pvt* brcm_get_cid_pvt(struct brcm_pvt *p, int connection_id)
{
	struct brcm_pvt *tmp = p;
	if (p->connection_id == connection_id) return p;

	tmp = brcm_get_next_pvt(tmp);

	while(tmp) {
		if (tmp->connection_id == connection_id) return tmp;
		tmp = brcm_get_next_pvt(tmp);
	}
	return NULL;
}


static void *brcm_event_handler(void *data)
{
	struct brcm_pvt *p = iflist;
	struct timeval tim;
	unsigned int ts;

	while(events) {
		p = iflist;
		gettimeofday(&tim, NULL);
		ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;

		/* loop over all pvt's */
		while(p) {
			int autodial = 0;
			/* If off hook send dialtone every 20 ms*/
			ast_mutex_lock(&p->lock);
			if (p->channel_state == OFFHOOK) {

				if (!p->last_dialtone_ts) p->last_dialtone_ts = ts;

				if (ts > p->last_dialtone_ts + 20) {
					if (!p->connection_init)
						brcm_create_connection(p);

					brcm_send_dialtone(p);
					p->last_dialtone_ts = p->last_dialtone_ts + 20;
				}
			}

//			if ((p->channel_state == DIALING) && (ts - p->last_dtmf_ts > TIMEOUTMSEC)) {
//				ast_verbose("ts - last_dtmf_ts > 2000\n");
//				ast_verbose("Trying to dial extension %s\n",p->dtmfbuf);
//			}
			/* If autodial is populated copy it to the dtmfbuffer and dial out directly */
			if ((strlen(p->autodial) > 0) && ((p->channel_state == DIALING) || (p->channel_state == OFFHOOK))) {
				autodial = 1;
				ast_copy_string(p->dtmfbuf, p->autodial, sizeof(p->dtmfbuf));
			}

			/* Check if the dtmf string matches anything in the dialplan */
			if ((((p->channel_state == DIALING) &&
			    (ts - p->last_dtmf_ts > (fxs_config[p->connection_id].timeoutmsec))) || autodial) &&
			    ast_exists_extension(NULL, p->context, p->dtmfbuf, 1, p->cid_num) &&
			    !ast_matchmore_extension(NULL, p->context, p->dtmfbuf, 1, p->cid_num)
			    ) {
				p->channel_state = INCALL;
				ast_verbose("Extension matching: %s found\n", p->dtmfbuf);
				ast_copy_string(p->ext, p->dtmfbuf, sizeof(p->dtmfbuf));
				ast_verbose("Starting pbx in context: %s with cid: %s ext: %s\n", p->context, p->cid_num, p->ext);

				/* Reset the dtmf buffer */
				memset(p->dtmfbuf, 0, sizeof(p->dtmfbuf));
				p->dtmf_len          = 0;
				p->dtmf_first        = -1;
				p->dtmfbuf[p->dtmf_len] = '\0';

				/* Start the pbx */
				if (!p->connection_init)
					brcm_create_connection(p);

				brcm_new(p, AST_STATE_UP, p->context, NULL, 0);

			}

			/* Get next channel pvt if there is one */
			ast_mutex_unlock(&p->lock);
			p = brcm_get_next_pvt(p);
		}
		usleep(100);
//		sched_yield();
	}

	ast_verbose("Events thread ended\n");
	/* Never reached */
	return NULL;
}


#define DTMF_CHECK(dtmf_button, event_string)				\
	{								\
		ast_verbose("%s event detected\n", event_string);	\
		gettimeofday(&tim, NULL);				\
		if (p->dtmf_first < 0) {				\
			p->dtmf_first = dtmf_button;			\
			p->last_dtmf_ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC; \
		} else if (p->dtmf_first == dtmf_button) {		\
			p->dtmfbuf[p->dtmf_len] = dtmf_button;		\
			p->dtmf_len++;					\
			p->dtmfbuf[p->dtmf_len] = '\0';			\
			p->dtmf_first = -1;				\
			p->last_dtmf_ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC; \
			if (p->channel_state == OFFHOOK) p->channel_state = DIALING; \
		} else {						\
			p->dtmf_first = -1;				\
		}							\
	}


static char phone_2digit(char c)
{
	if (c == 11)
		return '#';
	else if (c == 10)
		return '*';
	else if ((c < 10) && (c >= 0))
		return '0' + c;
	else
		return '?';
}

static void *brcm_monitor_packets(void *data)
{
	struct brcm_pvt *p;
	UINT8 pdata[PACKET_BUFFER_SIZE] = {0};
	EPPACKET epPacket;
	ENDPOINTDRV_PACKET_PARM tPacketParm;
	int rtp_packet_type  = BRCM_UNKNOWN;
	RTPPACKET *rtp;
	int current_dtmf_digit = -1;
	
	rtp = (RTPPACKET *)pdata;
	
	ast_verbose("Packets thread starting\n");

	while(packets) {
		struct ast_frame fr  = {0};
		fr.src = "BRCM";

		epPacket.mediaType   = 0;
		epPacket.packetp     = pdata;
		tPacketParm.epPacket = &epPacket;
		tPacketParm.cnxId    = 0;
		tPacketParm.length   = 0;

		if(ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_GET_PACKET, &tPacketParm) == IOCTL_STATUS_SUCCESS) {

			p = brcm_get_cid_pvt(iflist, tPacketParm.cnxId);
			
			if (tPacketParm.length <= 2) {
				ast_log(LOG_WARNING, "Ignoring RTP package - too short\n");
				continue;
			}

			/* Classify the rtp packet */
			rtp_packet_type = brcm_classify_rtp_packet(pdata[1]);

			/* Handle rtp packet accoarding to classification */
			if ((rtp_packet_type == BRCM_AUDIO) && p) {
				if (pdata[0] == 0x80) {
					fr.frametype = AST_FRAME_VOICE;
					fr.offset = 0;
					fr.data.ptr =  (pdata + 12);
					fr.datalen = tPacketParm.length - 12;
					//fr.seqno = RTPPACKET_GET_SEQNUM(rtp);
					//fr.ts = RTPPACKET_GET_TIMESTAMP(rtp);

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
							fr.samples = 80; //for 10 ms frame size
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
				}
			} else if  (rtp_packet_type == BRCM_DTMF) {
				int dtmf_short = fxs_config[p->connection_id].dtmf_short;

				if (dtmf_short) {
					fr.frametype = pdata[13] ? AST_FRAME_NULL : AST_FRAME_DTMF;
					fr.subclass.integer = phone_2digit(pdata[12]);

					if ((fr.frametype == AST_FRAME_NULL) && (current_dtmf_digit == fr.subclass.integer))
						current_dtmf_digit = -1;

					if ((current_dtmf_digit == -1) && (fr.frametype == AST_FRAME_DTMF))
						current_dtmf_digit = fr.subclass.integer;
					else
						fr.frametype = AST_FRAME_NULL;

					ast_debug(9, "[%c, %d] (%s)\n", fr.subclass.integer, fr.len, (fr.frametype==AST_FRAME_DTMF) ? "AST_FRAME_DTMF" : "AST_FRAME_NULL");
				}
				else {
					/* Use DTMFBE instead */
					//ast_verbose("[%d,%d] |%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|%02X|\n", rtp_packet_type, tPacketParm.length, pdata[0], pdata[1], pdata[2], pdata[3], pdata[4], pdata[5], pdata[6], pdata[7], pdata[8], pdata[9], pdata[10], pdata[11], pdata[12], pdata[13], pdata[14], pdata[15]);
					//fr.seqno = RTPPACKET_GET_SEQNUM(rtp);
					//fr.ts = RTPPACKET_GET_TIMESTAMP(rtp);
					fr.frametype = pdata[13] ? AST_FRAME_DTMF_END : AST_FRAME_DTMF_BEGIN;
					fr.subclass.integer = phone_2digit(pdata[12]);
					if (fr.frametype == AST_FRAME_DTMF_END) {
						//fr.samples = (pdata[14] << 8 | pdata[15]);
						//fr.len = fr.samples / 8;
					}
					ast_debug(9, "[%c, %d] (%s)\n", fr.subclass.integer, fr.len, (fr.frametype==AST_FRAME_DTMF_END) ? "AST_FRAME_DTMF_END" : "AST_FRAME_DTMF_BEGIN");
				}
			} else {
				ast_debug(10, "[%d,%d,%d] %X%X%X%X\n",pdata[0], map_rtp_to_ast_codec_id(pdata[1]), tPacketParm.length, pdata[0], pdata[1], pdata[2], pdata[3]);
			}

			ast_mutex_lock(&p->lock);
			if (p->owner && (p->owner->_state == AST_STATE_UP)) {

				/* try to lock channel and send frame */
				if(((rtp_packet_type == BRCM_DTMF) || (rtp_packet_type == BRCM_DTMFBE) || (rtp_packet_type == BRCM_AUDIO)) && !ast_channel_trylock(p->owner)) {
					/* and enque frame if channel is up */
					ast_queue_frame(p->owner, &fr);
					ast_channel_unlock(p->owner);
				}
			}
			ast_mutex_unlock(&p->lock);
		}
		//sched_yield();
		usleep(100);
	} /* while */

	ast_verbose("Packets thread ended\n");
	/* Never reached */
	return NULL;
}


static void *brcm_monitor_events(void *data)
{
	ENDPOINTDRV_EVENT_PARM tEventParm = {0};
	int rc = IOCTL_STATUS_FAILURE;
	struct brcm_pvt *p;
	struct timeval tim;

	while (monitor) {
		tEventParm.size = sizeof(ENDPOINTDRV_EVENT_PARM);
		tEventParm.length = 0;
		p = iflist;

		ast_verbose("Waiting for event\n");
		/* Get the event from the endpoint driver. */
		rc = ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_GET_EVENT, &tEventParm);
		if( rc == IOCTL_STATUS_SUCCESS )
			{
				ast_debug(9, "Event %d detected\n", tEventParm.event);
				p = brcm_get_cid_pvt(iflist, tEventParm.lineId);
				if (p) {
					switch (tEventParm.event) {
					case EPEVT_OFFHOOK:
						ast_debug(9, "EPEVT_OFFHOOK detected\n");
						ast_mutex_lock(&p->lock);		  
						ast_verbose("me: got mutex\n");
						gettimeofday(&tim, NULL);
						p->last_dtmf_ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;

						/* Reset the dtmf buffer */
						memset(p->dtmfbuf, 0, sizeof(p->dtmfbuf));
						p->dtmf_len          = 0;
						p->dtmf_first        = -1;
						p->dtmfbuf[p->dtmf_len] = '\0';
						p->channel_state = OFFHOOK;
						ast_verbose("Sending manager event\n");
						manager_event(EVENT_FLAG_SYSTEM, "BRCM", "Status: OFF %d\r\n", p->connection_id);

						if(p->owner) {

							if (!p->connection_init) {
								ast_debug(9, "create_connection()\n");
								brcm_create_connection(p);
							}

							ast_queue_control(p->owner, AST_CONTROL_ANSWER);
							p->channel_state = INCALL;
						}
						ast_mutex_unlock(&p->lock);
						ast_debug(9, "me: unlocked mutex\n");

						break;
					case EPEVT_ONHOOK:
						ast_debug(9, "EPEVT_ONHOOK detected\n");
						gettimeofday(&tim, NULL);
						p->last_dtmf_ts = tim.tv_sec*TIMEMSEC + tim.tv_usec/TIMEMSEC;

						ast_mutex_lock(&p->lock);
						ast_debug(9, "me: got mutex\n");
						p->channel_state = ONHOOK;
						ast_verbose("Sending manager event\n");
						manager_event(EVENT_FLAG_SYSTEM, "BRCM", "Status: ON %d\r\n", p->connection_id);

						/* Reset the dtmf buffer */
						memset(p->dtmfbuf, 0, sizeof(p->dtmfbuf));
						p->dtmf_len          = 0;
						p->dtmf_first        = -1;
						p->dtmfbuf[p->dtmf_len] = '\0';
						p->last_dialtone_ts = 0;
						brcm_close_connection(p);

						if(p->owner) {
							ast_queue_control(p->owner, AST_CONTROL_HANGUP);
						}
						ast_mutex_unlock(&p->lock);
						ast_debug(9, "me: unlocked mutex\n");
						break;

					case EPEVT_DTMF0: DTMF_CHECK('0', "EPEVT_DTMF0"); break;
					case EPEVT_DTMF1: DTMF_CHECK('1', "EPEVT_DTMF1"); break;
					case EPEVT_DTMF2: DTMF_CHECK('2', "EPEVT_DTMF2"); break;
					case EPEVT_DTMF3: DTMF_CHECK('3', "EPEVT_DTMF3"); break;
					case EPEVT_DTMF4: DTMF_CHECK('4', "EPEVT_DTMF4"); break;
					case EPEVT_DTMF5: DTMF_CHECK('5', "EPEVT_DTMF5"); break;
					case EPEVT_DTMF6: DTMF_CHECK('6', "EPEVT_DTMF6"); break;
					case EPEVT_DTMF7: DTMF_CHECK('7', "EPEVT_DTMF7"); break;
					case EPEVT_DTMF8: DTMF_CHECK('8', "EPEVT_DTMF8"); break;
					case EPEVT_DTMF9: DTMF_CHECK('9', "EPEVT_DTMF9"); break;
					case EPEVT_DTMFS: DTMF_CHECK('s', "EPEVT_DTMFS"); break;
					case EPEVT_DTMFH: DTMF_CHECK('h', "EPEVT_DTMFH"); break;
					case EPEVT_DTMFL: ast_verbose("EPEVT_DTMFL\n"); break;
					case EPEVT_EARLY_OFFHOOK: ast_verbose("EPEVT_EARLY_OFFHOOK\n"); break;
					case EPEVT_EARLY_ONHOOK: ast_verbose("EPEVT_EARLY_ONHOOK\n"); break;
					case EPEVT_MEDIA: ast_verbose("EPEVT_MEDIA\n"); break;
					default:
						ast_verbose("UNKNOWN event %d detected\n", tEventParm.event);
						break;
					}
				} else
					ast_verbose("No pvt with the correct connection_id/lineId %d found!\n", tEventParm.lineId);


			} else {
			ast_verbose("ENDPOINTIOCTL_ENDPT_GET_EVENT failed, endpoint_fd = %x\n", endpoint_fd);
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

	/* Start a new event handler thread */
	/* This thread processes events recieved by brcm_monitor_events */
	events = 1;
	if (ast_pthread_create_background(&event_thread, NULL, brcm_event_handler, NULL) < 0) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_ERROR, "Unable to start event thread.\n");
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

/* Load settings for each fxs line */
static void brcm_initialize_pvt(struct brcm_pvt *p)
{
	fxs_settings *s = &fxs_config[p->connection_id];

	ast_copy_string(p->language, s->language, sizeof(p->language));
	ast_copy_string(p->context, s->context, sizeof(p->context));
	ast_copy_string(p->cid_num, s->cid_num, sizeof(p->cid_num));
	ast_copy_string(p->cid_name, s->cid_name, sizeof(p->cid_name));
	p->txgain = s->txgain;
	p->rxgain = s->rxgain;
}

static void brcm_fill_autodial(struct brcm_pvt *p) {
	int i;
	fxs_settings *s = &fxs_config[p->connection_id];

	for (i=0 ; i<s->autodial_nr ; i++) {
		if (p->connection_id == s->autodial_ext[i].id)
			ast_copy_string(p->autodial, s->autodial_ext[i].extension, sizeof(p->autodial));
	}
}


static struct brcm_pvt *brcm_allocate_pvt(const char *iface, int endpoint_type)
{
	/* Make a brcm_pvt structure for this interface */
	struct brcm_pvt *tmp;
	
	tmp = ast_calloc(1, sizeof(*tmp));
	if (tmp) {
		tmp->owner = NULL;
		tmp->dtmf_len = 0;
		tmp->dtmf_first = -1;
		tmp->connection_id = -1;
		tmp->lastformat = -1;
		tmp->lastinput = -1;
		memset(tmp->ext, 0, sizeof(tmp->ext));
		tmp->next = NULL;
		tmp->last_dtmf_ts = 0;
		tmp->channel_state = ONHOOK;
		tmp->connection_init = 0;
		tmp->last_dialtone_ts = 0;
		tmp->endpoint_type = endpoint_type;
		tmp->time_stamp = 0;
		tmp->sequence_number = 0;
		tmp->ssrc = 0;
		tmp->codec = -1;
		tmp->dt_counter = 0;
	}
	return tmp;
}


static void brcm_create_pvts(struct brcm_pvt *p, int mode) {
	int i;
	struct brcm_pvt *tmp = iflist;
	struct brcm_pvt *tmp_next;

	for (i=0 ; i<num_fxs_endpoints ; i++) {
		tmp_next = brcm_allocate_pvt("", FXS);
		if (tmp != NULL) {
			tmp->next = tmp_next;
			tmp_next->next = NULL;
		} else {
			iflist = tmp_next;
			tmp    = tmp_next;
			tmp->next = NULL;
		}
	}
}


static void brcm_assign_connection_id(struct brcm_pvt *p)
{
	struct brcm_pvt *tmp = p;
	int i;

	/* Assign connection_id's */
	for (i=0 ; i<num_fxs_endpoints ; i++) { // + num_fxo_endpoints + num_dect_endpoints
		tmp->connection_id = endptObjState[i].lineId;
		brcm_fill_autodial(tmp);
		brcm_initialize_pvt(tmp);
		tmp = tmp->next;
	}
}


static struct ast_channel *brcm_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause)
{
	format_t oldformat;
	struct brcm_pvt *p;
	struct ast_channel *tmp = NULL;
	int port_id = -1;

	/* Search for an unowned channel */
	if (ast_mutex_lock(&iflock)) {
		ast_log(LOG_ERROR, "Unable to lock interface list???\n");
		return NULL;
	}
	
	/* Get port id */
	port_id = atoi((char*)data);
	ast_verbose("brcm_request = %s, port_id=%d, format %x\n", (char*) data, port_id, format);

	/* Map id to the correct pvt */
	p = brcm_get_cid_pvt(iflist, port_id);

	/* If the id doesn't exist (p==NULL) use 0 as default */
	if (!p) {
		ast_log(LOG_ERROR, "Port id %s not found using default 0 instead.\n", (char*) data);
		p = iflist;
	}

	ast_mutex_lock(&p->lock);

	/* Check that the request has an allowed format */
	format_t allowedformat = format & (AST_FORMAT_ALAW | AST_FORMAT_ULAW | AST_FORMAT_G729A | AST_FORMAT_G726 | AST_FORMAT_G723_1);

	if (!allowedformat) {
		ast_log(LOG_NOTICE, "Asked to get a channel of unsupported format %s\n", ast_getformatname(format));
		*cause = AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
	} else if ((!p->owner) && (!p->connection_init)) {
		tmp = brcm_new(p, AST_STATE_DOWN, p->context, requestor ? requestor->linkedid : NULL, format);
	} else {
		*cause = AST_CAUSE_BUSY;
	}

	ast_mutex_unlock(&p->lock);
	ast_mutex_unlock(&iflock);

	return tmp;
}


/* parse gain value from config file */
static int parse_gain_value(const char *gain_type, const char *value)
{
	float gain;

	/* try to scan number */
	if (sscanf(value, "%30f", &gain) != 1)
		{
			ast_log(LOG_ERROR, "Invalid %s value '%s' in '%s' config\n",
				value, gain_type, config);
			return DEFAULT_GAIN;
		}

	/* multiplicate gain by 1.0 gain value */ 
	gain = gain * (float)DEFAULT_GAIN;

	/* percentage? */
	if (value[strlen(value) - 1] == '%')
		return (int)(gain / (float)100);

	return (int)gain;
}


static void brcm_show_pvts(struct ast_cli_args *a)
{
	struct brcm_pvt *p = iflist;
	int i = 0;
	
	while(p) {
		ast_cli(a->fd, "\nPvt nr: %d\n",i);
		ast_cli(a->fd, "Connection id       : %d\n", p->connection_id);
		ast_cli(a->fd, "Channel state       : ");
		switch (p->channel_state) {
		case ONHOOK: 	ast_cli(a->fd, "ONHOOK\n");  break;
		case OFFHOOK:	ast_cli(a->fd, "OFFHOOK\n"); break;
		case DIALING:	ast_cli(a->fd, "DIALING\n"); break;
		case INCALL:	ast_cli(a->fd, "INCALL\n");  break;
		case ANSWER:	ast_cli(a->fd, "ANSWER\n");  break;
		case CALLENDED: ast_cli(a->fd, "CALLENDED\n");  break;
		case RINGING:	ast_cli(a->fd, "RINGING\n"); break;
		default:		ast_cli(a->fd, "UNKNOWN\n"); break;
		}
		ast_cli(a->fd, "Connection init     : %d\n", p->connection_init);
		ast_cli(a->fd, "Pvt next ptr        : 0x%x\n", (unsigned int) p->next);
		ast_cli(a->fd, "Pvt owner ptr       : 0x%x\n", (unsigned int) p->owner);		
		ast_cli(a->fd, "Endpoint type       : ");
		switch (p->endpoint_type) {
			case FXS:  ast_cli(a->fd, "FXS\n");  break;
			case FXO:  ast_cli(a->fd, "FXO\n");  break;
			case DECT: ast_cli(a->fd, "DECT\n"); break;
			default: ast_cli(a->fd, "Unknown\n");
		}
		ast_cli(a->fd, "DTMF buffer         : %s\n", p->dtmfbuf);
		ast_cli(a->fd, "Default context     : %s\n", p->context);
		ast_cli(a->fd, "Last DTMF timestamp : %d\n", p->last_dtmf_ts);
		ast_cli(a->fd, "RTP sequence number : %d\n", p->sequence_number);
		ast_cli(a->fd, "RTP SSRC            : %d\n", p->ssrc);
		ast_cli(a->fd, "RTP timestamp       : %d\n", p->time_stamp);
		ast_cli(a->fd, "Dialtone counter    : %d\n", p->dt_counter);
		ast_cli(a->fd, "Autodial extension  : %s\n", p->autodial);
		ast_cli(a->fd, "Codec used          : %s\n", brcm_get_codec_string(p->codec));

		fxs_settings* s = &fxs_config[p->connection_id];

		ast_cli(a->fd, "Echocancel          : %s\n", s->echocancel ? "on" : "off");
		ast_cli(a->fd, "Ringsignal          : %s\n", s->ringsignal ? "on" : "off");	
		ast_cli(a->fd, "DTMF short          : %s\n", s->dtmf_short ? "on" : "off");
		ast_cli(a->fd, "Dialout msecs       : %d\n", s->timeoutmsec);

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
				default: ast_cli(a->fd, "[%d] config error, ", s->codec_list[j]);
			}
		}
		ast_cli(a->fd, "\n");

		i++;
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
	ast_cli(a->fd, "Event thread  : 0x%x[%d]\n", (unsigned int) event_thread, events);
	ast_cli(a->fd, "Packet thread : 0x%x[%d]\n", (unsigned int) packet_thread, packets);
	ast_cli(a->fd, "Dialtone per. : %d\n", dialtone_period);

	/* print status for individual pvts */
	brcm_show_pvts(a);

	return CLI_SUCCESS;
}

static char *brcm_set_parameters_on_off(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int on_off = 0;

	if (cmd == CLI_INIT) {
		e->command = "brcm set {dtmf_short|echocancel|ringsignal} {on|off}";
		e->usage =
			"Usage: brcm set {dtmf_short|echocancel|ringsignal} {on|off} PvtNr\n"
			"       dtmf_short, dtmf sending mode.\n"
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
	if (pvt_id >= num_fxs_endpoints || pvt_id < 0) {
		return CLI_SHOWUSAGE;
	}
	fxs_settings *s = &fxs_config[pvt_id];

	if (!strcasecmp(a->argv[3], "on")) {
		on_off = 1;
	} else {
		on_off = 0;
	}

	if (!strcasecmp(a->argv[2], "dtmf_short")) {
		s->dtmf_short = on_off;
	} else if (!strcasecmp(a->argv[2], "echocancel")) {
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
    if (pvt_id >= num_fxs_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    fxs_settings *s = &fxs_config[pvt_id];

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
    if (pvt_id >= num_fxs_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    fxs_settings *s = &fxs_config[pvt_id];

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
		e->command = "brcm set dtmf_relay {inband|rfc2833|rfc2833_subtract}";
		e->usage =
			"Usage: brcm set dtmf_relay {inband|rfc2833|rfc2833_subtract} PvtNr\n"
			"       dtmf_relay, dtmf relay mode.\n"
			"       PvtNr, the Pvt to modify.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

    if (a->argc <= 4) {
        return CLI_SHOWUSAGE;
    }

    int pvt_id = atoi(a->argv[4]);
    if (pvt_id >= num_fxs_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    fxs_settings *s = &fxs_config[pvt_id];

	if        (!strcasecmp(a->argv[3], "inband")) {
		s->dtmf_relay = EPDTMFRFC2833_DISABLED;
	} else if (!strcasecmp(a->argv[3], "rfc2833")) {
		s->dtmf_relay = EPDTMFRFC2833_ENABLED;
	} else if (!strcasecmp(a->argv[3], "rfc2833_subtract")) {
		s->dtmf_relay = EPDTMFRFC2833_SUBTRACT;
	}

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
    if (pvt_id >= num_fxs_endpoints || pvt_id < 0) {
        return CLI_SHOWUSAGE;
    }
    fxs_settings *s = &fxs_config[pvt_id];

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
		if (p->connection_id == (a->argv[3][0]-'0'))
			ast_copy_string(p->autodial, a->argv[4], sizeof(p->autodial));
		p = brcm_get_next_pvt(p);
	}
	
	
	return CLI_SUCCESS;
}


/*! \brief BRCM Cli commands definition */
static struct ast_cli_entry cli_brcm[] = {
	AST_CLI_DEFINE(brcm_show_status, "Show chan_brcm status"),
	AST_CLI_DEFINE(brcm_set_parameters_on_off,  "Set chan_brcm parameters"),
	AST_CLI_DEFINE(brcm_set_dtmf_mode,  "Set chan_brcm dtmf_relay parameter"),
	AST_CLI_DEFINE(brcm_set_parameters_value,  "Set chan_brcm dialout msecs"),
	AST_CLI_DEFINE(brcm_set_autodial_extension,  "Set chan_brcm autodial extension"),
	AST_CLI_DEFINE(brcm_set_vad, "Set chan_brcm Voice Activity Detection"),
	AST_CLI_DEFINE(brcm_set_cng, "Set chan_brcm Comfort Noice Generation"),
};


static int unload_module(void)
{
	struct brcm_pvt *p, *pl;
	/* First, take us out of the channel loop */
	if (cur_tech)
		ast_channel_unregister(cur_tech);
	if (!ast_mutex_lock(&iflock)) {
		/* Hangup all interfaces if they have an owner */
		p = iflist;
		while(p) {
			if (p->owner)
				ast_softhangup(p->owner, AST_SOFTHANGUP_APPUNLOAD);
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
		
		if (events) {
			events = 0;
			while (pthread_kill(event_thread, SIGURG) == 0)
				sched_yield();
			pthread_join(event_thread, NULL);
		}
		event_thread = AST_PTHREADT_STOP;
		
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
	ast_verbose("[%d, %d, %d]\n",monitor, events, packets);

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
static EPZCNXPARAM brcm_get_epzcnxparam(struct brcm_pvt *p)
{
	EPZCNXPARAM epCnxParms = {0};
	fxs_settings *s = &fxs_config[p->connection_id];

	epCnxParms.mode = EPCNXMODE_SNDRX;

	if (p->owner) {
		//p is owned by a ast_channel, so we need to configure endpoint with the settings from there
		epCnxParms.cnxParmList.send.codecs[0].type		= map_codec_ast_to_brcm(p->owner->readformat);
		epCnxParms.cnxParmList.send.codecs[0].rtpPayloadType	= map_codec_ast_to_brcm_rtp(p->owner->readformat);
		epCnxParms.cnxParmList.send.numCodecs = 1;
		epCnxParms.cnxParmList.send.period[0] = CODEC_PTIME_20; //TODO: how do we determine packetization period?
		epCnxParms.cnxParmList.send.numPeriods = 1;
	}
	else {
		//we can configure then endpoint based on our preferences, so we will send using the first configured codec
		epCnxParms.cnxParmList.send.codecs[0].type              = s->codec_list[0];
		epCnxParms.cnxParmList.send.codecs[0].rtpPayloadType    = s->rtp_payload_list[0];
		epCnxParms.cnxParmList.send.numCodecs					= 1;
		epCnxParms.cnxParmList.send.period[0]					= s->period; //Use same packetization period for all codecs TODO: bad idea?
	}

	/* Configure endpoint receiving, should be able to receive any of our supported formats */
	epCnxParms.cnxParmList.recv.numCodecs = s->codec_nr;
	int i;
	for (i = 0; i < s->codec_nr; i++) {
		epCnxParms.cnxParmList.recv.codecs[i].type = s->codec_list[i]; //Locally supported codecs
		epCnxParms.cnxParmList.recv.codecs[i].rtpPayloadType = s->rtp_payload_list[i];
		epCnxParms.cnxParmList.recv.period[i] = CODEC_PTIME_ANY;
	}

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
 * Create a fxs_settings struct with default values.
 */
static fxs_settings fxs_settings_create(void)
{
	fxs_settings fxs_conf = (fxs_settings){
		.language = "",
		.cid_num = "",
		.cid_name = "",
		.context = "default",
		.silence = 0,
		.autodial_ext = {{0}},
		.autodial_nr = 0,
		.echocancel = 1,
		.txgain = DEFAULT_GAIN,
		.rxgain = DEFAULT_GAIN,
		.dtmf_relay = EPDTMFRFC2833_ENABLED,
		.dtmf_short = 1,
		.codec_list = {CODEC_PCMA, CODEC_PCMU, -1, -1, -1, -1},
		.codec_nr = 2,
		.rtp_payload_list = {RTP_PAYLOAD_PCMA, RTP_PAYLOAD_PCMU, -1, -1, -1, -1},
		.ringsignal = 1,
		.timeoutmsec = 4000,
		.period = CODEC_PTIME_20,
		.comfort_noise = 0,
	};
	return fxs_conf;
}

/*
 * Load config file settings into the specified fxs_settings struct.
 * Can be called multiple times in order to load from multiple ast_variables.
 */
static void fxs_settings_load(fxs_settings *fxs_config, struct ast_variable *v)
{
	int config_codecs = 0;

	while(v) {
		if (!strcasecmp(v->name, "silence")) {
			fxs_config->silence = ast_true(v->value)?1:0;
		} else if (!strcasecmp(v->name, "language")) {
			ast_copy_string(fxs_config->language, v->value, sizeof(fxs_config->language));
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_callerid_split(v->value, fxs_config->cid_name, sizeof(fxs_config->cid_name), fxs_config->cid_num, sizeof(fxs_config->cid_num));
		} else if (!strcasecmp(v->name, "context")) {
			ast_copy_string(fxs_config->context, v->value, sizeof(fxs_config->context));
		} else if (!strcasecmp(v->name, "autodial")) {
			if (fxs_config->autodial_nr < 4) {
				fxs_config->autodial_ext[fxs_config->autodial_nr].id = v->value[0] - '0';
				autodial* ad = &(fxs_config->autodial_ext[fxs_config->autodial_nr]);
				ast_copy_string(ad->extension, &v->value[2], sizeof(autodial));
				fxs_config->autodial_nr++;
			}
		} else if (!strcasecmp(v->name, "echocancel")) {
			fxs_config->echocancel = ast_true(v->value)?1:0;
		} else if (!strcasecmp(v->name, "txgain")) {
			fxs_config->txgain = parse_gain_value(v->name, v->value);
		} else if (!strcasecmp(v->name, "rxgain")) {
			fxs_config->rxgain = parse_gain_value(v->name, v->value);
		} else if (!strcasecmp(v->name, "dtmfrelay")) {
			if (!strcasecmp(v->value, "sipinfo")) {
				fxs_config->dtmf_relay = EPDTMFRFC2833_SUBTRACT;
			} else if (!strcasecmp(v->value, "rfc2833")) {
				fxs_config->dtmf_relay = EPDTMFRFC2833_ENABLED;
			} else {
				fxs_config->dtmf_relay = EPDTMFRFC2833_DISABLED;
			}
		} else if (!strcasecmp(v->name, "shortdtmf")) {
			fxs_config->dtmf_short = ast_true(v->value)?1:0;
		} else if (!strcasecmp(v->name, "allow")) {
			if (!strcasecmp(v->value, "alaw")) {
				fxs_config->codec_list[config_codecs] = CODEC_PCMA;
				fxs_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_PCMA;
			} else if (!strcasecmp(v->value, "ulaw")) {
				fxs_config->codec_list[config_codecs] = CODEC_PCMU;
				fxs_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_PCMU;
			} else if (!strcasecmp(v->value, "g729")) {
				fxs_config->codec_list[config_codecs] = CODEC_G729A;
				fxs_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_G729;
			} else if (!strcasecmp(v->value, "g723")) {
				fxs_config->codec_list[config_codecs] = CODEC_G7231_63;
				fxs_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_G723;
			} else if (!strcasecmp(v->value, "g726")) {
				fxs_config->codec_list[config_codecs] = CODEC_G726_32;
				fxs_config->rtp_payload_list[config_codecs++] = RTP_PAYLOAD_G726_32;
			} else {
				ast_log(LOG_WARNING, "Unknown codec: %s\n", v->value);
			}
		} else if (!strcasecmp(v->name, "ringsignal")) {
			fxs_config->ringsignal = ast_true(v->value)?1:0;
		} else if (!strcasecmp(v->name, "dialoutmsec")) {
			fxs_config->timeoutmsec = atoi(v->value);
		} else if (!strcasecmp(v->name, "period")) {
			switch(atoi(v->value)) {
				case 5:
					fxs_config->period = CODEC_PTIME_5;
					break;
				case 10:
					fxs_config->period = CODEC_PTIME_10;
					break;
				case 20:
					fxs_config->period = CODEC_PTIME_20;
					break;
				case 30:
					fxs_config->period = CODEC_PTIME_30;
					break;
				case 40:
					fxs_config->period = CODEC_PTIME_40;
					break;
				default:
					fxs_config->period = CODEC_PTIME_20;
					break;
			}
		} else if (!strcasecmp(v->name, "comfortnoice")) {
			fxs_config->comfort_noise = atoi(v->value);
		}

		if (config_codecs > 0)
			fxs_config->codec_nr = config_codecs;

		v = v->next;
	}
}

static int load_module(void)
{
	struct ast_config *cfg;
	struct ast_flags config_flags = { 0 };
	struct ast_tone_zone *zone = NULL;

	if ((cfg = ast_config_load(config, config_flags)) == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Config file %s is in an invalid format.  Aborting.\n", config);
		return AST_MODULE_LOAD_DECLINE;
	}

	/* We *must* have a config file otherwise stop immediately */
	if (!cfg) {
		ast_log(LOG_ERROR, "Unable to load config %s\n", config);
		return AST_MODULE_LOAD_DECLINE;
	}
	if (ast_mutex_lock(&iflock)) {
		/* It's a little silly to lock it, but we mind as well just to be sure */
		ast_log(LOG_ERROR, "Unable to lock interface list???\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Load global settings */
	struct ast_variable *v;
	v = ast_variable_browse(cfg, "default");

	while(v) {
		//TODO: use a table to lookup country
		if (!strcasecmp(v->name, "country")) {
			if      (!strcmp(v->value, "swe"))
				endpoint_country = VRG_COUNTRY_SWEDEN;
			else if (!strcmp(v->value, "fin"))
				endpoint_country = VRG_COUNTRY_FINLAND;
			else if (!strcmp(v->value, "dnk"))
				endpoint_country = VRG_COUNTRY_DENMARK;
			else if (!strcmp(v->value, "usa"))
				endpoint_country = VRG_COUNTRY_NORTH_AMERICA;
			else
				ast_log(LOG_WARNING, "Unknown country '%s'\n", v->value);
		}

		v = v->next;
	}
	
	/* Initialize the endpoints */
	endpt_init();
	brcm_get_endpoints_count();
	brcm_create_fxs_endpoints();

	/* Load fxs endpoint settings */
	int i;
	for (i = 0; i < num_fxs_endpoints; i++) {
		// Create and init a new settings struct
		fxs_config[i] = fxs_settings_create();
		// Load default settings
		v = ast_variable_browse(cfg, "default");
		fxs_settings_load(&fxs_config[i], v);
		// Load endpoint specific settings
		char config_section[64];
		snprintf(config_section, 64, "fxs_%d", i);
		v = ast_variable_browse(cfg, config_section);
		if (!v) {
			ast_log(LOG_WARNING, "Unable to load endpoint specific config (missing config section?): %s\n", config_section);
		}
		fxs_settings_load(&fxs_config[i], v);
	}

	brcm_create_pvts(iflist, 0);
	brcm_assign_connection_id(iflist);
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

	ast_verbose("ast_get_indication_tone\n");
	ast_tone_zone_ref(zone);

	if ((tzs = ast_get_indication_tone(zone, "dial"))) {
		int i, best_period_value = INT_MAX;
		int best_period_index = 160;
		ast_verbose("ast_get_indication_tone: %x, %s\n", (void*)tzs, tzs->name);
		ast_verbose("Tone string: %s\n", tzs->data);
		ast_tone_zone_part_parse(tzs->data, &tone_data_g);
		ast_verbose("Tone data: freq1 = %d, freq2 = %d\n", tone_data_g.freq1, tone_data_g.freq2);

		/* Generate 2400 16bit samples of the dialtone, not totally correct but good enough, 7219 ~ -8dB
		 * Only support for signle and dual tone dialtones, no modulation or other funky stuff
		 **/
		build_xlaw_table(linear_to_alaw, alaw2linear, 0xd5);
		for (i=0 ; i<2880 ; i++) {
			dialtone_gen[i] = linear_to_alaw[ ((short)(7219 * (sinf(2.0*M_PI*tone_data_g.freq1/8000.0*i) + sinf(2.0*M_PI*tone_data_g.freq2/8000.0*i)))+ 32768) >> 2];
			/*if (!(i % 160)) ast_verbose("dialtone_gen[%d] = %d, %d\n",i,dialtone_gen[i],(short)(7219 * (sinf(2.0*M_PI*tone_data_g.freq1/8000.0*i)))); */
		}
		
		/* Find a suitable period, we do this by checking that the signal has a linear phase (>0 check) */
		for (i=160 ; i<2720 ; i+=160) {
			if (((short)(7219 * (sinf(2.0*M_PI*tone_data_g.freq1/8000.0*(i+1)) + sinf(2.0*M_PI*tone_data_g.freq2/8000.0*(i+1))))) > 0)
				if (((short)(7219 * (sinf(2.0*M_PI*tone_data_g.freq1/8000.0*i) + sinf(2.0*M_PI*tone_data_g.freq2/8000.0*i)))) <= best_period_value) {
					best_period_value = ((short)(7219 * (sinf(2.0*M_PI*tone_data_g.freq1/8000.0*i) + sinf(2.0*M_PI*tone_data_g.freq2/8000.0*i))));
					best_period_index = i;
				}
		}
		dialtone_period = best_period_index;
		ast_verbose("dialtone_period: %d\n", dialtone_period);
	}
	zone = ast_tone_zone_unref(zone);

	/* Register all CLI functions for BRCM */
	ast_cli_register_multiple(cli_brcm, ARRAY_LEN(cli_brcm));
	ast_config_destroy(cfg);

	/* Start channel threads */
	start_threads();
	
	ast_verbose("BRCM init done\n");

	return AST_MODULE_LOAD_SUCCESS;
}


int endpt_deinit(void)
{
	int i, rc;
	/* Destroy Endpt */
	for ( i = 0; i < num_fxs_endpoints; i++ ) {
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

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPOINTCOUNT, &endpointCount ) != IOCTL_STATUS_SUCCESS ) {
		ast_verbose("ENDPOINTIOCTL_ENDPOINTCOUNT failed");
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
	}

	if ( ioctl( endpoint_fd, ENDPOINTIOCTL_DECTENDPOINTCOUNT, &endpointCount ) != IOCTL_STATUS_SUCCESS ) {
		ast_verbose("ENDPOINTIOCTL_DECTENDPOINTCOUNT failed");
		return -1;
	} else {
		num_dect_endpoints = endpointCount.endpointNum;
	}
	return 0;
}


static void brcm_create_fxs_endpoints(void)
{
	int i, rc;

	/* Creating Endpt */
	for ( i = 0; i < num_fxs_endpoints; i++ )
	{
		rc = vrgEndptCreate(i, i,(VRG_ENDPT_STATE *)&endptObjState[i]);
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


int brcm_signal_ringing(struct brcm_pvt *p)
{
	if (fxs_config[p->connection_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->connection_id], -1, EPSIG_RINGING, 1, -1, -1 , -1);
	}
	return 0;
}


int brcm_stop_ringing(struct brcm_pvt *p)
{
	if (fxs_config[p->connection_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->connection_id], -1, EPSIG_RINGING, 0, -1, -1 , -1);
	}

	return 0;
}

/* Prepare endpoint for ringing. Caller ID signal pending. */
int brcm_signal_ringing_callerid_pending(struct brcm_pvt *p)
{
	if (fxs_config[p->connection_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->connection_id], -1, EPSIG_CALLID_RINGING, 1, -1, -1 , -1);
	}

	return 0;
}

int brcm_stop_ringing_callerid_pending(struct brcm_pvt *p)
{
	if (fxs_config[p->connection_id].ringsignal) {
		ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->connection_id], -1, EPSIG_CALLID_RINGING, 0, -1, -1 , -1);
	}

	return 0;
}

/*
 * Send caller id message to endpoint.
 * MMDDHHMM, number, name
 * 'O' in number or name => not available
 * 'P' in number or name => presentation not allowed
 */
int brcm_signal_callerid(struct brcm_pvt *p)
{
	if (fxs_config[p->connection_id].ringsignal) {
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
		if (p->owner) {
			if ((ast_party_id_presentation(&p->owner->connected.id) & AST_PRES_RESTRICTION) == AST_PRES_ALLOWED) {
				if (p->owner->connected.id.number.valid) {
					strncpy(number, p->owner->connected.id.number.str, CLID_MAX_NAME);
					number[CLID_MAX_NUMBER - 1] = '\0';
				} else {
					strcpy(number, "O\0");
				}

				if (p->owner->connected.id.name.valid) {
					strncpy(name, p->owner->connected.id.name.str, CLID_MAX_NAME);
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

		ast_log(LOG_DEBUG, "CLID string: %s\n", (char *) &clid_string);
		return ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[p->connection_id], -1, EPSIG_CALLID, (int)&clid_string, -1, -1 , -1);
	}

	return( EPSTATUS_SUCCESS );
}

EPSTATUS vrgEndptDriverOpen(void)
{
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

EPSTATUS vrgEndptDriverClose(void)
{
	if ( close( endpoint_fd ) == -1 )
		{
			printf("%s: close error %d", __FUNCTION__, errno);
			return ( EPSTATUS_DRIVER_ERROR );
		}

	endpoint_fd = NOT_INITIALIZED;

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


static int brcm_create_connection(struct brcm_pvt *p) {

	/* generate random nr for rtp header */
	p->ssrc = rand();

	ENDPOINTDRV_CONNECTION_PARM tConnectionParm;
	EPZCNXPARAM epCnxParms = brcm_get_epzcnxparam(p); //Create a parameter list for this pvt

	ast_verbose("Creating connection for pvt %i\n", p->connection_id);
	if (p->owner) {
		char buf[256];
		ast_verbose("Owner channel raw read format: %s\n", ast_getformatname_multiple(buf, sizeof(buf), p->owner->rawreadformat));
		ast_verbose("Owner channel read format: %s\n", ast_getformatname_multiple(buf, sizeof(buf), p->owner->readformat));
		ast_verbose("Owner channel raw write format: %s\n", ast_getformatname_multiple(buf, sizeof(buf), p->owner->rawwriteformat));
		ast_verbose("Owner channel write format: %s\n", ast_getformatname_multiple(buf, sizeof(buf), p->owner->writeformat));
	}
	
	ast_verbose("Creating connection, send codec: %s\n", brcm_codec_to_string(epCnxParms.cnxParmList.send.codecs[0].type));
	ast_verbose("Configuring endpoint with send-RTPcodec: %s\n", brcm_rtppayload_to_string(epCnxParms.cnxParmList.send.codecs[0].rtpPayloadType));

	tConnectionParm.cnxId      = p->connection_id;
	tConnectionParm.cnxParam   = &epCnxParms;
	tConnectionParm.state      = (ENDPT_STATE*)&endptObjState[p->connection_id];
	tConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tConnectionParm.size       = sizeof(ENDPOINTDRV_CONNECTION_PARM);

	if (!p->connection_init) {
		if ( ioctl( endpoint_fd, ENDPOINTIOCTL_ENDPT_CREATE_CONNECTION, &tConnectionParm ) != IOCTL_STATUS_SUCCESS ){
			ast_verbose("%s: error during ioctl", __FUNCTION__);
			return -1;
		} else {
			ast_verbose("Connection %d created\n",p->connection_id);
			p->connection_init = 1;
		}
	}

	return 0;
}


static int brcm_close_connection(struct brcm_pvt *p) {

	/* Close connection */
	ENDPOINTDRV_DELCONNECTION_PARM tDelConnectionParm;

	tDelConnectionParm.cnxId      = p->connection_id;
	tDelConnectionParm.state      = (ENDPT_STATE*)&endptObjState[p->connection_id];
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
static void brcm_generate_rtp_packet(struct brcm_pvt *p, UINT8 *packet_buf, int type) {
	unsigned short* packet_buf16 = (unsigned short*)packet_buf;
	unsigned int*   packet_buf32 = (unsigned int*)packet_buf;

	//Generate the rtp header, packet is zero from the start, that fact is used
	packet_buf[0] |= 0x80; //Set version 2 of header
	//Padding 0
	//Extension 0
	//CSRC count 0
	//Marker 0
	packet_buf[1] = type;
	packet_buf16[1] = p->sequence_number++; //Add sequence number
	if (p->sequence_number > 0xFFFF) p->sequence_number=0;
	packet_buf32[1] = p->time_stamp;	//Add timestamp
	p->time_stamp += 160;
	packet_buf32[2] = p->ssrc;	//Random SSRC
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Brcm SLIC channel");
