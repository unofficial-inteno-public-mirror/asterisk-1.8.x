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

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 284597 $")

#include <ctype.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

/* Still use some IXJ specific stuff */
#include <linux/ixjuser.h>

#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/utils.h"
#include "asterisk/callerid.h"
#include "asterisk/causes.h"
#include "asterisk/stringfields.h"
#include "asterisk/musiconhold.h"

#include "chan_brcm.h"

#define DEFAULT_CALLER_ID "Unknown"
#define PHONE_MAX_BUF 480
#define DEFAULT_GAIN 0x100

static const char tdesc[] = "Brcm SLIC Driver";
static const char config[] = "brcm.conf";

static const char digital_milliwatt[] = {0x1e,0x0b,0x0b,0x1e,0x9e,0x8b,0x8b,0x9e};
uint32_t bogus_data[100];
int fd;

/* rtp stuff */
int sequence_number = 0;
int time_stamp = 3200;
int bflag = 0;
int ssrc = 0;
#define NOT_INITIALIZED -1
#define EPSTATUS_DRIVER_ERROR -1
#define MAX_NUM_LINEID 2
void generate_rtp_packet(UINT8 *packet_buf);
#define PACKET_BUFFER_SIZE 172

#define NOT_INITIALIZED -1
#define EPSTATUS_DRIVER_ERROR -1
#define MAX_NUM_LINEID 2

typedef void (*rtpDropPacketResetCallback)(void);

typedef struct
{
   endptEventCallback         pEventCallBack;
   endptPacketCallback        pPacketCallBack;
   rtpDropPacketResetCallback pRtpDropPacketResetCallBack;
   int                        fileHandle;
   int                        logFileHandle;

} ENDPTUSER_CTRLBLOCK;

EPSTATUS vrgEndptSignal
(
   ENDPT_STATE   *endptState,
   int            cnxId,
   EPSIG          signal,
   unsigned int   value,
   int            duration,
   int            period,
   int            repetition
 );

EPSTATUS vrgEndptDriverOpen(void);
int endpt_init(void);
int endpt_deinit(void);
void event_loop(void);

ENDPTUSER_CTRLBLOCK endptUserCtrlBlock = {NULL, NULL, NULL, NOT_INITIALIZED, NOT_INITIALIZED};
VRG_ENDPT_STATE endptObjState[MAX_NUM_LINEID];

/* Default context for dialtone mode */
static char context[AST_MAX_EXTENSION] = "default";

/* Default language */
static char language[MAX_LANGUAGE] = "";

static int echocancel = AEC_OFF;

static int silencesupression = 0;

static format_t prefformat = AST_FORMAT_G729A | AST_FORMAT_G723_1 | AST_FORMAT_SLINEAR | AST_FORMAT_ULAW;

/* Protect the interface list (of brcm_pvt's) */
AST_MUTEX_DEFINE_STATIC(iflock);

/* Protect the monitoring thread, so only one process can kill or start it, and not
   when it's doing something critical. */
AST_MUTEX_DEFINE_STATIC(monlock);

/* Boolean value whether the monitoring thread shall continue. */
static unsigned int monitor;
   
/* This is the thread for the monitor which checks for input on the channels
   which are not currently in use.  */
static pthread_t monitor_thread = AST_PTHREADT_NULL;

static int restart_monitor(void);

/* The private structures of the Phone Jack channels are linked for
   selecting outgoing channels */
   
#define MODE_DIALTONE 	1
#define MODE_IMMEDIATE	2
#define MODE_FXO	3
#define MODE_FXS        4
#define MODE_SIGMA      5

static struct brcm_pvt {
	int fd;							/* Raw file descriptor for this device */
	struct ast_channel *owner;		/* Channel we belong to, possibly NULL */
	int mode;						/* Is this in the  */
	format_t lastformat;            /* Last output format */
	format_t lastinput;             /* Last input format */
	int ministate;					/* Miniature state, for dialtone mode */
	char dev[256];					/* Device name */
	struct brcm_pvt *next;			/* Next channel in list */
	struct ast_frame fr;			/* Frame */
	char offset[AST_FRIENDLY_OFFSET];
	char buf[PHONE_MAX_BUF];					/* Static buffer for reading frames */
	int obuflen;
	int dialtone;
	int txgain, rxgain;             /* gain control for playing, recording  */
									/* 0x100 - 1.0, 0x200 - 2.0, 0x80 - 0.5 */
	int cpt;						/* Call Progress Tone playing? */
	int silencesupression;
	char context[AST_MAX_EXTENSION];
	char obuf[PHONE_MAX_BUF * 2];
	char ext[AST_MAX_EXTENSION];
	char language[MAX_LANGUAGE];
	char cid_num[AST_MAX_EXTENSION];
	char cid_name[AST_MAX_EXTENSION];
} *iflist = NULL;

static char cid_num[AST_MAX_EXTENSION];
static char cid_name[AST_MAX_EXTENSION];

static struct ast_channel *brcm_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);
static int brcm_digit_begin(struct ast_channel *ast, char digit);
static int brcm_digit_end(struct ast_channel *ast, char digit, unsigned int duration);
static int brcm_call(struct ast_channel *ast, char *dest, int timeout);
static int brcm_hangup(struct ast_channel *ast);
static int brcm_answer(struct ast_channel *ast);
static struct ast_frame *brcm_read(struct ast_channel *ast);
static int brcm_write(struct ast_channel *ast, struct ast_frame *frame);
static struct ast_frame *brcm_exception(struct ast_channel *ast);
static int brcm_send_text(struct ast_channel *ast, const char *text);
static int brcm_fixup(struct ast_channel *old, struct ast_channel *new);
static int brcm_indicate(struct ast_channel *chan, int condition, const void *data, size_t datalen);

static const struct ast_channel_tech brcm_tech = {
	.type = "BRCM",
	.description = tdesc,
	.capabilities = AST_FORMAT_SLINEAR | AST_FORMAT_ULAW | AST_FORMAT_ALAW,
	.requester = brcm_request,
	.send_digit_begin = brcm_digit_begin,
	.send_digit_end = brcm_digit_end,
	.call = brcm_call,
	.hangup = brcm_hangup,
	.answer = brcm_answer,
	.read = brcm_read,
	.write = brcm_write,
	.exception = brcm_exception,
	.indicate = brcm_indicate,
	.fixup = brcm_fixup
};

static struct ast_channel_tech brcm_tech_fxs = {
	.type = "BRCM",
	.description = tdesc,
	.requester = brcm_request,
	.send_digit_begin = brcm_digit_begin,
	.send_digit_end = brcm_digit_end,
	.call = brcm_call,
	.hangup = brcm_hangup,
	.answer = brcm_answer,
	.read = brcm_read,
	.write = brcm_write,
	.exception = brcm_exception,
	.write_video = brcm_write,
	.send_text = brcm_send_text,
	.indicate = brcm_indicate,
	.fixup = brcm_fixup
};

static struct ast_channel_tech *cur_tech;

static int brcm_indicate(struct ast_channel *chan, int condition, const void *data, size_t datalen)
{
	struct brcm_pvt *p = chan->tech_pvt;
	int res=-1;
	ast_debug(1, "Requested indication %d on channel %s\n", condition, chan->name);
	switch(condition) {
	case AST_CONTROL_FLASH:
		usleep(320000);
			p->lastformat = -1;
			res = 0;
			break;
	case AST_CONTROL_HOLD:
		ast_moh_start(chan, data, NULL);
		break;
	case AST_CONTROL_UNHOLD:
		ast_moh_stop(chan);
		break;
	case AST_CONTROL_SRCUPDATE:
		res = 0;
		break;
	default:
		ast_log(LOG_WARNING, "Condition %d is not supported on channel %s\n", condition, chan->name);
	}
	return res;
}

static int brcm_fixup(struct ast_channel *old, struct ast_channel *new)
{
	struct brcm_pvt *pvt = old->tech_pvt;
	if (pvt && pvt->owner == old)
		pvt->owner = new;
	return 0;
}

static int brcm_digit_begin(struct ast_channel *chan, char digit)
{
	/* XXX Modify this callback to let Asterisk support controlling the length of DTMF */
	return 0;
}

static int brcm_digit_end(struct ast_channel *ast, char digit, unsigned int duration)
{
	struct brcm_pvt *p;
	int outdigit;
	p = ast->tech_pvt;
	ast_debug(1, "Dialed %c\n", digit);
	switch(digit) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		outdigit = digit - '0';
		break;
	case '*':
		outdigit = 11;
		break;
	case '#':
		outdigit = 12;
		break;
	case 'f':	/*flash*/
	case 'F':
		usleep(320000);
		p->lastformat = -1;
		return 0;
	default:
		ast_log(LOG_WARNING, "Unknown digit '%c'\n", digit);
		return -1;
	}
	ast_debug(1, "Dialed %d\n", outdigit);
	p->lastformat = -1;
	return 0;
}

static int brcm_call(struct ast_channel *ast, char *dest, int timeout)
{
	struct brcm_pvt *p;

	PHONE_CID cid;
	struct timeval UtcTime = ast_tvnow();
	struct ast_tm tm;
	int start;

	ast_log(LOG_WARNING, "BRCM brcm_call\n");
	ast_localtime(&UtcTime, &tm, NULL);

	memset(&cid, 0, sizeof(PHONE_CID));
	if(&tm != NULL) {
		snprintf(cid.month, sizeof(cid.month), "%02d",(tm.tm_mon + 1));
		snprintf(cid.day, sizeof(cid.day),     "%02d", tm.tm_mday);
		snprintf(cid.hour, sizeof(cid.hour),   "%02d", tm.tm_hour);
		snprintf(cid.min, sizeof(cid.min),     "%02d", tm.tm_min);
	}
	/* the standard format of ast->callerid is:  "name" <number>, but not always complete */
	if (!ast->connected.id.name.valid
		|| ast_strlen_zero(ast->connected.id.name.str)) {
		strcpy(cid.name, DEFAULT_CALLER_ID);
	} else {
		ast_copy_string(cid.name, ast->connected.id.name.str, sizeof(cid.name));
	}

	if (ast->connected.id.number.valid && ast->connected.id.number.str) {
		ast_copy_string(cid.number, ast->connected.id.number.str, sizeof(cid.number));
	}

	p = ast->tech_pvt;

	if ((ast->_state != AST_STATE_DOWN) && (ast->_state != AST_STATE_RESERVED)) {
		ast_log(LOG_WARNING, "brcm_call called on %s, neither down nor reserved\n", ast->name);
		return -1;
	}
	ast_debug(1, "Ringing %s on %s (%d)\n", dest, ast->name, ast->fds[0]);

	signal_ringing();

	/* start = IXJ_PHONE_RING_START(cid); */
	/* if (start == -1) */
	/* 	return -1; */
	
	if (p->mode == MODE_FXS) {
		char *digit = strchr(dest, '/');
		if (digit)
		{
		  digit++;
		  while (*digit)
		    brcm_digit_end(ast, *digit++, 0);
		}
	}
 
  	ast_setstate(ast, AST_STATE_RINGING);
	ast_queue_control(ast, AST_CONTROL_RINGING);
	return 0;
}

static int brcm_hangup(struct ast_channel *ast)
{
	struct brcm_pvt *p;
	p = ast->tech_pvt;

	ast_log(LOG_ERROR, "BRCM brcm_hangup\n");
	ast_debug(1, "brcm_hangup(%s)\n", ast->name);
	if (!ast->tech_pvt) {
		ast_log(LOG_WARNING, "Asked to hangup channel not connected\n");
		return 0;
	}
	
	stop_ringing();

	/* XXX Is there anything we can do to really hang up except stop recording? */
	ast_setstate(ast, AST_STATE_DOWN);

	p->lastformat = -1;
	p->lastinput = -1;
	p->ministate = 0;
	p->obuflen = 0;
	p->dialtone = 0;
	memset(p->ext, 0, sizeof(p->ext));
	((struct brcm_pvt *)(ast->tech_pvt))->owner = NULL;
	ast_module_unref(ast_module_info->self);
	ast_verb(3, "Hungup '%s'\n", ast->name);
	ast->tech_pvt = NULL;
	ast_setstate(ast, AST_STATE_DOWN);

	return 0;
}

static int brcm_setup(struct ast_channel *ast)
{
	struct brcm_pvt *p;
	p = ast->tech_pvt;

	/* Default to g711 */
	p->lastinput = AST_FORMAT_ULAW;
	ast_log(LOG_WARNING, "AST_FORMAT_ULAW set\n");
	/* Nothing to answering really, just start recording */
/*	if (ast->rawreadformat == AST_FORMAT_G729A) {
		if (p->lastinput != AST_FORMAT_G729A) {
			p->lastinput = AST_FORMAT_G729A;
		}
        } else if (ast->rawreadformat == AST_FORMAT_G723_1) {
		if (p->lastinput != AST_FORMAT_G723_1) {
			p->lastinput = AST_FORMAT_G723_1;
		}
	} else if (ast->rawreadformat == AST_FORMAT_SLINEAR) {
		if (p->lastinput != AST_FORMAT_SLINEAR) {
			p->lastinput = AST_FORMAT_SLINEAR;
		}
	} else if (ast->rawreadformat == AST_FORMAT_ULAW) {
		if (p->lastinput != AST_FORMAT_ULAW) {
			p->lastinput = AST_FORMAT_ULAW;
		}
	} else if (p->mode == MODE_FXS) {
		if (p->lastinput != ast->rawreadformat) {
			p->lastinput = ast->rawreadformat;
		}
	} else {
		ast_log(LOG_WARNING, "Can't do format %s\n", ast_getformatname(ast->rawreadformat));
		return -1;
	}
*/
	return 0;
}

static int brcm_answer(struct ast_channel *ast)
{
	struct brcm_pvt *p;

	ast_log(LOG_ERROR, "BRCM brcm_answer\n");
	p = ast->tech_pvt;

	brcm_setup(ast);
	ast_debug(1, "brcm_answer(%s)\n", ast->name);
	ast->rings = 0;
	create_connection();
	ast_queue_control(p->owner, AST_CONTROL_ANSWER);
	ast_setstate(ast, AST_STATE_UP);
	return 0;
}


static struct ast_frame  *brcm_exception(struct ast_channel *ast)
{
	int res;
	union telephony_exception phonee;
	struct brcm_pvt *p = ast->tech_pvt;
	char digit;

	/* Some nice norms */
	p->fr.datalen = 0;
	p->fr.samples = 0;
	p->fr.data.ptr =  bogus_data;
	p->fr.src = "Phone";
	p->fr.offset = 0;
	p->fr.mallocd=0;
	p->fr.delivery = ast_tv(0,0);
	
	if (phonee.bits.dtmf_ready)  {
		ast_debug(1, "brcm_exception(): DTMF\n");
	
		/* We've got a digit -- Just handle this nicely and easily */
		p->fr.subclass.integer = digit;
		p->fr.frametype = AST_FRAME_DTMF;
		return &p->fr;
	}
	if (phonee.bits.hookstate) {
		ast_debug(1, "Hookstate changed\n");
		/* See if we've gone on hook, if so, notify by returning NULL */
		ast_debug(1, "New hookstate: %d\n", res);
		if (!res && (p->mode != MODE_FXO))
			return NULL;
		else {
			if (ast->_state == AST_STATE_RINGING) {
				/* They've picked up the phone */
				p->fr.frametype = AST_FRAME_CONTROL;
				p->fr.subclass.integer = AST_CONTROL_ANSWER;
				brcm_setup(ast);
				ast_setstate(ast, AST_STATE_UP);
				return &p->fr;
			}  else 
				ast_log(LOG_WARNING, "Got off hook in weird state %d\n", ast->_state);
		}
	}
#if 1
	if (phonee.bits.pstn_ring)
		ast_verbose("Unit is ringing\n");
	if (phonee.bits.caller_id) {
		ast_verbose("We have caller ID\n");
	}
	if (phonee.bits.pstn_wink)
		ast_verbose("Detected Wink\n");
#endif
	/* Strange -- nothing there.. */
	p->fr.frametype = AST_FRAME_NULL;
	p->fr.subclass.integer = 0;
	return &p->fr;
}




static struct ast_frame  *brcm_read(struct ast_channel *ast)
{
	int res;
	struct brcm_pvt *p = ast->tech_pvt;
	UINT8 data[1024] = {0};	
	EPPACKET epPacket;
	ENDPOINTDRV_PACKET_PARM tPacketParm;
	int rc2 = IOCTL_STATUS_SUCCESS;
   	int buf_pos_idx = 0;
   	UINT8 packet_buffer[PACKET_BUFFER_SIZE] = {0};

	/* Some nice norms */
	p->fr.datalen = 0;
	p->fr.samples = 0;
	p->fr.data.ptr =  digital_milliwatt;
	p->fr.src = "Phone";
	p->fr.offset = 0;
	p->fr.mallocd=0;
	p->fr.delivery = ast_tv(0,0);

	if (ast->_state = AST_STATE_UP) {

	  /* Connection is established; try to read some data... */

	  /* get rtp packets from endpoint */
	  epPacket.mediaType   = 0;
	  epPacket.packetp     = data;
	  tPacketParm.epPacket = &epPacket;
	  tPacketParm.cnxId    = 0;
	  tPacketParm.length   = 0;

	  rc2 = ioctl( fd, ENDPOINTIOCTL_ENDPT_GET_PACKET, &tPacketParm);
	  if( rc2 == IOCTL_STATUS_SUCCESS )
	    {

	      unsigned short sn = (unsigned short)(data[3] | data[2] <<8);
	      if (tPacketParm.cnxId == 0 && tPacketParm.length == 172) {

		memcpy(&packet_buffer[buf_pos_idx], &data[0], tPacketParm.length);
		buf_pos_idx += tPacketParm.length;
		if (buf_pos_idx >= PACKET_BUFFER_SIZE)
		  buf_pos_idx = 0;

		p->fr.data.ptr =  (data + 12);
		p->fr.samples = 160;
		p->fr.datalen = tPacketParm.length;
		p->fr.frametype = AST_FRAME_VOICE;
		p->fr.subclass.codec = AST_FORMAT_ULAW;
		p->fr.offset = AST_FRIENDLY_OFFSET;

		return &p->fr;

	      }
	    }
	}
	p->fr.samples = 8;
	p->fr.datalen = 8;
	p->fr.frametype = AST_FRAME_VOICE;
	p->fr.subclass.codec = AST_FORMAT_ULAW;
	p->fr.offset = AST_FRIENDLY_OFFSET;

	return &p->fr;
}

static int brcm_write_buf(struct brcm_pvt *p, const char *buf, int len, int frlen, int swap)
{
	int res;
	/* Store as much of the buffer as we can, then write fixed frames */
	int space = sizeof(p->obuf) - p->obuflen;
	/* Make sure we have enough buffer space to store the frame */
	if (space < len)
		len = space;
	if (swap)
		ast_swapcopy_samples(p->obuf+p->obuflen, buf, len/2);
	else
		memcpy(p->obuf + p->obuflen, buf, len);
	p->obuflen += len;
	while(p->obuflen > frlen) {
		res = write(p->fd, p->obuf, frlen);
		if (res != frlen) {
			if (res < 1) {
/*
 * Card is in non-blocking mode now and it works well now, but there are
 * lot of messages like this. So, this message is temporarily disabled.
 */
				return 0;
			} else {
				ast_log(LOG_WARNING, "Only wrote %d of %d bytes\n", res, frlen);
			}
		}
		p->obuflen -= frlen;
		/* Move memory if necessary */
		if (p->obuflen) 
			memmove(p->obuf, p->obuf + frlen, p->obuflen);
	}
	return len;
}

static int brcm_send_text(struct ast_channel *ast, const char *text)
{
    int length = strlen(text);
    return brcm_write_buf(ast->tech_pvt, text, length, length, 0) == length ? 0 : -1;
}

static int brcm_write(struct ast_channel *ast, struct ast_frame *frame)
{
	struct brcm_pvt *p = ast->tech_pvt;
	int res;
	int maxfr=0;
	char *pos;
	int sofar;
	int expected;
	int codecset = 0;
	char tmpbuf[4];
	EPPACKET epPacket_send;
	ENDPOINTDRV_PACKET_PARM tPacketParm_send;
   	UINT8 packet_buffer[PACKET_BUFFER_SIZE] = {0};
   	int buf_pos_idx = 0;
	int tcounter = 0;

	if (ast->_state != AST_STATE_UP) {
	  ast_verbose("error: channel not up\n");
	  return -1;
	}

	if(frame->frametype == AST_FRAME_VOICE) {

	  /* send rtp packet to the endpoint */
	  epPacket_send.mediaType   = 0;

	  /* copy frame data to local buffer */
	  memcpy(packet_buffer + 12, frame->data.ptr, frame->datalen);
	    
	  /* add buffer to outgoing packet */
	  epPacket_send.packetp = packet_buffer;

	  /* generate the rtp header */
	  generate_rtp_packet(epPacket_send.packetp);

	  tPacketParm_send.cnxId       = 0;
	  tPacketParm_send.state       = (ENDPT_STATE*)&endptObjState[0];
	  tPacketParm_send.length      = 172;
	  tPacketParm_send.bufDesc     = (int)&epPacket_send;
	  tPacketParm_send.epPacket    = &epPacket_send;
	  tPacketParm_send.epStatus    = EPSTATUS_DRIVER_ERROR;
	  tPacketParm_send.size        = sizeof(ENDPOINTDRV_PACKET_PARM);

	  if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_PACKET, &tPacketParm_send ) != IOCTL_STATUS_SUCCESS )
	    ast_verbose("%s: error during ioctl", __FUNCTION__);
	}

	return 0;

	/* Write a frame of (presumably voice) data */
	if (frame->frametype != AST_FRAME_VOICE && p->mode != MODE_FXS) {
		if (frame->frametype != AST_FRAME_IMAGE)
			ast_log(LOG_WARNING, "Don't know what to do with  frame type '%d'\n", frame->frametype);
		return 0;
	}
	if (!(frame->subclass.codec &
		(AST_FORMAT_G723_1 | AST_FORMAT_SLINEAR | AST_FORMAT_ULAW | AST_FORMAT_G729A)) && 
	    p->mode != MODE_FXS) {
		ast_log(LOG_WARNING, "Cannot handle frames in %s format\n", ast_getformatname(frame->subclass.codec));
		return -1;
	}
#if 0
	/* If we're not in up mode, go into up mode now */
	if (ast->_state != AST_STATE_UP) {
		ast_setstate(ast, AST_STATE_UP);
		brcm_setup(ast);
	}
#else
	if (ast->_state != AST_STATE_UP) {
		/* Don't try tos end audio on-hook */
		return 0;
	}
#endif	
	if (frame->subclass.codec == AST_FORMAT_G729A) {
		if (p->lastformat != AST_FORMAT_G729A) {
			p->lastformat = AST_FORMAT_G729A;
			p->lastinput = AST_FORMAT_G729A;
			/* Reset output buffer */
			p->obuflen = 0;
			codecset = 1;
		}
		if (frame->datalen > 80) {
			ast_log(LOG_WARNING, "Frame size too large for G.729 (%d bytes)\n", frame->datalen);
			return -1;
		}
		maxfr = 80;
        } else if (frame->subclass.codec == AST_FORMAT_G723_1) {
		if (p->lastformat != AST_FORMAT_G723_1) {
			p->lastformat = AST_FORMAT_G723_1;
			p->lastinput = AST_FORMAT_G723_1;
			/* Reset output buffer */
			p->obuflen = 0;
			codecset = 1;
		}
		if (frame->datalen > 24) {
			ast_log(LOG_WARNING, "Frame size too large for G.723.1 (%d bytes)\n", frame->datalen);
			return -1;
		}
		maxfr = 24;
	} else if (frame->subclass.codec == AST_FORMAT_SLINEAR) {
		if (p->lastformat != AST_FORMAT_SLINEAR) {
			p->lastformat = AST_FORMAT_SLINEAR;
			p->lastinput = AST_FORMAT_SLINEAR;
			codecset = 1;
			/* Reset output buffer */
			p->obuflen = 0;
		}
		maxfr = 480;
	} else if (frame->subclass.codec == AST_FORMAT_ULAW) {
		if (p->lastformat != AST_FORMAT_ULAW) {
			p->lastformat = AST_FORMAT_ULAW;
			p->lastinput = AST_FORMAT_ULAW;
			codecset = 1;
			/* Reset output buffer */
			p->obuflen = 0;
		}
		maxfr = 240;
	} else {
		if (p->lastformat != frame->subclass.codec) {
			p->lastformat = frame->subclass.codec;
			p->lastinput = frame->subclass.codec;
			codecset = 1;
			/* Reset output buffer */
			p->obuflen = 0;
		}
		maxfr = 480;
	}
 	if (codecset) {
	}
	/* If we get here, we have a frame of Appropriate data */
	sofar = 0;
	pos = frame->data.ptr;
	while(sofar < frame->datalen) {
		/* Write in no more than maxfr sized frames */
		expected = frame->datalen - sofar;
		if (maxfr < expected)
			expected = maxfr;
		/* XXX Internet Phone Jack does not handle the 4-byte VAD frame properly! XXX 
		   we have to pad it to 24 bytes still.  */
		if (frame->datalen == 4) {
			if (p->silencesupression) {
				memcpy(tmpbuf, frame->data.ptr, 4);
				expected = 24;
				res = brcm_write_buf(p, tmpbuf, expected, maxfr, 0);
			}
			res = 4;
			expected=4;
		} else {
			int swap = 0;
#if __BYTE_ORDER == __BIG_ENDIAN
			if (frame->subclass.codec == AST_FORMAT_SLINEAR)
				swap = 1; /* Swap big-endian samples to little-endian as we copy */
#endif
			res = brcm_write_buf(p, pos, expected, maxfr, swap);
		}
		if (res != expected) {
			if ((errno != EAGAIN) && (errno != EINTR)) {
				if (res < 0) 
					ast_log(LOG_WARNING, "Write returned error (%s)\n", strerror(errno));
	/*
	 * Card is in non-blocking mode now and it works well now, but there are
	 * lot of messages like this. So, this message is temporarily disabled.
	 */
#if 0
				else
					ast_log(LOG_WARNING, "Only wrote %d of %d bytes\n", res, frame->datalen);
#endif
				return -1;
			} else /* Pretend it worked */
				res = expected;
		}
		sofar += res;
		pos += res;
	}
	return 0;
}

static struct ast_channel *brcm_new(struct brcm_pvt *i, int state, char *cntx, const char *linkedid)
{
	struct ast_channel *tmp;
	struct phone_codec_data queried_codec;

	ast_log(LOG_ERROR, "BRCM brcm_new 1\n");

	tmp = ast_channel_alloc(1, state, i->cid_num, i->cid_name, "", i->ext, i->context, linkedid, 0, "Brcm/%s", i->dev + 5);
	ast_log(LOG_ERROR, "BRCM brcm_new 2\n");

	if (tmp) {
		tmp->tech = cur_tech;
		/* ast_channel_set_fd(tmp, 0, i->fd); */
		/* /\* XXX Switching formats silently causes kernel panics XXX *\/ */
		/* if (i->mode == MODE_FXS && */
		/*     ioctl(i->fd, PHONE_QUERY_CODEC, &queried_codec) == 0) { */
		/* 	if (queried_codec.type == LINEAR16) */
		/* 		tmp->nativeformats = */
		/* 		tmp->rawreadformat = */
		/* 		tmp->rawwriteformat = */
		/* 		AST_FORMAT_SLINEAR; */
		/* 	else { */
		/* 		tmp->nativeformats = */
		/* 		tmp->rawreadformat = */
		/* 		tmp->rawwriteformat = */
		/* 		prefformat & ~AST_FORMAT_SLINEAR; */
		/* 	} */
		/* } */
		/* else { */
		tmp->nativeformats  = AST_FORMAT_ULAW | AST_FORMAT_ALAW;
		tmp->rawreadformat  = AST_FORMAT_ULAW | AST_FORMAT_ALAW;
		tmp->rawwriteformat = AST_FORMAT_ULAW | AST_FORMAT_ALAW;
		/* } */
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
			if (state == AST_STATE_RING) {
				i->cpt = 1;
			}
			if (ast_pbx_start(tmp)) {
				ast_log(LOG_WARNING, "Unable to start PBX on %s\n", tmp->name);
				ast_hangup(tmp);
			}
		}
	} else
		ast_log(LOG_WARNING, "Unable to allocate channel structure\n");
	ast_log(LOG_ERROR, "BRCM brcm_new 3\n");
	return tmp;
}

enum channel_state {
    ONHOOK,
    OFFHOOK,
    DIALING,
    INCALL,
    ANSWER,
};

#define DTMF_CHECK(dtmf_button, event_string) \
{\
    if (dtmf_first < 0) {\
        dtmf_first = dtmf_button;\
    } else if (dtmf_first == dtmf_button) {\
        dtmfbuf[dtmf_len] = dtmf_button;\
        dtmf_len++;\
        dtmfbuf[dtmf_len] = '\0';\
        dtmf_first = -1;\
    } else {\
        dtmf_first = -1;\
    }\
}

static void *do_monitor(void *data)
{
    struct pollfd *fds = NULL;
    int nfds = 0, inuse_fds = 0, res;
    int tonepos = 0;
    /* The tone we're playing this round */
    struct timeval tv = { 0, 0 };
    int dotone;
    /* This thread monitors all the frame relay interfaces which are not yet in use
       (and thus do not have a separate thread) indefinitely */
    ENDPOINTDRV_EVENT_PARM tEventParm = {0};
    ENDPT_STATE endptState;
    int rc = IOCTL_STATUS_FAILURE;
    int event_cnt = 20;
    struct brcm_pvt *p;
    struct brcm_pvt *i = iflist;
    int channel_state = ONHOOK;
    char dtmfbuf[300];
    int dtmf_len = 0;
    int dtmf_first = -1;

    while (monitor) {
        tEventParm.size = sizeof(ENDPOINTDRV_EVENT_PARM);
        tEventParm.length = 0;
        p = iflist;

        /* Get the event from the endpoint driver. */
        rc = ioctl( fd, ENDPOINTIOCTL_ENDPT_GET_EVENT, &tEventParm);
        if( rc == IOCTL_STATUS_SUCCESS )
        {
            endptState.lineId = tEventParm.lineId;
            switch (tEventParm.event) {
                case EPEVT_OFFHOOK:
                    ast_verbose("EPEVT_OFFHOOK detected\n");
                    channel_state = OFFHOOK;
                    /* Reset the dtmf buffer */
                    memset(dtmfbuf, 0, sizeof(dtmfbuf));
                    dtmf_len          = 0;
                    dtmf_first        = -1;
                    dtmfbuf[dtmf_len] = '\0';
                    if(p->owner) {
                        create_connection();
                        ast_queue_control(p->owner, AST_CONTROL_ANSWER);
                        ast_setstate(p->owner, AST_STATE_UP);
                    }
                    break;
                case EPEVT_ONHOOK:
                    ast_verbose("EPEVT_ONHOOK detected\n");
                    channel_state = ONHOOK;
                    /* Reset the dtmf buffer */
                    memset(dtmfbuf, 0, sizeof(dtmfbuf));
                    dtmf_len          = 0;
                    dtmf_first        = -1;
                    dtmfbuf[dtmf_len] = '\0';
                    if(p->owner) {
                        ast_queue_control(p->owner, AST_CONTROL_HANGUP);
                        ast_setstate(p->owner, AST_STATE_DOWN);
                        close_connection();
                    }
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
                default:
                    break;
            }
            ast_verbose("DTMF string: %s\n", dtmfbuf);

            /* Check if the dtmf string matches anything in the dialplan */
            if (ast_exists_extension(NULL, i->context, dtmfbuf, 1, i->cid_num)) {
                channel_state = INCALL;
                ast_verbose("Extension matching: %s found\n", dtmfbuf);
                ast_copy_string(i->ext, dtmfbuf, sizeof(dtmfbuf));
                ast_verbose("Starting pbx in context: %s with cid: %d ext: %s\n", i->context, i->cid_num, i->ext);

                /* Reset the dtmf buffer */
                memset(dtmfbuf, 0, sizeof(dtmfbuf));
                dtmf_len          = 0;
                dtmf_first        = -1;
                dtmfbuf[dtmf_len] = '\0';

                /* Start the pbx */
                brcm_new(i, AST_STATE_RING, i->context, NULL);
            }
        }
    }

    return NULL;
}


static int restart_monitor()
{
  ast_log(LOG_ERROR, "BRCM: restart_monitor 1\n");
	/* If we're supposed to be stopped -- stay stopped */
	if (monitor_thread == AST_PTHREADT_STOP)
		return 0;
  ast_log(LOG_ERROR, "BRCM: restart_monitor 2\n");
	if (ast_mutex_lock(&monlock)) {
		ast_log(LOG_WARNING, "Unable to lock monitor\n");
		return -1;
	}
  ast_log(LOG_ERROR, "BRCM: restart_monitor 3\n");
	if (monitor_thread == pthread_self()) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_WARNING, "Cannot kill myself\n");
		return -1;
	}
  ast_log(LOG_ERROR, "BRCM: restart_monitor 4\n");
	if (monitor_thread != AST_PTHREADT_NULL) {
		if (ast_mutex_lock(&iflock)) {
			ast_mutex_unlock(&monlock);
			ast_log(LOG_WARNING, "Unable to lock the interface list\n");
			return -1;
		}
  ast_log(LOG_ERROR, "BRCM: restart_monitor 5\n");
		monitor = 0;
		while (pthread_kill(monitor_thread, SIGURG) == 0)
			sched_yield();
		pthread_join(monitor_thread, NULL);
		ast_mutex_unlock(&iflock);
	}
	ast_log(LOG_ERROR, "BRCM: restart_monitor 6\n");
	monitor = 1;
	/* Start a new monitor */
	if (ast_pthread_create_background(&monitor_thread, NULL, do_monitor, NULL) < 0) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_ERROR, "Unable to start monitor thread.\n");
		return -1;
	}
  ast_log(LOG_ERROR, "BRCM: restart_monitor 7\n");
	ast_mutex_unlock(&monlock);
	return 0;
}

static struct brcm_pvt *mkif(const char *iface, int mode, int txgain, int rxgain)
{
	/* Make a brcm_pvt structure for this interface */
	struct brcm_pvt *tmp;
	int flags;	
	
	tmp = ast_calloc(1, sizeof(*tmp));
	if (tmp) {
		tmp->fd = open(iface, O_RDWR);
		if (tmp->fd < 0) {
			ast_log(LOG_WARNING, "Unable to open '%s'\n", iface);
			ast_free(tmp);
			return NULL;
		}
		if (echocancel != AEC_OFF)
			ioctl(tmp->fd, IXJCTL_AEC_START, echocancel);
		if (silencesupression) 
			tmp->silencesupression = 1;
		tmp->mode = mode;
		flags = fcntl(tmp->fd, F_GETFL);
		fcntl(tmp->fd, F_SETFL, flags | O_NONBLOCK);
		tmp->owner = NULL;
		tmp->lastformat = -1;
		tmp->lastinput = -1;
		tmp->ministate = 0;
		memset(tmp->ext, 0, sizeof(tmp->ext));
		ast_copy_string(tmp->language, language, sizeof(tmp->language));
		ast_copy_string(tmp->dev, iface, sizeof(tmp->dev));
		ast_copy_string(tmp->context, context, sizeof(tmp->context));
		tmp->next = NULL;
		tmp->obuflen = 0;
		tmp->dialtone = 0;
		tmp->cpt = 0;
		ast_copy_string(tmp->cid_num, cid_num, sizeof(tmp->cid_num));
		ast_copy_string(tmp->cid_name, cid_name, sizeof(tmp->cid_name));
		tmp->txgain = txgain;
		tmp->rxgain = rxgain;
	}
	return tmp;
}

static struct ast_channel *brcm_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause)
{
	format_t oldformat;
	struct brcm_pvt *p;
	struct ast_channel *tmp = NULL;
	char *name = data;


	format_t src, dst;
	

	/* Search for an unowned channel */
	if (ast_mutex_lock(&iflock)) {
		ast_log(LOG_ERROR, "Unable to lock interface list???\n");
		return NULL;
	}

	p = iflist;
	tmp = brcm_new(p, AST_STATE_DOWN, p->context, requestor ? requestor->linkedid : NULL);
	ast_mutex_unlock(&iflock);
	/* restart_monitor(); */
	if (tmp == NULL) {
		oldformat = format;
		format &= (AST_FORMAT_G729A | AST_FORMAT_G723_1 | AST_FORMAT_SLINEAR | AST_FORMAT_ULAW);
		if (!format) {
			char buf[256];
			ast_log(LOG_ERROR, "Asked to get a channel of unsupported format '%s'\n", ast_getformatname_multiple(buf, sizeof(buf), oldformat));
			return NULL;
		}
	}

	tmp->fds[0] = p->fd;

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

static int __unload_module(void)
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
		if (monitor_thread > AST_PTHREADT_NULL) {
			monitor = 0;
			while (pthread_kill(monitor_thread, SIGURG) == 0)
				sched_yield();
			pthread_join(monitor_thread, NULL);
		}
		monitor_thread = AST_PTHREADT_STOP;
		ast_mutex_unlock(&monlock);
	} else {
		ast_log(LOG_WARNING, "Unable to lock the monitor\n");
		return -1;
	}

	if (!ast_mutex_lock(&iflock)) {
		/* Destroy all the interfaces and free their memory */
		p = iflist;
		while(p) {
			/* Close the socket, assuming it's real */
			if (p->fd > -1)
				close(p->fd);
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

	endpt_deinit();
		
	return 0;
}

static int unload_module(void)
{
	return __unload_module();
}

static int load_module(void)
{
	struct ast_config *cfg;
	struct ast_variable *v;
	struct brcm_pvt *tmp;
	int mode = MODE_IMMEDIATE;
	int txgain = DEFAULT_GAIN, rxgain = DEFAULT_GAIN; /* default gain 1.0 */
	struct ast_flags config_flags = { 0 };

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
	v = ast_variable_browse(cfg, "interfaces");
	while(v) {
		/* Create the interface list */
		if (!strcasecmp(v->name, "device")) {
				tmp = mkif(v->value, mode, txgain, rxgain);
				if (tmp) {
					tmp->next = iflist;
					iflist = tmp;
					
				} else {
					ast_log(LOG_ERROR, "Unable to register channel '%s'\n", v->value);
					ast_config_destroy(cfg);
					ast_mutex_unlock(&iflock);
					__unload_module();
					return AST_MODULE_LOAD_FAILURE;
				}
		} else if (!strcasecmp(v->name, "silencesupression")) {
			silencesupression = ast_true(v->value);
		} else if (!strcasecmp(v->name, "language")) {
			ast_copy_string(language, v->value, sizeof(language));
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_callerid_split(v->value, cid_name, sizeof(cid_name), cid_num, sizeof(cid_num));
		} else if (!strcasecmp(v->name, "mode")) {
			if (!strncasecmp(v->value, "di", 2)) 
				mode = MODE_DIALTONE;
			else if (!strncasecmp(v->value, "sig", 3))
				mode = MODE_SIGMA;
			else if (!strncasecmp(v->value, "im", 2))
				mode = MODE_IMMEDIATE;
			else if (!strncasecmp(v->value, "fxs", 3)) {
				mode = MODE_FXS;
				prefformat = 0x01ff0000; /* All non-voice */
			}
			else if (!strncasecmp(v->value, "fx", 2))
				mode = MODE_FXO;
			else
				ast_log(LOG_WARNING, "Unknown mode: %s\n", v->value);
		} else if (!strcasecmp(v->name, "context")) {
			ast_copy_string(context, v->value, sizeof(context));
		} else if (!strcasecmp(v->name, "format")) {
			if (!strcasecmp(v->value, "g729")) {
				prefformat = AST_FORMAT_G729A;
                        } else if (!strcasecmp(v->value, "g723.1")) {
				prefformat = AST_FORMAT_G723_1;
			} else if (!strcasecmp(v->value, "slinear")) {
				if (mode == MODE_FXS)
				    prefformat |= AST_FORMAT_SLINEAR;
				else prefformat = AST_FORMAT_SLINEAR;
			} else if (!strcasecmp(v->value, "ulaw")) {
				prefformat = AST_FORMAT_ULAW;
			} else
				ast_log(LOG_WARNING, "Unknown format '%s'\n", v->value);
		} else if (!strcasecmp(v->name, "echocancel")) {
			if (!strcasecmp(v->value, "off")) {
				echocancel = AEC_OFF;
			} else if (!strcasecmp(v->value, "low")) {
				echocancel = AEC_LOW;
			} else if (!strcasecmp(v->value, "medium")) {
				echocancel = AEC_MED;
			} else if (!strcasecmp(v->value, "high")) {
				echocancel = AEC_HIGH;
			} else 
				ast_log(LOG_WARNING, "Unknown echo cancellation '%s'\n", v->value);
		} else if (!strcasecmp(v->name, "txgain")) {
			txgain = parse_gain_value(v->name, v->value);
		} else if (!strcasecmp(v->name, "rxgain")) {
			rxgain = parse_gain_value(v->name, v->value);
		}	
		v = v->next;
	}
	ast_mutex_unlock(&iflock);

	if (mode == MODE_FXS) {
		brcm_tech_fxs.capabilities = prefformat;
		cur_tech = &brcm_tech_fxs;
	} else
		cur_tech = (struct ast_channel_tech *) &brcm_tech;

	/* Make sure we can register our Adtranphone channel type */

	if (ast_channel_register(cur_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'Brcm'\n");
		ast_config_destroy(cfg);
		__unload_module();
		return AST_MODULE_LOAD_FAILURE;
	}
	ast_config_destroy(cfg);
	/* And start the monitor for the first time */

	endpt_init();
	restart_monitor();

	return AST_MODULE_LOAD_SUCCESS;
}



void endptEventCb()
{
  printf("Received callback event.\n");
}


void ingressPktRecvCb( ENDPT_STATE *endptState, int cnxId, EPPACKET *epPacketp, int length )
{

}


int endpt_deinit(void)
{
  vrgEndptDeinit();

  return 0;
}


int endpt_init(void)
{
  int num_endpts;
  VRG_ENDPT_INIT_CFG   vrgEndptInitCfg;
  int rc, i;

  ast_verbose("Initializing endpoint interface\n");

  vrgEndptDriverOpen();

  vrgEndptInitCfg.country = VRG_COUNTRY_NORTH_AMERICA;
  vrgEndptInitCfg.currentPowerSource = 0;

  /* Intialize endpoint */
  rc = vrgEndptInit( &vrgEndptInitCfg,
		     endptEventCb,
		     ingressPktRecvCb,
		     NULL,
		     NULL,
		     NULL,
		     NULL );

  num_endpts = vrgEndptGetNumEndpoints();
  
  printf("Num endpoints: %d\n", num_endpts);

  /* Creating Endpt */
  for ( i = 0; i < vrgEndptGetNumEndpoints(); i++ )
    {
      rc = vrgEndptCreate( i, i,(VRG_ENDPT_STATE *)&endptObjState[i] );
    }

  return 0;
}


int signal_ringing(void)
{
  int i;

#ifdef LOUD
   /* Check whether value is on or off */
  for ( i = 0; i < vrgEndptGetNumEndpoints(); i++ )
     vrgEndptSignal( (ENDPT_STATE*)&endptObjState[i], -1, EPSIG_RINGING, 1, -1, -1 , -1);
#endif
  return 0;
}


int stop_ringing(void)
{
  int i;

#ifdef LOUD
   /* Check whether value is on or off */
  for ( i = 0; i < vrgEndptGetNumEndpoints(); i++ )
     vrgEndptSignal( (ENDPT_STATE*)&endptObjState[i], -1, EPSIG_RINGING, 0, -1, -1 , -1);
#endif

  return 0;
}


/*
*****************************************************************************
** FUNCTION:   vrgEndptDriverOpen
**
** PURPOSE:    Opens the Linux kernel endpoint driver.
**             This function should be the very first call used by the
**             application before isssuing any other endpoint APIs because
**             the ioctls for the endpoint APIs won't reach the kernel
**             if the driver is not successfully opened.
**
** PARAMETERS:
**
** RETURNS:    EPSTATUS
**
*****************************************************************************
*/
EPSTATUS vrgEndptDriverOpen(void)
{
   /* Open and initialize Endpoint driver */
   if( ( fd = open("/dev/bcmendpoint0", O_RDWR) ) == -1 )
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


/*
*****************************************************************************
** FUNCTION:   vrgEndptDriverClose
**
** PURPOSE:    Close endpoint driver
**
** PARAMETERS: None
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgEndptDriverClose()
{
   if ( close( fd ) == -1 )
   {
      printf("%s: close error %d", __FUNCTION__, errno);
      return ( EPSTATUS_DRIVER_ERROR );
   }

   fd = NOT_INITIALIZED;

   return( EPSTATUS_SUCCESS );
}


/*
*****************************************************************************
** FUNCTION:   vrgEndptInit
**
** PURPOSE:    Module initialization for the VRG endpoint. The endpoint
**             module is responsible for controlling a set of endpoints.
**             Individual endpoints are initialized using the vrgEndptInit() API.
**
** PARAMETERS: country           - Country type
**             notifyCallback    - Callback to use for event notification
**             packetCallback           - Callback to use for endpt packets
**             getProvisionCallback     - Callback to get provisioned values.
**                                        May be set to NULL.
**             setProvisionCallback     - Callback to get provisioned values.
**                                        May be set to NULL.
**             packetReleaseCallback    - Callback to release ownership of
**                                        endpt packet back to caller
**             taskShutdownCallback     - Callback invoked to indicate endpt
**                                        task shutdown
**
** RETURNS:    EPSTATUS
**
** NOTE:       getProvisionCallback, setProvisionCallback,
**             packetReleaseCallback, and taskShutdownCallback are currently not used within
**             the DSL framework and should be set to NULL when
**             invoking this function.
**
*****************************************************************************
*/
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
   if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_INIT, &tStartupParam ) != IOCTL_STATUS_SUCCESS )
     return ( tStartupParam.epStatus );

   return ( tStartupParam.epStatus );
}


/*
*****************************************************************************
** FUNCTION:   vrgEndptDeinit
**
** PURPOSE:    VRG endpoint module shutdown - call once during system shutdown.
**             This will shutdown all endpoints and free all resources used by
**             the VRG endpt manager. (i.e. this function should free all resources
**             allocated in vrgEndptInit() and vrgEndptCreate()).
**
** PARAMETERS: none
**
** RETURNS:    EPSTATUS
**             This function should only return an error under catastrophic
**             circumstances. i.e. Something that cannot be fixed by re-invoking
**             the module initialization function.
**
** NOTE:       It is assumed that this function is only called after all endpoint
**             tasks have been notified of a pending application reset, and each
**             one has acknowledged the notification. This implies that each endpoint
**             task is currently blocked, waiting to be resumed so that they may
**             complete the shutdown procedure.
**
**             It is also assumed that no task is currently blocked on any OS
**             resource that was created in the module initialization functions.
**
*****************************************************************************
*/
EPSTATUS vrgEndptDeinit( void )
{
   int filehandle = open("/dev/bcmendpoint0", O_RDWR);
   if ( filehandle == -1 )
   {
      return( EPSTATUS_DRIVER_ERROR );
   }

   if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_DEINIT, NULL ) != IOCTL_STATUS_SUCCESS )
   {
   }

   /* bGlobalTaskExit = TRUE; */

   close( filehandle );

   /* endptDeinitialized = 1; */

   return( EPSTATUS_SUCCESS );
}


/*****************************************************************************
*  FUNCTION:   vrgEndptSignal
*
*  PURPOSE:    Generate a signal on the endpoint (or connection)
*
*  PARAMETERS: endptState  - state of the endpt object
*              cnxId       - connection identifier (-1 if not applicable)
*              signal      - signal type code (see EPSIG)
*              value       - signal value
*                          BR signal types - 1
*                          OO signal types - 0 == off, 1 == on
*                          TO signal types - 0 = stop/off, 1= start/on
*                          String types - (char *) cast to NULL-term string value
*
*  RETURNS:    EPSTATUS
*
*****************************************************************************/
EPSTATUS vrgEndptSignal
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

   if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_SIGNAL, &tSignalParm ) != IOCTL_STATUS_SUCCESS )
   {
   }

   return( tSignalParm.epStatus );
}


/*
*****************************************************************************
** FUNCTION:   vrgEndptGetNumEndpoints
**
** PURPOSE:    Retrieve the number of endpoints
**
** PARAMETERS: None
**
** RETURNS:    Number of endpoints
**
*****************************************************************************
*/
int vrgEndptGetNumEndpoints( void )
{
   ENDPOINTDRV_ENDPOINTCOUNT_PARM endpointCount;
   int retVal = 0;
   int filehandle = open("/dev/bcmendpoint0", O_RDWR);

   endpointCount.size = sizeof(ENDPOINTDRV_ENDPOINTCOUNT_PARM);

   if ( ioctl( filehandle, ENDPOINTIOCTL_ENDPOINTCOUNT, &endpointCount ) != IOCTL_STATUS_SUCCESS )
   {
   }
   else
   {
      retVal = endpointCount.endpointNum;
   }

   close(filehandle);

   return( retVal );
}


/*
*****************************************************************************
** FUNCTION:   vrgEndptCreate
**
** PURPOSE:    This function is used to create an VRG endpoint object.
**
** PARAMETERS: physId      (in)  Physical interface.
**             lineId      (in)  Endpoint line identifier.
**             endptState  (out) Created endpt object.
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgEndptCreate( int physId, int lineId, VRG_ENDPT_STATE *endptState )
{
   ENDPOINTDRV_CREATE_PARM tInitParm;

   tInitParm.physId     = physId;
   tInitParm.lineId     = lineId;
   tInitParm.endptState = endptState;
   tInitParm.epStatus   = EPSTATUS_DRIVER_ERROR;
   tInitParm.size       = sizeof(ENDPOINTDRV_CREATE_PARM);

   /* Check if kernel driver is opened */

   if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_CREATE, &tInitParm ) != IOCTL_STATUS_SUCCESS )
   {
   }

   return( tInitParm.epStatus );
}


/*
*****************************************************************************
** FUNCTION:   vrgEndptDestroy
**
** PURPOSE:    This function is used to destroy VRG endpoint object
**             (previously created with vrgEndptCreate)
**
** PARAMETERS: endptState (in) Endpt object to be destroyed.
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgEndptDestroy( VRG_ENDPT_STATE *endptState )
{
   ENDPOINTDRV_DESTROY_PARM tInitParm;

   tInitParm.endptState = endptState;
   tInitParm.epStatus   = EPSTATUS_DRIVER_ERROR;
   tInitParm.size       = sizeof(ENDPOINTDRV_DESTROY_PARM);

   /* Check if kernel driver is opened */

   if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_DESTROY, &tInitParm ) != IOCTL_STATUS_SUCCESS )
   {
   }

   return( tInitParm.epStatus );
}


int create_connection() {

  int i;
  int buf_pos_idx = 0;

  UINT8 packet_buffer[PACKET_BUFFER_SIZE] = {0};
  int tcounter = 0;
  UINT8 data[1024] = {0};
  unsigned int *data32;

  /* generate random nr for rtp header */
  ssrc = rand();

  for ( i = 0; i < /*vrgEndptGetNumEndpoints()*/1; i++ ) {
    ENDPOINTDRV_CONNECTION_PARM tConnectionParm;
    EPZCNXPARAM epCnxParms = {0};
    //		CODECLIST  codecListLocal = {0};
    //		CODECLIST  codecListRemote = {0};

    /* Enable sending a receving G711 */
    epCnxParms.cnxParmList.recv.numCodecs = 3;
    epCnxParms.cnxParmList.recv.codecs[0].type = CODEC_PCMU;
    epCnxParms.cnxParmList.recv.codecs[0].rtpPayloadType = RTP_PAYLOAD_PCMU;
    epCnxParms.cnxParmList.recv.codecs[1].type = CODEC_PCMA;
    epCnxParms.cnxParmList.recv.codecs[1].rtpPayloadType = RTP_PAYLOAD_PCMA;
    epCnxParms.cnxParmList.recv.codecs[2].type = CODEC_G726_32;
    epCnxParms.cnxParmList.recv.codecs[2].rtpPayloadType = RTP_PAYLOAD_G726_32;

    epCnxParms.cnxParmList.send.numCodecs = 3;
    epCnxParms.cnxParmList.send.codecs[0].type = CODEC_PCMU;
    epCnxParms.cnxParmList.send.codecs[0].rtpPayloadType = RTP_PAYLOAD_PCMU;
    epCnxParms.cnxParmList.send.codecs[1].type = CODEC_PCMA;
    epCnxParms.cnxParmList.send.codecs[1].rtpPayloadType = RTP_PAYLOAD_PCMA;
    epCnxParms.cnxParmList.send.codecs[2].type = CODEC_G726_32;
    epCnxParms.cnxParmList.send.codecs[2].rtpPayloadType = RTP_PAYLOAD_G726_32;

    // Set 20ms packetization period
    epCnxParms.cnxParmList.send.period[0] = 20;
    epCnxParms.mode  =   EPCNXMODE_SNDRX;
    //         epCnxParms.cnxParmList.recv = codecListLocal;
    //         epCnxParms.cnxParmList.send = codecListRemote;
    //         epCnxParms.period = 20;
    epCnxParms.echocancel = 1;
    epCnxParms.silence = 0;
    //         epCnxParms.pktsize = CODEC_G711_PAYLOAD_BYTE;   /* Not used ??? */


    tConnectionParm.cnxId      = i;
    tConnectionParm.cnxParam   = &epCnxParms;
    tConnectionParm.state      = (ENDPT_STATE*)&endptObjState[i];
    tConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
    tConnectionParm.size       = sizeof(ENDPOINTDRV_CONNECTION_PARM);

    if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_CREATE_CONNECTION, &tConnectionParm ) != IOCTL_STATUS_SUCCESS ){
      printf("%s: error during ioctl", __FUNCTION__);
    } else {
      printf("\n\nConnection %d created\n\n",i);
    }
  }

  return 0;
}


int close_connection(void) {
  int i;

  /* Close connection */
  for ( i = 0; i < /*vrgEndptGetNumEndpoints()*/1; i++ ) {
    ENDPOINTDRV_DELCONNECTION_PARM tDelConnectionParm;

    tDelConnectionParm.cnxId      = i;
    tDelConnectionParm.state      = (ENDPT_STATE*)&endptObjState[i];
    tDelConnectionParm.epStatus   = EPSTATUS_DRIVER_ERROR;
    tDelConnectionParm.size       = sizeof(ENDPOINTDRV_DELCONNECTION_PARM);

    if ( ioctl( fd, ENDPOINTIOCTL_ENDPT_DELETE_CONNECTION, &tDelConnectionParm ) != IOCTL_STATUS_SUCCESS )
      {
	printf("%s: error during ioctl", __FUNCTION__);
      } else {
      printf("\n\nConnection %d closed\n\n",i);
    }
  }

  return 0;
}


/* Generate rtp payload, 12 bytes of header and 160 bytes of ulaw payload */
void generate_rtp_packet(UINT8 *packet_buf) {
	int i,j;
	int bidx = 0;
	unsigned short* packet_buf16 = (unsigned short*)packet_buf;
	unsigned int*   packet_buf32 = (unsigned int*)packet_buf;

	//Generate the rtp header, packet is zero from the start, that fact is used
	packet_buf[0] |= 0x80; //Set version 2 of header
	//Padding 0
	//Extension 0
	//CSRC count 0
	//Marker 0
	packet_buf[1] = 0; //Payload type PCMU = 0, FIXME use table to lookup value
	packet_buf16[1] = sequence_number++; //Add sequence number
	if (sequence_number > 0xFFFF) sequence_number=0;
	packet_buf32[1] = time_stamp;	//Add timestamp
	time_stamp += 160;
	packet_buf32[2] = ssrc;	//Random SSRC

	//Add the payload
	bidx = 12;

}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Brcm SLIC channel");
