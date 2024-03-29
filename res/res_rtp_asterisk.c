/*!
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2008, Digium, Inc.
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

/*!
 * \file
 *
 * \brief Supports RTP and RTCP with Symmetric RTP support for NAT traversal.
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Olle E. Johansson <oej@edvina.net>
 *
 * \note RTP is defined in RFC 3550.
 *
 * \ingroup rtp_engines
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 351611 $")

#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>

#include "asterisk/options.h"
#include "asterisk/stun.h"
#include "asterisk/pbx.h"
#include "asterisk/frame.h"
#include "asterisk/channel.h"
#include "asterisk/acl.h"
#include "asterisk/config.h"
#include "asterisk/lock.h"
#include "asterisk/utils.h"
#include "asterisk/cli.h"
#include "asterisk/manager.h"
#include "asterisk/unaligned.h"
#include "asterisk/module.h"
#include "asterisk/rtp_engine.h"

#define MAX_TIMESTAMP_SKEW	640

#define RTP_SEQ_MOD     (1<<16)	/*!< A sequence number can't be more than 16 bits */
#define RTCP_DEFAULT_INTERVALMS   5000	/*!< Default milli-seconds between RTCP reports we send */
#define RTCP_MIN_INTERVALMS       500	/*!< Min milli-seconds between RTCP reports we send */
#define RTCP_MAX_INTERVALMS       60000	/*!< Max milli-seconds between RTCP reports we send */

#define DEFAULT_RTP_START 5000 /*!< Default port number to start allocating RTP ports from */
#define DEFAULT_RTP_END 31000  /*!< Default maximum port number to end allocating RTP ports at */

#define MINIMUM_RTP_PORT 1024 /*!< Minimum port number to accept */
#define MAXIMUM_RTP_PORT 65535 /*!< Maximum port number to accept */

#define RTCP_PT_FUR     192		/*!< FIR  - Full Intra-frame request (h.261) */
#define RTCP_PT_NACK    193		/*!< NACK - Negative acknowledgement (h.261) */
#define RTCP_PT_IJ      195		/*!< IJ   - RFC 5450 Extended Inter-arrival jitter report */
#define RTCP_PT_SR      200		/*!< SR   - RFC 3550 Sender report */
#define RTCP_PT_RR      201		/*!< RR   - RFC 3550 Receiver report */
#define RTCP_PT_SDES    202		/*!< SDES - Source Description */
#define RTCP_PT_BYE     203		/*!< BYE  - Goodbye */
#define RTCP_PT_APP     204		/*!< APP  - Application defined */
#define RTCP_PT_RTPFB   205		/*!< RTPFB - Generic RTP feedback RFC 4585 */
#define RTCP_PT_PSFB    206		/*!< PSFB - Payload specific data  RFC 4585 */
#define RTCP_PT_XR      207		/*!< XR   - Extended report - RFC3611 */
#define RTCP_PT_AVB     208		/*!< ACB RTCP Packet */
#define RTCP_PT_RSI     209		/*!< Receiver summary information */
#define RTCP_PT_TOKEN   210		/*!< Port mapping, RFC 6284 */

/*! \brief RFC 3550 RTCP SDES Item types */
enum rtcp_sdes {
	SDES_END	= 0,		/*!< End of SDES list */
	SDES_CNAME	= 1,		/*!< Canonical name */
	SDES_NAME	= 2,		/*!< User name */
	SDES_EMAIL	= 3,		/*!< User's e-mail address */
	SDES_PHONE	= 4,		/*!< User's phone number */
	SDES_LOC	= 5,		/*!< Geographic user location */
	SDES_TOOL	= 6,		/*!< Name of application or tool */
	SDES_NOTE	= 7,		/*!< Notice about the source */
	SDES_PRIV	= 8,		/*!< SDES Private extensions */
	SDES_H323_CADDR	= 9,		/*!< H.323 Callable address */
	SDES_APSI	= 10,		/*!< Application Specific Identifier (RFC 6776) */
};

#define RTP_MTU		1200

#define DTMF_SAMPLE_RATE_MS    8 /*!< DTMF samples per millisecond */

#define DEFAULT_DTMF_TIMEOUT (150 * (8000 / 1000))	/*!< samples */
#define DEFAULT_DTMF_GAP	45000			/*!< Minimum DTMF gap (as in channel.c) in microseconds - used for DTMF "echo"/dtmfmute */
							/* used to be 500000 microseconds - far too much */

#define ZFONE_PROFILE_ID 0x505a

#define DEFAULT_LEARNING_MIN_SEQUENTIAL 4

extern struct ast_srtp_res *res_srtp;
static int dtmftimeout = DEFAULT_DTMF_TIMEOUT;

static int rtpstart = DEFAULT_RTP_START;			/*!< First port for RTP sessions (set in rtp.conf) */
static int rtpend = DEFAULT_RTP_END;			/*!< Last port for RTP sessions (set in rtp.conf) */
static int rtpdebug;			/*!< Are we debugging? */
static int rtcpdebug;			/*!< Are we debugging RTCP? */
static int rtcpstats;			/*!< Are we gathering stats? */
static int rtcpinterval = RTCP_DEFAULT_INTERVALMS; /*!< Time between rtcp reports in millisecs */
static struct ast_sockaddr rtpdebugaddr;	/*!< Debug packets to/from this host */
static struct ast_sockaddr rtcpdebugaddr;	/*!< Debug RTCP packets to/from this host */
static int rtpdebugport;		/*< Debug only RTP packets from IP or IP+Port if port is > 0 */
static int rtcpdebugport;		/*< Debug only RTCP packets from IP or IP+Port if port is > 0 */
#ifdef SO_NO_CHECK
static int nochecksums;
#endif
static int strictrtp;			/*< Only accept RTP frames from a defined source. If we receive an indication of a changing source, enter learning mode. */
static int learning_min_sequential;	/*< Number of sequential RTP frames needed from a single source during learning mode to accept new source. */

enum strict_rtp_state {
	STRICT_RTP_OPEN = 0, /*! No RTP packets should be dropped, all sources accepted */
	STRICT_RTP_LEARN,    /*! Accept next packet as source */
	STRICT_RTP_CLOSED,   /*! Drop all RTP packets not coming from source that was learned */
};

/*! \brief States for an outbound RTP stream that handles DTMF in RFC 2833 mode */
enum dtmf_send_states {
	DTMF_NOT_SENDING = 0,	/*! Not sending DTMF this very moment */
	DTMF_SEND_INIT,		/*! Initializing */
	DTMF_SEND_INPROGRESS,	/*! Playing DTMF */
	DTMF_SEND_INPROGRESS_WITH_QUEUE	/*! Playing and having a queue to continue with */
};

#define FLAG_3389_WARNING               (1 << 0)
#define FLAG_NAT_ACTIVE                 (3 << 1)
#define FLAG_NAT_INACTIVE               (0 << 1)
#define FLAG_NAT_INACTIVE_NOWARN        (1 << 1)
#define FLAG_NEED_MARKER_BIT            (1 << 3)
#define FLAG_DTMF_COMPENSATE            (1 << 4)
#define FLAG_HOLD	        	(1 << 4)	/* This RTP stream is put on hold by someone else, a:sendonly */

/*! \brief RTP session description */
struct ast_rtp {
	int s;
	struct ast_frame f;
	unsigned char rawdata[8192 + AST_FRIENDLY_OFFSET];
	unsigned int ssrc;		/*!< Synchronization source, RFC 3550, page 10. */
	unsigned int themssrc;		/*!< Their SSRC */
	unsigned int rxssrc;
	unsigned int lastts;
	unsigned int lastrxts;
	unsigned int lastividtimestamp;
	unsigned int lastovidtimestamp;
	unsigned int lastitexttimestamp;
	unsigned int lastotexttimestamp;
	unsigned int lasteventseqn;
	int lastrxseqno;                /*!< Last received sequence number */
	unsigned short seedrxseqno;     /*!< What sequence number did they start with?*/
	unsigned int seedrxts;          /*!< What RTP timestamp did they start with? */
	unsigned int rxcount;           /*!< How many packets have we received? */
	unsigned int rxoctetcount;      /*!< How many octets have we received? should be rxcount *160*/
	unsigned int txcount;           /*!< How many packets have we sent? */
	unsigned int txoctetcount;      /*!< How many octets have we sent? (txcount*160)*/
	unsigned int cycles;            /*!< Shifted count of sequence number cycles */
	double rxjitter;                /*!< Interarrival jitter at the moment in seconds */
	double rxtransit;               /*!< Relative transit time for previous packet */
	format_t lasttxformat;
	format_t lastrxformat;

	int rtptimeout;			/*!< RTP timeout time (negative or zero means disabled, negative value means temporarily disabled) */
	int rtpholdtimeout;		/*!< RTP timeout when on hold (negative or zero means disabled, negative value means temporarily disabled). */
	int rtpkeepalive;		/*!< Send RTP comfort noice packets for keepalive */

	/* DTMF Reception Variables */
	char resp;
	unsigned int lastevent;
	unsigned int dtmf_duration;     /*!< Total duration in samples since the digit start event */
	unsigned int dtmf_timeout;      /*!< When this timestamp is reached we consider END frame lost and forcibly abort digit */
	unsigned int dtmfsamples;
	enum ast_rtp_dtmf_mode dtmfmode;/*!< The current DTMF mode of the RTP stream */
	/* DTMF Transmission Variables */
	unsigned int lastdigitts;
	enum dtmf_send_states sending_dtmf;     /*!< - are we sending dtmf */
	char send_digit;                /*!< digit we are sending in Ascii */
	char send_dtmf_frame;           /*!< Number of samples in a frame with the current packetization */
	AST_LIST_HEAD_NOLOCK(, ast_frame) dtmfqueue;    /*!< \ref DTMFQUEUE : Queue for DTMF that we receive while occupied with transmitting an outbound DTMF */
	struct timeval dtmfmute;	/*!< Minimum time between DTMF... Default 500 ms. */
	int send_endflag:1;             /*!< We have received END marker but are in waiting mode */
	unsigned int received_duration; /*!< Received duration (according to control frames) */
	int send_payload;
	int send_duration;
	unsigned int flags;
	struct timeval rxcore;
	struct timeval txcore;
	double drxcore;                 /*!< The double representation of the first received packet */
	struct timeval start;          /*!< When the stream started (we can't depend on CDRs) */
	struct timeval lastrx;          /*!< timeval when we last received a packet */
	struct timeval holdstart;       /*!< When the stream was put on hold */
	struct ast_smoother *smoother;
	unsigned short seqno;		/*!< Sequence number, RFC 3550, page 13. */
	unsigned short rxseqno;
	struct sched_context *sched;
	struct io_context *io;
	void *data;
	struct ast_rtcp *rtcp;
	struct ast_rtp *bridged;        /*!< Who we are Packet bridged to */

	enum strict_rtp_state strict_rtp_state; /*!< Current state that strict RTP protection is in */
	struct ast_sockaddr strict_rtp_address;  /*!< Remote address information for strict RTP purposes */
	struct ast_sockaddr alt_rtp_address; /*!<Alternate remote address information */

	/*
	 * Learning mode values based on pjmedia's probation mode.  Many of these values are redundant to the above,
	 * but these are in place to keep learning mode sequence values sealed from their normal counterparts.
	 */
	uint16_t learning_max_seq;		/*!< Highest sequence number heard */
	int learning_probation;		/*!< Sequential packets untill source is valid */
	int isactive;			/*!< Whether the RTP stream is active or not */

	struct rtp_red *red;
};

/*!
 * \brief Structure defining an RTCP session.
 *
 * The concept "RTCP session" is not defined in RFC 3550, but since
 * this structure is analogous to ast_rtp, which tracks a RTP session,
 * it is logical to think of this as a RTCP session.
 *
 * On the other hand, RTCP SDES defines the names for the actual
 * RTP session so it's one session - RTP and RTCP together (OEJ)
 *
 * RTCP packet is defined on page 9 of RFC 3550.
 *
 */
struct ast_rtcp {
	int rtcp_info;
	char ourcname[255];		/*!< Our SDES RTP session name (CNAME) */
	size_t ourcnamelength;		/*!< Length of CNAME (utf8) */
	char theircname[255];		/*!< Their SDES RTP session name (CNAME) */
	size_t theircnamelength;	/*!< Length of CNAME (utf8) */
	int s;				/*!< Socket */
	struct ast_sockaddr us;		/*!< Socket representation of the local endpoint. */
	struct ast_sockaddr them;	/*!< Socket representation of the remote endpoint. */
	unsigned int soc;		/*!< What they told us */
	unsigned int spc;		/*!< What they told us */
	unsigned int themrxlsr;		/*!< The middle 32 bits of the NTP timestamp in the last received SR*/
	struct timeval rxlsr;		/*!< Time when we got their last SR */
	struct timeval txlsr;		/*!< Time when we sent or last SR*/
	unsigned int expected_prior;	/*!< no. packets in previous interval */
	unsigned int received_prior;	/*!< no. packets received in previous interval */
	int schedid;			/*!< Schedid returned from ast_sched_add() to schedule RTCP-transmissions*/
	unsigned int rr_count;		/*!< number of RRs we've sent, not including report blocks in SR's */
	unsigned int sr_count;		/*!< number of SRs we've sent */
	unsigned int rec_rr_count;      /*!< Number of RRs we've received */
	unsigned int rec_sr_count;      /*!< Number of SRs we've received */
	unsigned int lastsrtxcount;     /*!< Transmit packet count when last SR sent */
	double accumulated_transit;	/*!< accumulated a-dlsr-lsr */
	double rtt;			/*!< Last reported rtt */
	unsigned int reported_jitter;	/*!< The contents of their last jitter entry in the RR */
	unsigned int reported_lost;	/*!< Reported lost packets in their RR */

	double reported_maxjitter;	/*!< The contents of their max jitter entry received by us */
	double reported_minjitter;	/*!< The contents of their min jitter entry received by us */
	double reported_normdev_jitter;
	double reported_stdev_jitter;
	unsigned int reported_jitter_count; /*! Number of reports received */

	double reported_maxlost;
	double reported_minlost;
	double reported_normdev_lost;
	double reported_stdev_lost;

	double rxlost;
	double maxrxlost;
	double minrxlost;
	double normdev_rxlost;
	double stdev_rxlost;
	unsigned int rxlost_count;	/*! Number of reports received */

	double maxrxjitter;
	double minrxjitter;
	double normdev_rxjitter;
	double stdev_rxjitter;
	unsigned int rxjitter_count;	/*! Number of reports received */
	double maxrtt;
	double minrtt;
	double normdevrtt;
	double stdevrtt;
	unsigned int rtt_count;		/*! Number of reports received */
	char bridgedchannel[AST_MAX_EXTENSION];		/*!< Bridged channel name */
	char bridgeduniqueid[AST_MAX_EXTENSION];	/*!< Bridged channel uniqueid */
	char channel[AST_MAX_EXTENSION];		/*!< Our channel name */
	char uniqueid[AST_MAX_EXTENSION];	/*!< Our channel uniqueid */
	char readtranslator[80];	/* Translation done on reading audio from PBX */
	char writetranslator[80];	/* Translation done on writing audio to PBX - bridged channel */
	int readcost;			/* Delay in milliseconds for translation of 1 second of audio */
	int writecost;			/* Delay in milliseconds for translation of 1 second of audio */
};

struct rtp_red {
	struct ast_frame t140;  /*!< Primary data  */
	struct ast_frame t140red;   /*!< Redundant t140*/
	unsigned char pt[AST_RED_MAX_GENERATION];  /*!< Payload types for redundancy data */
unsigned char ts[AST_RED_MAX_GENERATION]; /*!< Time stamps */
	unsigned char len[AST_RED_MAX_GENERATION]; /*!< length of each generation */
	int num_gen; /*!< Number of generations */
	int schedid; /*!< Timer id */
	int ti; /*!< How long to buffer data before send */
	unsigned char t140red_data[64000];
	unsigned char buf_data[64000]; /*!< buffered primary data */
	int hdrlen;
	long int prev_ts;
};

AST_LIST_HEAD_NOLOCK(frame_list, ast_frame);

/* Forward Declarations */
static int ast_rtp_new(struct ast_rtp_instance *instance, struct sched_context *sched, struct ast_sockaddr *addr, void *data);
static int ast_rtp_destroy(struct ast_rtp_instance *instance);
static int ast_rtp_dtmf_begin(struct ast_rtp_instance *instance, char digit);
static int ast_rtp_dtmf_continue(struct ast_rtp_instance *instance, char digit, unsigned int duration);
static int ast_rtp_dtmf_end(struct ast_rtp_instance *instance, char digit);
static int ast_rtp_dtmf_end_with_duration(struct ast_rtp_instance *instance, char digit, unsigned int duration);
static int ast_rtp_dtmf_mode_set(struct ast_rtp_instance *instance, enum ast_rtp_dtmf_mode dtmf_mode);
static enum ast_rtp_dtmf_mode ast_rtp_dtmf_mode_get(struct ast_rtp_instance *instance);
static void ast_rtp_update_source(struct ast_rtp_instance *instance);
static void ast_rtp_change_source(struct ast_rtp_instance *instance);
static int ast_rtp_write(struct ast_rtp_instance *instance, struct ast_frame *frame);
static struct ast_frame *ast_rtp_read(struct ast_rtp_instance *instance, int rtcp);
static void ast_rtp_prop_set(struct ast_rtp_instance *instance, enum ast_rtp_property property, int value);
static int ast_rtp_fd(struct ast_rtp_instance *instance, int rtcp);
static void ast_rtp_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr);
static void ast_rtp_alt_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr);
static int rtp_red_init(struct ast_rtp_instance *instance, int buffer_time, int *payloads, int generations);
static int rtp_red_buffer(struct ast_rtp_instance *instance, struct ast_frame *frame);
static int ast_rtp_local_bridge(struct ast_rtp_instance *instance0, struct ast_rtp_instance *instance1);
static int ast_rtp_get_stat(struct ast_rtp_instance *instance, struct ast_rtp_instance_stats *stats, enum ast_rtp_instance_stat stat);
static int ast_rtp_dtmf_compatible(struct ast_channel *chan0, struct ast_rtp_instance *instance0, struct ast_channel *chan1, struct ast_rtp_instance *instance1);
static void ast_rtp_stun_request(struct ast_rtp_instance *instance, struct ast_sockaddr *suggestion, const char *username);
static void ast_rtp_hold(struct ast_rtp_instance *instance, int status);
static void ast_rtp_stop(struct ast_rtp_instance *instance);
static int ast_rtp_qos_set(struct ast_rtp_instance *instance, int tos, int cos, const char* desc);
static int ast_rtp_sendcng(struct ast_rtp_instance *instance, int level);
static int ast_rtcp_write(const void *data);
static void ast_rtcp_setcname(struct ast_rtp_instance *instance, const char *cname, size_t length);
static void ast_rtcp_set_bridged(struct ast_rtp_instance *instance, const char *channel, const char *uniqueid, const char *bridgedchan, const char *bridgeduniqueid);
void ast_rtcp_set_translator(struct ast_rtp_instance *instance, const char *readtranslator, const int readcost, const char *writetranslator, const int writecost);
static int ast_rtp_isactive(struct ast_rtp_instance *instance);
static int add_sdes_bodypart(struct ast_rtp *rtp, unsigned int *rtcp_packet, int len, int type);
static int add_sdes_header(struct ast_rtp *rtp, unsigned int *rtcp_packet, int len);
static int ast_rtcp_write_empty_frame(struct ast_rtp_instance *instance);
static unsigned int calc_txstamp(struct ast_rtp *rtp, struct timeval *delivery);

/* RTP Engine Declaration */
static struct ast_rtp_engine asterisk_rtp_engine = {
	.name = "asterisk",
	.new = ast_rtp_new,
	.destroy = ast_rtp_destroy,
	.dtmf_begin = ast_rtp_dtmf_begin,
	.dtmf_continue = ast_rtp_dtmf_continue,
	.dtmf_end = ast_rtp_dtmf_end,
	.dtmf_end_with_duration = ast_rtp_dtmf_end_with_duration,
	.dtmf_mode_set = ast_rtp_dtmf_mode_set,
	.dtmf_mode_get = ast_rtp_dtmf_mode_get,
	.update_source = ast_rtp_update_source,
	.change_source = ast_rtp_change_source,
	.write = ast_rtp_write,
	.read = ast_rtp_read,
	.prop_set = ast_rtp_prop_set,
	.fd = ast_rtp_fd,
	.remote_address_set = ast_rtp_remote_address_set,
	.alt_remote_address_set = ast_rtp_alt_remote_address_set,
	.red_init = rtp_red_init,
	.red_buffer = rtp_red_buffer,
	.local_bridge = ast_rtp_local_bridge,
	.get_stat = ast_rtp_get_stat,
	.dtmf_compatible = ast_rtp_dtmf_compatible,
	.stun_request = ast_rtp_stun_request,
	.hold = ast_rtp_hold,
	.stop = ast_rtp_stop,
	.qos = ast_rtp_qos_set,
	.sendcng = ast_rtp_sendcng,
	.setcname = ast_rtcp_setcname,
	.set_bridged_chan = ast_rtcp_set_bridged,
	.set_translator = ast_rtcp_set_translator,
	.isactive = ast_rtp_isactive,
	.rtcp_write_empty = ast_rtcp_write_empty_frame,
};


/* Payload types */
struct {
	int		payload;
	const char 	*desc;
} rtcp_pt[] = {
	{ RTCP_PT_FUR,	"FIR  - Full Intra-frame request (h.261)", },
	{ RTCP_PT_NACK,	"NACK - Negative acknowledgement (h.261)", },
	{ RTCP_PT_IJ,	"IJ   - RFC 5450 Extended Inter-arrival jitter report", },
	{ RTCP_PT_SR,	"SR   - RFC 3550 Sender report", },
	{ RTCP_PT_RR,	"RR   - RFC 3550 Receiver report", },
	{ RTCP_PT_SDES,	"SDES - Source Description", },
	{ RTCP_PT_BYE ,	"BYE  - Goodbye", },
	{ RTCP_PT_APP,	"APP  - Application defined", },
	{ RTCP_PT_RTPFB," RTPFB - Generic RTP feedback RFC 4585", },
	{ RTCP_PT_PSFB,	"PSFB - Payload specific data  RFC 4585", },
	{ RTCP_PT_XR,	"XR   - Extended report - RFC3611", },
	{ RTCP_PT_AVB,	"ACB RTCP Packet", },
	{ RTCP_PT_RSI,	"Receiver summary information", },
	{ RTCP_PT_TOKEN,"Port mapping, RFC 6284", },
};

static const char *find_rtcp_pt(int payload)
{
	int x;

	for (x = 0; x < ARRAY_LEN(rtcp_pt); x++) {
		if (rtcp_pt[x].payload == payload)
			return rtcp_pt[x].desc;
	}

	return "Unknown RTCP payload";
}

/*! * \page DTMFQUEUE Queue for outbound DTMF events

	The Asterisk RTP Engine contains a queue for outbound DTMF events. Because of Asterisk's
	architecture, we might have situations where DTMF events are not happening at the same
 	time on the inbound call leg and the outbound. Because the feature handling, we might
	"swallow" a DTMF for a while to figure out the next digit. When we realize that this
	is not a digit we want, we start playing out the complete DTMF on the outbound call leg.

	During that time, we might get an incoming DTMF begin signal on the inbound call leg,
	which is transported over the bridge and to the outbound call leg, that gets a 
	request to begin a new DTMF, while still playing out the previous one.

	In order not to drop this DTMF, we queue it up until we're done with the previous
	DTMF and then play it out.

	The DTMF queue is held in the rtp structure. 
*/


static inline int rtp_debug_test_addr(struct ast_sockaddr *addr)
{
	if (!rtpdebug) {
		return 0;
	}
	if (!ast_sockaddr_isnull(&rtpdebugaddr)) {
		if (rtpdebugport) {
			return (ast_sockaddr_cmp(&rtpdebugaddr, addr) == 0); /* look for RTP packets from IP+Port */
		} else {
			return (ast_sockaddr_cmp_addr(&rtpdebugaddr, addr) == 0); /* only look for RTP packets from IP */
		}
	}

	return 1;
}

static inline int rtcp_debug_test_addr(struct ast_sockaddr *addr)
{
	if (!rtcpdebug) {
		return 0;
	}
	if (!ast_sockaddr_isnull(&rtcpdebugaddr)) {
		if (rtcpdebugport) {
			return (ast_sockaddr_cmp(&rtcpdebugaddr, addr) == 0); /* look for RTCP packets from IP+Port */
		} else {
			return (ast_sockaddr_cmp_addr(&rtcpdebugaddr, addr) == 0); /* only look for RTCP packets from IP */
		}
	}

	return 1;
}

static int __rtp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int rtcp)
{
	int len;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance);

	if ((len = ast_recvfrom(rtcp ? rtp->rtcp->s : rtp->s, buf, size, flags, sa)) < 0) {
	   return len;
	}

	if (res_srtp && srtp && res_srtp->unprotect(srtp, buf, &len, rtcp) < 0) {
	   return -1;
	}

	return len;
}

static int rtcp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_recvfrom(instance, buf, size, flags, sa, 1);
}

static int rtp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_recvfrom(instance, buf, size, flags, sa, 0);
}

static int __rtp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int rtcp)
{
	int len = size;
	void *temp = buf;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance);

	if (res_srtp && srtp && res_srtp->protect(srtp, &temp, &len, rtcp) < 0) {
	   return -1;
	}

	return ast_sendto(rtcp ? rtp->rtcp->s : rtp->s, temp, len, flags, sa);
}

static int rtcp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_sendto(instance, buf, size, flags, sa, 1);
}

static int rtp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_sendto(instance, buf, size, flags, sa, 0);
}

static int rtp_get_rate(format_t subclass)
{
	return (subclass == AST_FORMAT_G722) ? 8000 : ast_format_rate(subclass);
}

static unsigned int ast_rtcp_calc_interval(struct ast_rtp *rtp)
{
	unsigned int interval;
	/*! \todo XXX Do a more reasonable calculation on this one
	 * Look in RFC 3550 Section A.7 for an example*/
	interval = rtcpinterval;
	return interval;
}

/*! \brief Schedule RTCP transmissions for RTP channel */
static void ast_rtcp_schedule(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Do not schedule RR if RTCP isn't run */
	if (rtp->rtcp && !ast_sockaddr_isnull(&rtp->rtcp->them)  && rtp->rtcp->schedid < 1) {
		/* Schedule transmission of Receiver Report */
		ast_rtcp_write_empty(instance);
		ao2_ref(instance, +1);
		rtp->rtcp->schedid = ast_sched_add(rtp->sched, ast_rtcp_calc_interval(rtp), ast_rtcp_write, instance);
		if (rtp->rtcp->schedid < 0) {
			ao2_ref(instance, -1);
			ast_log(LOG_WARNING, "scheduling RTCP transmission failed.\n");
		}
	}
}

/*! \brief Calculate normal deviation */
static double normdev_compute(double normdev, double sample, unsigned int sample_count)
{
	normdev = normdev * sample_count + sample;
	sample_count++;

	return normdev / sample_count;
}

static double stddev_compute(double stddev, double sample, double normdev, double normdev_curent, unsigned int sample_count)
{
/*
		for the formula check http://www.cs.umd.edu/~austinjp/constSD.pdf
		return sqrt( (sample_count*pow(stddev,2) + sample_count*pow((sample-normdev)/(sample_count+1),2) + pow(sample-normdev_curent,2)) / (sample_count+1));
		we can compute the sigma^2 and that way we would have to do the sqrt only 1 time at the end and would save another pow 2 compute
		optimized formula
*/
#define SQUARE(x) ((x) * (x))

	stddev = sample_count * stddev;
	sample_count++;

	return stddev +
		( sample_count * SQUARE( (sample - normdev) / sample_count ) ) +
		( SQUARE(sample - normdev_curent) / sample_count );

#undef SQUARE
}

static int create_new_socket(const char *type, int af)
{
	int sock = socket(af, SOCK_DGRAM, 0);

	if (sock < 0) {
		if (!type) {
			type = "RTP/RTCP";
		}
		ast_log(LOG_WARNING, "Unable to allocate %s socket: %s\n", type, strerror(errno));
	} else {
		long flags = fcntl(sock, F_GETFL);
		fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#ifdef SO_NO_CHECK
		if (nochecksums) {
			setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &nochecksums, sizeof(nochecksums));
		}
#endif
	}

	return sock;
}

/*!
 * \internal
 * \brief Initializes sequence values and probation for learning mode.
 * \note This is an adaptation of pjmedia's pjmedia_rtp_seq_init function.
 *
 * \param rtp pointer to rtp struct used with the received rtp packet.
 * \param seq sequence number read from the rtp header
 */
static void rtp_learning_seq_init(struct ast_rtp *rtp, uint16_t seq)
{
	rtp->learning_max_seq = seq - 1;
	rtp->learning_probation = learning_min_sequential;
}

/*!
 * \internal
 * \brief Updates sequence information for learning mode and determines if probation/learning mode should remain in effect.
 * \note This function was adapted from pjmedia's pjmedia_rtp_seq_update function.
 *
 * \param rtp pointer to rtp struct used with the received rtp packet.
 * \param seq sequence number read from the rtp header
 * \return boolean value indicating if probation mode is active at the end of the function
 */
static int rtp_learning_rtp_seq_update(struct ast_rtp *rtp, uint16_t seq)
{
	int probation = 1;

	ast_debug(1, "%p -- probation = %d, seq = %d\n", rtp, rtp->learning_probation, seq);

	if (seq == rtp->learning_max_seq + 1) {
		/* packet is in sequence */
		rtp->learning_probation--;
		rtp->learning_max_seq = seq;
		if (rtp->learning_probation == 0) {
			probation = 0;
		}
	} else {
		rtp->learning_probation = learning_min_sequential - 1;
		rtp->learning_max_seq = seq;
	}

	return probation;
}

static int ast_rtp_new(struct ast_rtp_instance *instance,
		       struct sched_context *sched, struct ast_sockaddr *addr,
		       void *data)
{
	struct ast_rtp *rtp = NULL;
	int x, startplace;

	/* Create a new RTP structure to hold all of our data */
	if (!(rtp = ast_calloc(1, sizeof(*rtp)))) {
		return -1;
	}

	/* Set default parameters on the newly created RTP structure */
	rtp->ssrc = ast_random();
	rtp->seqno = ast_random() & 0xffff;
	rtp->strict_rtp_state = (strictrtp ? STRICT_RTP_LEARN : STRICT_RTP_OPEN);
	if (strictrtp) {
		rtp_learning_seq_init(rtp, (uint16_t)rtp->seqno);
	}

	/* Create a new socket for us to listen on and use */
	if ((rtp->s =
	     create_new_socket("RTP",
			       ast_sockaddr_is_ipv4(addr) ? AF_INET  :
			       ast_sockaddr_is_ipv6(addr) ? AF_INET6 : -1)) < 0) {
		ast_debug(1, "Failed to create a new socket for RTP instance '%p'\n", instance);
		ast_free(rtp);
		return -1;
	}

	/* Now actually find a free RTP port to use */
	x = (rtpend == rtpstart) ? rtpstart : (ast_random() % (rtpend - rtpstart)) + rtpstart;
	x = x & ~1;
	startplace = x;

	for (;;) {
		ast_sockaddr_set_port(addr, x);
		/* Try to bind, this will tell us whether the port is available or not */
		if (!ast_bind(rtp->s, addr)) {
			ast_debug(1, "Allocated port %d for RTP instance '%p'\n", x, instance);
			ast_rtp_instance_set_local_address(instance, addr);
			break;
		}

		x += 2;
		if (x > rtpend) {
			x = (rtpstart + 1) & ~1;
		}

		/* See if we ran out of ports or if the bind actually failed because of something other than the address being in use */
		if (x == startplace || errno != EADDRINUSE) {
			ast_log(LOG_ERROR, "Oh dear... we couldn't allocate a port for RTP instance '%p'\n", instance);
			return -1;
		}
	}

	/* Record any information we may need */
	rtp->sched = sched;

	/* Associate the RTP structure with the RTP instance and be done */
	ast_rtp_instance_set_data(instance, rtp);

	gettimeofday(&rtp->start, NULL);
	rtp->isactive = 1;

	return 0;
}

static int ast_rtp_destroy(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_frame *f;

	/* Destroy the smoother that was smoothing out audio if present */
	if (rtp->smoother) {
		ast_smoother_free(rtp->smoother);
	}

	/* Close our own socket so we no longer get packets */
	if (rtp->s > -1) {
		close(rtp->s);
	}

	/* Destroy RTCP if it was being used */
	if (rtp->rtcp) {
		/*
		 * It is not possible for there to be an active RTCP scheduler
		 * entry at this point since it holds a reference to the
		 * RTP instance while it's active.
		 */
		close(rtp->rtcp->s);
		ast_free(rtp->rtcp);
	}

	/* Destroy RED if it was being used */
	if (rtp->red) {
		AST_SCHED_DEL(rtp->sched, rtp->red->schedid);
		ast_free(rtp->red);
	}

	/* Empty the DTMF queue */
	while ((f = AST_LIST_REMOVE_HEAD(&rtp->dtmfqueue, frame_list))) {
		ast_frfree(f);
	}

	/* Finally destroy ourselves */
	ast_free(rtp);

	return 0;
}

static int ast_rtp_dtmf_mode_set(struct ast_rtp_instance *instance, enum ast_rtp_dtmf_mode dtmf_mode)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	rtp->dtmfmode = dtmf_mode;
	return 0;
}

static int dtmf_char_to_code(char digit)
{
	/* Convert the given digit to the one we are going to send */
	if (digit == '*') {
		return 10;
	} 
	if (digit == '#') {
		return 11;
	}
	if ((digit >= 'A') && (digit <= 'D')) {
		return digit - 'A' + 12;
	} 
	if ((digit >= 'a') && (digit <= 'd')) {
		return digit - 'a' + 12;
	}
	if ((digit <= '9') && (digit >= '0')) {
		return digit - '0';
	}
	return -1;
}

static enum ast_rtp_dtmf_mode ast_rtp_dtmf_mode_get(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->dtmfmode;
}

static int ast_rtp_dtmf_begin(struct ast_rtp_instance *instance, char digit)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0, i = 0, payload = 101;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;
	int dtmfcode;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we have no remote address information bail out now */
	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	/* If we're sending DTMF already, we will ignore this but raise sending_dtmf with one
	   to mark that we're busy and can't be disturbed. When we receive an END packet, we will
	   act on that - either start playing with some delay or stack it up in a dtmfqueue.
	*/
	if (rtp->sending_dtmf) {
		ast_debug(3, "Received DTMF begin while we're playing out DTMF. Ignoring \n");
		rtp->sending_dtmf = DTMF_SEND_INPROGRESS_WITH_QUEUE;	/* Tell the world that there's an ignored DTMF */
	//	AST_LIST_INSERT_TAIL(&frames, f, frame_list);
/* OEJ Fix ??? */
	}

	dtmfcode = dtmf_char_to_code(digit);
	if (dtmfcode < 0 ) {
		ast_log(LOG_WARNING, "Don't know how to represent '%c'\n", digit);
		return -1;
	}

	/* Grab the payload that they expect the RFC2833 packet to be received in */
	payload = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance), 0, AST_RTP_DTMF);

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, DEFAULT_DTMF_GAP));
	rtp->send_duration = 160;               /* XXX This assumes 20 ms packetization */
	rtp->received_duration = 160;
	rtp->lastdigitts = rtp->lastts + rtp->send_duration;

	/* Create the actual packet that we will be sending */
	rtpheader[0] = htonl((2 << 30) | (1 << 23) | (payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);

	/* Actually send the packet */
	for (i = 0; i < 2; i++) {
		rtpheader[3] = htonl((dtmfcode << 24) | (0xa << 16) | (rtp->send_duration));
		res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address);
		if (res < 0) {
			ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		}
		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP DTMF packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				    ast_sockaddr_stringify(&remote_address),
				    payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
		}
		rtp->seqno++;
		//rtp->send_duration += 160;	/* OEJ - check what's going on here. */
		
		rtpheader[0] = htonl((2 << 30) | (payload << 16) | (rtp->seqno));
	}

	/* Since we received a begin, we can safely store the digit and disable any compensation */
	rtp->sending_dtmf = DTMF_SEND_INIT;
	rtp->send_digit = digit;
	rtp->send_payload = payload;

	ast_debug(4, "DEBUG DTMF BEGIN - Digit %d send-digit %d\n", dtmfcode, dtmfcode);

	return 0;
}

/*! \brief Get notification of duration updates */
static int ast_rtp_dtmf_continue(struct ast_rtp_instance *instance, char digit, unsigned int duration)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ast_debug(4, "DTMF CONTINUE - Duration %d Digit %d Send-digit %d\n", duration, digit, dtmf_char_to_code(rtp->send_digit));

	/* If we missed the BEGIN, we will have to turn on the flag */
	if (!rtp->sending_dtmf) {
		rtp->sending_dtmf = DTMF_SEND_INPROGRESS;
	}

	/* Duration is in ms. Calculate the duration in timestamps */
	if (duration > 0) {
		/* We have an incoming duration from the incoming channel. This needs
		   to be matched with our outbound pacing. The inbound can be paced
		   in either 50 ms or whatever packetization that is used on that channel,
		   so we can't assume 20 ms (160 units in 8000 hz audio).
		*/
		int dursamples = duration * rtp_get_rate(rtp->f.subclass.codec) / 1000;

		/* How do we get the sample rate for the primary media in this call? */

		ast_debug(4, "DTMF CONTINUE : %d ms %d samples\n", duration, dursamples);
		rtp->received_duration = dursamples;
	} else {
		ast_debug(4, "DTMF CONTINUE : Missing duration!!!!!!!\n");
		
	}
	return 0;
}

/*! \brief Send continuation frame for DTMF 

This is called when we get a frame in ast_rtp_read. To keep the timing, because there may be delays through Asterisk
feature handling and other code, we need to clock the outbound DTMF with the frame size we have on the stream.
We should not cut short and send a begin then in the next packet an END with a duration that exceeds the
framesize (in most cases for audio 20 ms) and number of frames. That will seriously cause issues in gateways
or phones down the path.

An effect of this is that we may get a new DTMF frame while we're transmitting the previous one. For this case,
we have implemented an DTMF queue that will queue up the dtmf and play out. The alternative would be to skip
these, which is no good, or cut them short and cause issues with timing for other devices, while we solve our
own situation. That's generally considered bad behaviour amongst SIP devices.
*/
static int ast_rtp_dtmf_cont(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Make sure we know where the other side is so we can send them the packet */
	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}


	/*! \todo XXX This code assumes 160 samples, which is for 20 ms of 8000 samples
		we need to calculate this based on the current sample rate and the rtp 
		stream packetization. Please help me figure this out :-)
	 */
	/* OEJ disabled this. RFC 4733 actually allows us to send without regards to packetization */
	if (!rtp->send_endflag && rtp->send_duration + 160 > rtp->received_duration) {
	 	ast_debug(4, "---- Digit %d Send duration %d Received duration %d - Sending DTMF keep-alive frame\n", rtp->send_digit, rtp->send_duration, rtp->received_duration);
		/* We haven't got 160 samples, but let's catch up anyway */
		if (rtp->received_duration > rtp->send_duration) {
			rtp->send_duration = rtp->received_duration;
		}
	}
	if (rtp->received_duration == 0 || rtp->send_duration + 160 < rtp->received_duration) {
		/* Do we need to catch up? */
		ast_debug(3, "---- Adding 160 samples before sending : (previous values) Send duration %d Received duration %d\n", rtp->send_duration, rtp->received_duration);
		rtp->send_duration += 160;
	} 
	if (rtp->send_endflag) {
		if (rtp->send_duration + 160 >= rtp->received_duration) {
			int durms =  ast_tvdiff_ms(ast_samp2tv(rtp->received_duration, rtp_get_rate(rtp->f.subclass.codec)), ast_tv(0, 0));
			ast_debug(4, "---- Send duration %d (samples) Received duration %d (samples) - sending END packet\n", rtp->send_duration, rtp->received_duration);
			/* We are done, ready to send end flag */
			rtp->send_endflag = 0;
			return ast_rtp_dtmf_end_with_duration(instance, rtp->send_digit, durms);
		} else {
			ast_debug(4, "---- Send duration %d samples, Received duration %d samples, - delaying END packet (not ready for it yet)\n", rtp->send_duration, rtp->received_duration);
		}
	}
	ast_debug(4, "---- Send duration %d Received duration %d Endflag %d Send-digit %d\n", rtp->send_duration, rtp->received_duration, rtp->send_endflag, rtp->send_digit);
	/* Actually create the packet we will be sending */
	rtpheader[0] = htonl((2 << 30) | (rtp->send_payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);
	rtpheader[3] = htonl((dtmf_char_to_code(rtp->send_digit) << 24) | (0xa << 16) | (rtp->send_duration));

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, DEFAULT_DTMF_GAP));		/* Reset DTMF mute */

	/* Boom, send it on out */
	res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
			ast_sockaddr_stringify(&remote_address),
			strerror(errno));
	}

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent RTP DTMF packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
			    ast_sockaddr_stringify(&remote_address),
			    rtp->send_payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
	}

	/* And now we increment some values for the next time we swing by */
	rtp->seqno++;
	rtp->send_duration += 160;

	return 0;
}

static int ast_rtp_dtmf_end_with_duration(struct ast_rtp_instance *instance, char digit, unsigned int duration)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0, i = 0;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;
	int dtmfcode;
	unsigned int dursamples;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Make sure we know where the remote side is so we can send them the packet we construct */
	if (ast_sockaddr_isnull(&remote_address)) {
		goto cleanup;
	}
	dursamples = duration * rtp_get_rate(rtp->f.subclass.codec) / 1000;

	ast_debug(3, "---- Send duration %d samples, Received duration %d samples, Duration %d ms, Endflag %d Digit %d Send-digit %d\n", rtp->send_duration, rtp->received_duration, duration, rtp->send_endflag, digit, dtmf_char_to_code(rtp->send_digit));

	/* If the duration we received is way larger than our send_duration, then use the duration received */
	if (duration > 0 && dursamples > rtp->send_duration) {
		ast_debug(2, "Adjusting final end duration from %d samples to %u samples\n", rtp->send_duration, dursamples);
		rtp->received_duration = dursamples;
	}

	if (!rtp->send_endflag && rtp->send_duration + 160 < rtp->received_duration) {
		/* We still have to send DTMF continuation, because otherwise we will end prematurely. Set end flag to indicate
		   that we will have to end ourselves when we're done with the actual duration
		 */
		ast_debug(4, "---- Send duration %d Received duration %d - Avoiding sending END packet\n", rtp->send_duration, rtp->received_duration);
		rtp->send_endflag = 1;
		return ast_rtp_dtmf_cont(instance);
	}

	dtmfcode = dtmf_char_to_code(digit);
	if (dtmfcode < 0 ) {
		ast_log(LOG_WARNING, "Don't know how to represent '%c'\n", digit);
		return -1;
	}

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, DEFAULT_DTMF_GAP));

	/* Construct the packet we are going to send */
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);
	rtpheader[3] = htonl((dtmfcode << 24) | (0xa << 16) | (rtp->received_duration));
	rtpheader[3] |= htonl((1 << 23));

	/* Send it 3 times, that's the magical number */
	for (i = 0; i < 3; i++) {
		rtpheader[0] = htonl((2 << 30) | (rtp->send_payload << 16) | (rtp->seqno));
		res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address);
		if (res < 0) {
			ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		}
		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP DTMF packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				    ast_sockaddr_stringify(&remote_address),
				    rtp->send_payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
		}
		rtp->seqno++;
	}

	/* Oh and we can't forget to turn off the stuff that says we are sending DTMF */
	//rtp->lastts += rtp->send_duration//;

	rtp->lastts += calc_txstamp(rtp, NULL) * DTMF_SAMPLE_RATE_MS;
cleanup:
	rtp->sending_dtmf = DTMF_NOT_SENDING;
	rtp->send_digit = 0;

	return 0;
}

static int ast_rtp_dtmf_end(struct ast_rtp_instance *instance, char digit)
{
	return ast_rtp_dtmf_end_with_duration(instance, digit, 0);
}

static void ast_rtp_update_source(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* We simply set this bit so that the next packet sent will have the marker bit turned on */
	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);
	ast_debug(3, "Setting the marker bit due to a source update\n");

	return;
}

static void ast_rtp_change_source(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance);
	unsigned int ssrc = ast_random();

	if (!rtp->lastts) {
		ast_debug(3, "Not changing SSRC since we haven't sent any RTP yet\n");
		return;
	}

	/* We simply set this bit so that the next packet sent will have the marker bit turned on */
	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);

	ast_debug(3, "Changing ssrc from %u to %u due to a source change\n", rtp->ssrc, ssrc);

	if (srtp) {
		ast_debug(3, "Changing ssrc for SRTP from %u to %u\n", rtp->ssrc, ssrc);
		res_srtp->change_source(srtp, rtp->ssrc, ssrc);
	}

	rtp->ssrc = ssrc;

	return;
}

static unsigned int calc_txstamp(struct ast_rtp *rtp, struct timeval *delivery)
{
	struct timeval t;
	long ms;

	if (ast_tvzero(rtp->txcore)) {
		rtp->txcore = ast_tvnow();
		rtp->txcore.tv_usec -= rtp->txcore.tv_usec % 20000;
	}

	t = (delivery && !ast_tvzero(*delivery)) ? *delivery : ast_tvnow();
	if ((ms = ast_tvdiff_ms(t, rtp->txcore)) < 0) {
		ms = 0;
	}
	rtp->txcore = t;

	return (unsigned int) ms;
}

static void timeval2ntp(struct timeval tv, unsigned int *msw, unsigned int *lsw)
{
	unsigned int sec, usec, frac;
	sec = tv.tv_sec + 2208988800u; /* Sec between 1900 and 1970 */
	usec = tv.tv_usec;
	frac = (usec << 12) + (usec << 8) - ((usec * 3650) >> 6);
	*msw = sec;
	*lsw = frac;
}

/*! \brief Send RTCP recipient's report */
static int ast_rtcp_write_rr(struct ast_rtp_instance *instance, int goodbye)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;
	int len = 32;
	unsigned int lost;
	unsigned int extended;
	unsigned int expected;
	unsigned int expected_interval;
	unsigned int received_interval;
	int lost_interval;
	struct timeval now;
	unsigned int *rtcpheader, *start;
	char bdata[1024];
	struct timeval dlsr;
	int fraction;
	int rate = rtp_get_rate(rtp->f.subclass.codec);

	double rxlost_current;

	if (!rtp || !rtp->rtcp)
		return 0;

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) {
		/*
		 * RTCP was stopped.
		 */
		return 0;
	}

	extended = rtp->cycles + rtp->lastrxseqno;
	expected = extended - rtp->seedrxseqno + 1;
	lost = expected - rtp->rxcount;
	expected_interval = expected - rtp->rtcp->expected_prior;
	rtp->rtcp->expected_prior = expected;
	received_interval = rtp->rxcount - rtp->rtcp->received_prior;
	rtp->rtcp->received_prior = rtp->rxcount;
	lost_interval = expected_interval - received_interval;

	if (lost_interval <= 0)
		rtp->rtcp->rxlost = 0;
	else rtp->rtcp->rxlost = rtp->rtcp->rxlost;
	if (rtp->rtcp->rxlost_count == 0)
		rtp->rtcp->minrxlost = rtp->rtcp->rxlost;
	if (lost_interval < rtp->rtcp->minrxlost)
		rtp->rtcp->minrxlost = rtp->rtcp->rxlost;
	if (lost_interval > rtp->rtcp->maxrxlost)
		rtp->rtcp->maxrxlost = rtp->rtcp->rxlost;

	rxlost_current = normdev_compute(rtp->rtcp->normdev_rxlost, rtp->rtcp->rxlost, rtp->rtcp->rxlost_count);
	rtp->rtcp->stdev_rxlost = stddev_compute(rtp->rtcp->stdev_rxlost, rtp->rtcp->rxlost, rtp->rtcp->normdev_rxlost, rxlost_current, rtp->rtcp->rxlost_count);
	rtp->rtcp->normdev_rxlost = rxlost_current;
	rtp->rtcp->rxlost_count++;

	if (expected_interval == 0 || lost_interval <= 0)
		fraction = 0;
	else
		fraction = (lost_interval << 8) / expected_interval;
	gettimeofday(&now, NULL);
	timersub(&now, &rtp->rtcp->rxlsr, &dlsr);
	rtcpheader = (unsigned int *) bdata;
	rtcpheader[0] = htonl((2 << 30) | (1 << 24) | (RTCP_PT_RR << 16) | ((len/4)-1));
	rtcpheader[1] = htonl(rtp->ssrc);
	rtcpheader[2] = htonl(rtp->themssrc);
	rtcpheader[3] = htonl(((fraction & 0xff) << 24) | (lost & 0xffffff));
	rtcpheader[4] = htonl((rtp->cycles) | ((rtp->lastrxseqno & 0xffff)));
	rtcpheader[5] = htonl((unsigned int)(rtp->rxjitter * rate));
	rtcpheader[6] = htonl(rtp->rtcp->themrxlsr);
	rtcpheader[7] = htonl((((dlsr.tv_sec * 1000) + (dlsr.tv_usec / 1000)) * 65536) / 1000);


	start = &rtcpheader[len/4];
	len +=8; /* SKip header for now */
	len = add_sdes_bodypart(rtp, &rtcpheader[len/4], len, SDES_CNAME);
	len = add_sdes_bodypart(rtp, &rtcpheader[len/4], len, SDES_END);
	/* Now, add header when we know the actual length */
	add_sdes_header(rtp, start, len);
	res = rtcp_sendto(instance, (unsigned int *)rtcpheader, len, 0, &rtp->rtcp->them);

	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP RR transmission error, rtcp halted: %s\n",strerror(errno));
		return 0;
	}

	rtp->rtcp->rr_count++;
	if (rtcp_debug_test_addr(&rtp->rtcp->them)) {
		ast_verbose("\n* Sending RTCP RR to %s\n"
			"  Our SSRC: %u\nTheir SSRC: %u\niFraction lost: %d\nCumulative loss: %u\n"
			"  IA jitter: %.4f\n"
			"  Their last SR: %u\n"
			    "  DLSR: %4.4f (sec)\n\n",
			    ast_sockaddr_stringify(&rtp->rtcp->them),
			    rtp->ssrc, rtp->themssrc, fraction, lost,
			    rtp->rxjitter,
			    rtp->rtcp->themrxlsr,
			    (double)(ntohl(rtcpheader[7])/65536.0));
	}

	return res;
}

/*! \brief Send RTCP sender's report */
static int ast_rtcp_write_sr(struct ast_rtp_instance *instance, int goodbye)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;
	int len = 0;	/* Measured in chunks of four bytes */
	int srlen = 0;
	struct timeval now;
	unsigned int now_lsw;
	unsigned int now_msw;
	unsigned int *rtcpheader, *start;
	unsigned int lost;
	unsigned int extended;
	unsigned int expected;
	unsigned int expected_interval;
	unsigned int received_interval;
	int lost_interval;
	int fraction;
	struct timeval dlsr;
	char bdata[512];
	int rate = rtp_get_rate(rtp->f.subclass.codec);

	if (!rtp || !rtp->rtcp)
		return 0;

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) {  /* This'll stop rtcp for this rtp session */
		/*
		 * RTCP was stopped.
		 */
		return 0;
	}

	gettimeofday(&now, NULL);
	timeval2ntp(now, &now_msw, &now_lsw); /* fill these ones in from utils.c*/
	/* Set the header for sender's report */
	rtcpheader = (unsigned int *)bdata;
	rtcpheader[1] = htonl(rtp->ssrc);               /* Our SSRC */
	rtcpheader[2] = htonl(now_msw);                 /* now, MSW. gettimeofday() + SEC_BETWEEN_1900_AND_1970*/
	rtcpheader[3] = htonl(now_lsw);                 /* now, LSW */
	rtcpheader[4] = htonl(rtp->lastts);             /* FIXME shouldn't be that, it should be now */
	rtcpheader[5] = htonl(rtp->txcount);            /* No. packets sent */
	rtcpheader[6] = htonl(rtp->txoctetcount);       /* No. bytes sent */
	len += 28;

	extended = rtp->cycles + rtp->lastrxseqno;
	expected = extended - rtp->seedrxseqno + 1;
	if (rtp->rxcount > expected)
		expected += rtp->rxcount - expected;
	lost = expected - rtp->rxcount;
	expected_interval = expected - rtp->rtcp->expected_prior;
	rtp->rtcp->expected_prior = expected;
	received_interval = rtp->rxcount - rtp->rtcp->received_prior;
	rtp->rtcp->received_prior = rtp->rxcount;
	lost_interval = expected_interval - received_interval;
	if (expected_interval == 0 || lost_interval <= 0)
		fraction = 0;
	else
		fraction = (lost_interval << 8) / expected_interval;
	timersub(&now, &rtp->rtcp->rxlsr, &dlsr);
	rtcpheader[7] = htonl(rtp->themssrc);
	rtcpheader[8] = htonl(((fraction & 0xff) << 24) | (lost & 0xffffff));
	rtcpheader[9] = htonl((rtp->cycles) | ((rtp->lastrxseqno & 0xffff)));
	rtcpheader[10] = htonl((unsigned int)(rtp->rxjitter * rate));
	rtcpheader[11] = htonl(rtp->rtcp->themrxlsr);
	rtcpheader[12] = htonl((((dlsr.tv_sec * 1000) + (dlsr.tv_usec / 1000)) * 65536) / 1000);
	len += 24;

	rtcpheader[0] = htonl((2 << 30) | (1 << 24) | (RTCP_PT_SR << 16) | ((len/4)-1));

	start = &rtcpheader[len/4];
	srlen = len;
	len +=8; /* SKip header for now */
	len = add_sdes_bodypart(rtp, &rtcpheader[len/4], len, SDES_CNAME);
	len = add_sdes_bodypart(rtp, &rtcpheader[len/4], len, SDES_END);
	/* Now, add header when we know the actual length */
	add_sdes_header(rtp, start, len - srlen);

	if (goodbye) {
		/* An additional RTCP block */
		rtcpheader[len/4] = htonl((2 << 30) | (1 << 24) | (RTCP_PT_BYE << 16) | 1);
		len += 4;
		rtcpheader[len/4] = htonl(rtp->ssrc);               /* Our SSRC */
		len += 4;
	}

	res = rtcp_sendto(instance, (unsigned int *)rtcpheader, len, 0, &rtp->rtcp->them);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP SR transmission error to %s, rtcp halted %s\n",
			ast_sockaddr_stringify(&rtp->rtcp->them),
			strerror(errno));
		return 0;
	}

	/* FIXME Don't need to get a new one */
	gettimeofday(&rtp->rtcp->txlsr, NULL);
	rtp->rtcp->sr_count++;

	rtp->rtcp->lastsrtxcount = rtp->txcount;

	if (rtcp_debug_test_addr(&rtp->rtcp->them)) {
		ast_verbose("* Sent RTCP SR to %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
		ast_verbose("  Our SSRC: %u\n", rtp->ssrc);
		ast_verbose("  Sent(NTP): %u.%010u\n", (unsigned int)now.tv_sec, (unsigned int)now.tv_usec*4096);
		ast_verbose("  Sent(RTP): %u\n", rtp->lastts);
		ast_verbose("  Sent packets: %u\n", rtp->txcount);
		ast_verbose("  Sent octets: %u\n", rtp->txoctetcount);
		ast_verbose("  Report block:\n");
		ast_verbose("    Fraction lost (since last report): %u\n", fraction);
		ast_verbose("    Cumulative loss: %u\n", lost);
		ast_verbose("    IA jitter: %.4f\n", rtp->rxjitter);
		ast_verbose("    Their last SR: %u\n", rtp->rtcp->themrxlsr);
		ast_verbose("    Delay since last SR (DLSR): %4.4f (sec)\n\n", (double)(ntohl(rtcpheader[12])/65536.0));
	}
	manager_event(EVENT_FLAG_REPORTING, "RTCPSent", "To: %s\r\n"
					    "OurSSRC: %u\r\n"
					    "SentNTP: %u.%010u\r\n"
					    "SentRTP: %u\r\n"
					    "SentPackets: %u\r\n"
					    "SentOctets: %u\r\n"
					    "ReportBlock:\r\n"
					    "FractionLost: %u\r\n"
					    "CumulativeLoss: %u\r\n"
					    "IAJitter: %.4f\r\n"
					    "TheirLastSR: %u\r\n"
		      "DLSR: %4.4f (sec)\r\n",
		      ast_sockaddr_stringify(&rtp->rtcp->them),
		      rtp->ssrc,
		      (unsigned int)now.tv_sec, (unsigned int)now.tv_usec*4096,
		      rtp->lastts,
		      rtp->txcount,
		      rtp->txoctetcount,
		      fraction,
		      lost,
		      rtp->rxjitter,
		      rtp->rtcp->themrxlsr,
		      (double)(ntohl(rtcpheader[12])/65536.0));
	return res;
}

/*! \brief Write and RTCP packet to the far end
 * \note Decide if we are going to send an SR (with Reception Block) or RR
 * RR is sent if we have not sent any rtp packets in the previous interval */
static int ast_rtcp_write(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance *) data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;

	if (!rtp || !rtp->rtcp || rtp->rtcp->schedid == -1) {
		ao2_ref(instance, -1);
		return 0;
	}

	if (rtp->txcount > rtp->rtcp->lastsrtxcount) {
		res = ast_rtcp_write_sr(instance, 0);
	} else {
		res = ast_rtcp_write_rr(instance, 0);
	}

	if (!res) {
		/* 
		 * Not being rescheduled.
		 */
		ao2_ref(instance, -1);
		rtp->rtcp->schedid = -1;
	}

	return res;
}

static int ast_rtp_raw_write(struct ast_rtp_instance *instance, struct ast_frame *frame, int codec)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int pred, mark = 0;
	unsigned int ms = calc_txstamp(rtp, &frame->delivery);
	struct ast_sockaddr remote_address = { {0,} };
	int rate = rtp_get_rate(frame->subclass.codec) / 1000;

	if (frame->subclass.codec == AST_FORMAT_G722) {
		frame->samples /= 2;
	}

	if (rtp->sending_dtmf) {
		return 0;
	}

	if (frame->frametype == AST_FRAME_VOICE) {
		pred = rtp->lastts + frame->samples;

		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms * rate;
		if (ast_tvzero(frame->delivery)) {
			/* If this isn't an absolute delivery time, Check if it is close to our prediction,
			   and if so, go with our prediction */
			if (abs(rtp->lastts - pred) < MAX_TIMESTAMP_SKEW) {
				rtp->lastts = pred;
			} else {
				ast_debug(3, "Difference is %d, ms is %d\n", abs(rtp->lastts - pred), ms);
				mark = 1;
			}
		}
	} else if (frame->frametype == AST_FRAME_VIDEO) {
		mark = frame->subclass.codec & 0x1;
		pred = rtp->lastovidtimestamp + frame->samples;
		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms * 90;
		/* If it's close to our prediction, go for it */
		if (ast_tvzero(frame->delivery)) {
			if (abs(rtp->lastts - pred) < 7200) {
				rtp->lastts = pred;
				rtp->lastovidtimestamp += frame->samples;
			} else {
				ast_debug(3, "Difference is %d, ms is %d (%d), pred/ts/samples %d/%d/%d\n", abs(rtp->lastts - pred), ms, ms * 90, rtp->lastts, pred, frame->samples);
				rtp->lastovidtimestamp = rtp->lastts;
			}
		}
	} else {
		pred = rtp->lastotexttimestamp + frame->samples;
		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms;
		/* If it's close to our prediction, go for it */
		if (ast_tvzero(frame->delivery)) {
			if (abs(rtp->lastts - pred) < 7200) {
				rtp->lastts = pred;
				rtp->lastotexttimestamp += frame->samples;
			} else {
				ast_debug(3, "Difference is %d, ms is %d, pred/ts/samples %d/%d/%d\n", abs(rtp->lastts - pred), ms, rtp->lastts, pred, frame->samples);
				rtp->lastotexttimestamp = rtp->lastts;
			}
		}
	}

	/* If we have been explicitly told to set the marker bit then do so */
	if (ast_test_flag(rtp, FLAG_NEED_MARKER_BIT)) {
		mark = 1;
		ast_clear_flag(rtp, FLAG_NEED_MARKER_BIT);
	}

	/* If the timestamp for non-digt packets has moved beyond the timestamp for digits, update the digit timestamp */
	if (rtp->lastts > rtp->lastdigitts) {
		rtp->lastdigitts = rtp->lastts;
	}

	if (ast_test_flag(frame, AST_FRFLAG_HAS_TIMING_INFO)) {
		rtp->lastts = frame->ts * rate;
	}

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we know the remote address construct a packet and send it out */
	if (!ast_sockaddr_isnull(&remote_address)) {
		int hdrlen = 12, res;
		unsigned char *rtpheader = (unsigned char *)(frame->data.ptr - hdrlen);

		put_unaligned_uint32(rtpheader, htonl((2 << 30) | (codec << 16) | (rtp->seqno) | (mark << 23)));
		put_unaligned_uint32(rtpheader + 4, htonl(rtp->lastts));
		put_unaligned_uint32(rtpheader + 8, htonl(rtp->ssrc));

		if ((res = rtp_sendto(instance, (void *)rtpheader, frame->datalen + hdrlen, 0, &remote_address)) < 0) {
			if (!ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT) || (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT) && (ast_test_flag(rtp, FLAG_NAT_ACTIVE) == FLAG_NAT_ACTIVE))) {
				ast_debug(1, "RTP Transmission error of packet %d to %s: %s\n",
					  rtp->seqno,
					  ast_sockaddr_stringify(&remote_address),
					  strerror(errno));
			} else if (((ast_test_flag(rtp, FLAG_NAT_ACTIVE) == FLAG_NAT_INACTIVE) || rtpdebug) && !ast_test_flag(rtp, FLAG_NAT_INACTIVE_NOWARN)) {
				/* Only give this error message once if we are not RTP debugging */
				if (option_debug || rtpdebug)
					ast_debug(0, "RTP NAT: Can't write RTP to private address %s, waiting for other end to send audio...\n",
						  ast_sockaddr_stringify(&remote_address));
				ast_set_flag(rtp, FLAG_NAT_INACTIVE_NOWARN);
			}
		} else {
			rtp->txcount++;
			rtp->txoctetcount += (res - hdrlen);

			ast_rtcp_schedule(instance);
		}

		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP packet to      %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				    ast_sockaddr_stringify(&remote_address),
				    codec, rtp->seqno, rtp->lastts, res - hdrlen);
		}
	}

	rtp->seqno++;

	return 0;
}

static struct ast_frame *red_t140_to_red(struct rtp_red *red) {
	unsigned char *data = red->t140red.data.ptr;
	int len = 0;
	int i;

	/* replace most aged generation */
	if (red->len[0]) {
		for (i = 1; i < red->num_gen+1; i++)
			len += red->len[i];

		memmove(&data[red->hdrlen], &data[red->hdrlen+red->len[0]], len);
	}

	/* Store length of each generation and primary data length*/
	for (i = 0; i < red->num_gen; i++)
		red->len[i] = red->len[i+1];
	red->len[i] = red->t140.datalen;

	/* write each generation length in red header */
	len = red->hdrlen;
	for (i = 0; i < red->num_gen; i++)
		len += data[i*4+3] = red->len[i];

	/* add primary data to buffer */
	memcpy(&data[len], red->t140.data.ptr, red->t140.datalen);
	red->t140red.datalen = len + red->t140.datalen;

	/* no primary data and no generations to send */
	if (len == red->hdrlen && !red->t140.datalen)
		return NULL;

	/* reset t.140 buffer */
	red->t140.datalen = 0;

	return &red->t140red;
}

static int ast_rtp_write(struct ast_rtp_instance *instance, struct ast_frame *frame)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	format_t codec, subclass;

	if (ast_test_flag(rtp, FLAG_HOLD)) {
		/* This stream is on hold, just keep on happily and don't do anything */
		ast_debug(1, "** Frame muted since we're on hold. \n");
		return 0;
	}

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we don't actually know the remote address don't even bother doing anything */
	if (ast_sockaddr_isnull(&remote_address)) {
		ast_debug(1, "No remote address on RTP instance '%p' so dropping frame\n", instance);
		return 0;
	}

	/* If there is no data length we can't very well send the packet */
	if (!frame->datalen) {
		ast_debug(1, "Received frame with no data for RTP instance '%p' so dropping frame\n", instance);
		return 0;
	}

	/* If the packet is not one our RTP stack supports bail out */
	if (frame->frametype != AST_FRAME_VOICE && frame->frametype != AST_FRAME_VIDEO && frame->frametype != AST_FRAME_TEXT) {
		ast_log(LOG_WARNING, "RTP can only send voice, video, and text\n");
		return -1;
	}

	if (rtp->red) {
		/* return 0; */
		/* no primary data or generations to send */
		if ((frame = red_t140_to_red(rtp->red)) == NULL)
			return 0;
	}

	/* Grab the subclass and look up the payload we are going to use */
	subclass = frame->subclass.codec;
	if (frame->frametype == AST_FRAME_VIDEO) {
		subclass &= ~0x1LL;
	}
	if ((codec = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance), 1, subclass)) < 0) {
		ast_log(LOG_WARNING, "Don't know how to send format %s packets with RTP\n", ast_getformatname(frame->subclass.codec));
		return -1;
	}

	/* Oh dear, if the format changed we will have to set up a new smoother */
	if (rtp->lasttxformat != subclass) {
		ast_debug(1, "Ooh, format changed from %s to %s\n", ast_getformatname(rtp->lasttxformat), ast_getformatname(subclass));
		rtp->lasttxformat = subclass;
		if (rtp->smoother) {
			ast_smoother_free(rtp->smoother);
			rtp->smoother = NULL;
		}
	}

	/* If no smoother is present see if we have to set one up */
	if (!rtp->smoother) {
		struct ast_format_list fmt = ast_codec_pref_getsize(&ast_rtp_instance_get_codecs(instance)->pref, subclass);

		switch (subclass) {
		case AST_FORMAT_SPEEX:
		case AST_FORMAT_SPEEX16:
		case AST_FORMAT_G723_1:
		case AST_FORMAT_SIREN7:
		case AST_FORMAT_SIREN14:
		case AST_FORMAT_G719:
			/* these are all frame-based codecs and cannot be safely run through
			   a smoother */
			break;
		default:
			if (fmt.inc_ms) {
				if (!(rtp->smoother = ast_smoother_new((fmt.cur_ms * fmt.fr_len) / fmt.inc_ms))) {
					ast_log(LOG_WARNING, "Unable to create smoother: format %s ms: %d len: %d\n", ast_getformatname(subclass), fmt.cur_ms, ((fmt.cur_ms * fmt.fr_len) / fmt.inc_ms));
					return -1;
				}
				if (fmt.flags) {
					ast_smoother_set_flags(rtp->smoother, fmt.flags);
				}
				ast_debug(1, "Created smoother: format: %s ms: %d len: %d\n", ast_getformatname(subclass), fmt.cur_ms, ((fmt.cur_ms * fmt.fr_len) / fmt.inc_ms));
			}
		}
	}

	/* Feed audio frames into the actual function that will create a frame and send it */
	if (rtp->smoother) {
		struct ast_frame *f;

		if (ast_smoother_test_flag(rtp->smoother, AST_SMOOTHER_FLAG_BE)) {
			ast_smoother_feed_be(rtp->smoother, frame);
		} else {
			ast_smoother_feed(rtp->smoother, frame);
		}

		while ((f = ast_smoother_read(rtp->smoother)) && (f->data.ptr)) {
				ast_rtp_raw_write(instance, f, codec);
		}
	} else {
		int hdrlen = 12;
		struct ast_frame *f = NULL;

		if (frame->offset < hdrlen) {
			f = ast_frdup(frame);
		} else {
			f = frame;
		}
		if (f->data.ptr) {
			ast_rtp_raw_write(instance, f, codec);
		}
		if (f != frame) {
			ast_frfree(f);
		}

	}

	return 0;
}

static void calc_rxstamp(struct timeval *tv, struct ast_rtp *rtp, unsigned int timestamp, int mark)
{
	struct timeval now;
	struct timeval tmp;
	double transit;
	double current_time;
	double d;
	double dtv;
	double prog;
	int rate = rtp_get_rate(rtp->f.subclass.codec);

	double normdev_rxjitter_current;
	if ((!rtp->rxcore.tv_sec && !rtp->rxcore.tv_usec) || mark) {
		gettimeofday(&rtp->rxcore, NULL);
		rtp->drxcore = (double) rtp->rxcore.tv_sec + (double) rtp->rxcore.tv_usec / 1000000;
		/* map timestamp to a real time */
		rtp->seedrxts = timestamp; /* Their RTP timestamp started with this */
		tmp = ast_samp2tv(timestamp, rate);
		rtp->rxcore = ast_tvsub(rtp->rxcore, tmp);
		/* Round to 0.1ms for nice, pretty timestamps */
		rtp->rxcore.tv_usec -= rtp->rxcore.tv_usec % 100;
	}

	gettimeofday(&now,NULL);
	/* rxcore is the mapping between the RTP timestamp and _our_ real time from gettimeofday() */
	tmp = ast_samp2tv(timestamp, rate);
	*tv = ast_tvadd(rtp->rxcore, tmp);

	prog = (double)((timestamp-rtp->seedrxts)/(float)(rate));
	dtv = (double)rtp->drxcore + (double)(prog);
	current_time = (double)now.tv_sec + (double)now.tv_usec/1000000;
	transit = current_time - dtv;
	d = transit - rtp->rxtransit;
	rtp->rxtransit = transit;
	if (d<0)
		d=-d;
	rtp->rxjitter += (1./16.) * (d - rtp->rxjitter);

	if (!rtp->rtcp) {
		return;
	}
	if (rtp->rxjitter > rtp->rtcp->maxrxjitter)
		rtp->rtcp->maxrxjitter = rtp->rxjitter;
	if (rtp->rtcp->rxjitter_count == 1) {
		rtp->rtcp->minrxjitter = rtp->rxjitter;
	}
	if (rtp->rtcp && rtp->rxjitter < rtp->rtcp->minrxjitter) {
		rtp->rtcp->minrxjitter = rtp->rxjitter;
	}

	normdev_rxjitter_current = normdev_compute(rtp->rtcp->normdev_rxjitter,rtp->rxjitter,rtp->rtcp->rxjitter_count);
	rtp->rtcp->stdev_rxjitter = stddev_compute(rtp->rtcp->stdev_rxjitter,rtp->rxjitter,rtp->rtcp->normdev_rxjitter,normdev_rxjitter_current,rtp->rtcp->rxjitter_count);

	rtp->rtcp->normdev_rxjitter = normdev_rxjitter_current;
	rtp->rtcp->rxjitter_count++;
}

static struct ast_frame *create_dtmf_frame(struct ast_rtp_instance *instance, enum ast_frame_type type, int compensate)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Check if we have the right gap between DTMF tones. We need at least 45 ms in channel.c 
		I don't know how other channels will handle this. At some point after the mute ends, we will
		still send DTMF and being in the middle so the duration will not be affected, only the duration
		between DTMF tones. This will of course cause a delay somewhere in playing out DTMF.
	 */
	if (((compensate && type == AST_FRAME_DTMF_END) || (type == AST_FRAME_DTMF_BEGIN)) && ast_tvcmp(ast_tvnow(), rtp->dtmfmute) < 0) {
		ast_debug(1, "Ignore potential DTMF echo from '%s' TV Diff %d\n", ast_sockaddr_stringify(&remote_address), ast_tvcmp(ast_tvnow(), rtp->dtmfmute));
		rtp->resp = 0;
		rtp->dtmfsamples = 0;
		return &ast_null_frame;
	}
	ast_debug(1, "Sending dtmf: %d (%c), at %s\n", rtp->resp, rtp->resp,
		  ast_sockaddr_stringify(&remote_address));
	if (rtp->resp == 'X') {
		rtp->f.frametype = AST_FRAME_CONTROL;
		rtp->f.subclass.integer = AST_CONTROL_FLASH;
	} else {
		rtp->f.frametype = type;
		rtp->f.subclass.integer = rtp->resp;
	}
	rtp->f.datalen = 0;
	rtp->f.samples = 0;
	rtp->f.mallocd = 0;
	rtp->f.src = "RTP";
	AST_LIST_NEXT(&rtp->f, frame_list) = NULL;

	return &rtp->f;
}

static void process_dtmf_rfc2833(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, struct ast_sockaddr *addr, int payloadtype, int mark, struct frame_list *frames)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	unsigned int event, event_end, samples;
	char resp = 0;
	struct ast_frame *f = NULL;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Figure out event, event end, and samples */
	event = ntohl(*((unsigned int *)(data)));
	event >>= 24;
	event_end = ntohl(*((unsigned int *)(data)));
	event_end <<= 8;
	event_end >>= 24;
	samples = ntohl(*((unsigned int *)(data)));
	samples &= 0xFFFF;

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Got  RTP RFC2833 from   %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u, mark %d, event %08x, end %d, duration %-5.5d) \n",
			    ast_sockaddr_stringify(&remote_address),
			    payloadtype, seqno, timestamp, len, (mark?1:0), event, ((event_end & 0x80)?1:0), samples);
	}

	/* Print out debug if turned on */
	if (rtpdebug || option_debug > 2)
		ast_debug(0, "- RTP 2833 Event: %08x (len = %d)\n", event, len);

	/* Figure out what digit was pressed */
	if (event < 10) {
		resp = '0' + event;
	} else if (event < 11) {
		resp = '*';
	} else if (event < 12) {
		resp = '#';
	} else if (event < 16) {
		resp = 'A' + (event - 12);
	} else if (event < 17) {        /* Event 16: Hook flash */
		resp = 'X';
	} else {
		/* Not a supported event */
		ast_debug(4, "Ignoring RTP 2833 Event: %08x. Not a DTMF Digit.\n", event);
		return;
	}

	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)) {
		if ((rtp->lastevent != timestamp) || (rtp->resp && rtp->resp != resp)) {
			rtp->resp = resp;
			rtp->dtmf_timeout = 0;
			f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)));
			f->len = 0;
			rtp->lastevent = timestamp;
			AST_LIST_INSERT_TAIL(frames, f, frame_list);
		}
	} else {
		/*  The duration parameter measures the complete
		    duration of the event (from the beginning) - RFC2833.
		    Account for the fact that duration is only 16 bits long
		    (about 8 seconds at 8000 Hz) and can wrap is digit
		    is hold for too long. */
		unsigned int new_duration = rtp->dtmf_duration;
		unsigned int last_duration = new_duration & 0xFFFF;

		if (last_duration > 64000 && samples < last_duration) {
			new_duration += 0xFFFF + 1;
		}
		new_duration = (new_duration & ~0xFFFF) | samples;

		/* The second portion of this check is to not mistakenly
		 * stop accepting DTMF if the seqno rolls over beyond
		 * 65535.
		 */
		if (rtp->lastevent > seqno && rtp->lastevent - seqno < 50) {
			/* Out of order frame. Processing this can cause us to
			 * improperly duplicate incoming DTMF, so just drop
			 * this.
			 */
			return;
		}

		if (event_end & 0x80) {
			/* End event */
			if ((rtp->lastevent != seqno) && rtp->resp) {
				rtp->dtmf_duration = new_duration;
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0));
				f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.codec)), ast_tv(0, 0));
				if (f->len < option_dtmfminduration) {
					f->len = option_dtmfminduration;
					ast_debug(4, "--GOT DTMF END message. Duration samples %d (%ld ms - adjusted to min DTMF %d)\n", rtp->dtmf_duration, f->len, option_dtmfminduration);
				} else {
					ast_debug(4, "--GOT DTMF END message. Duration samples %d (%ld ms)\n", rtp->dtmf_duration, f->len);
				}
				rtp->resp = 0;
				rtp->dtmf_duration = rtp->dtmf_timeout = 0;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}
		} else {
			/* Begin/continuation */

			if (rtp->resp && rtp->resp != resp) {
				/* Another digit already began. End it */
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0));
				f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.codec)), ast_tv(0, 0));
				rtp->resp = 0;
				rtp->dtmf_duration = rtp->dtmf_timeout = 0;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}

			if (rtp->resp) {
				/* Digit continues */
				rtp->dtmf_duration = new_duration;
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_CONTINUE, 0));
				f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.codec)), ast_tv(0, 0));
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
				ast_debug(4, "Queued frame AST_FRAME_DTMF_CONTINUE, Samples %d Ms %d\n", rtp->dtmf_duration, (int)f->len);
			} else {
				/* New digit began */
				rtp->resp = resp;
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_BEGIN, 0));
				rtp->dtmf_duration = samples;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}

			rtp->dtmf_timeout = timestamp + rtp->dtmf_duration + dtmftimeout;
		}

		rtp->lastevent = seqno;
	}

	rtp->dtmfsamples = samples;

	return;
}

static struct ast_frame *process_dtmf_cisco(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, struct ast_sockaddr *addr, int payloadtype, int mark)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	unsigned int event, flags, power;
	char resp = 0;
	unsigned char seq;
	struct ast_frame *f = NULL;

	if (len < 4) {
		return NULL;
	}

	/*      The format of Cisco RTP DTMF packet looks like next:
		+0                              - sequence number of DTMF RTP packet (begins from 1,
						  wrapped to 0)
		+1                              - set of flags
		+1 (bit 0)              - flaps by different DTMF digits delimited by audio
						  or repeated digit without audio???
		+2 (+4,+6,...)  - power level? (rises from 0 to 32 at begin of tone
						  then falls to 0 at its end)
		+3 (+5,+7,...)  - detected DTMF digit (0..9,*,#,A-D,...)
		Repeated DTMF information (bytes 4/5, 6/7) is history shifted right
		by each new packet and thus provides some redudancy.

		Sample of Cisco RTP DTMF packet is (all data in hex):
			19 07 00 02 12 02 20 02
		showing end of DTMF digit '2'.

		The packets
			27 07 00 02 0A 02 20 02
			28 06 20 02 00 02 0A 02
		shows begin of new digit '2' with very short pause (20 ms) after
		previous digit '2'. Bit +1.0 flips at begin of new digit.

		Cisco RTP DTMF packets comes as replacement of audio RTP packets
		so its uses the same sequencing and timestamping rules as replaced
		audio packets. Repeat interval of DTMF packets is 20 ms and not rely
		on audio framing parameters. Marker bit isn't used within stream of
		DTMFs nor audio stream coming immediately after DTMF stream. Timestamps
		are not sequential at borders between DTMF and audio streams,
	*/

	seq = data[0];
	flags = data[1];
	power = data[2];
	event = data[3] & 0x1f;

	if (option_debug > 2 || rtpdebug)
		ast_debug(0, "Cisco DTMF Digit: %02x (len=%d, seq=%d, flags=%02x, power=%d, history count=%d)\n", event, len, seq, flags, power, (len - 4) / 2);
	if (event < 10) {
		resp = '0' + event;
	} else if (event < 11) {
		resp = '*';
	} else if (event < 12) {
		resp = '#';
	} else if (event < 16) {
		resp = 'A' + (event - 12);
	} else if (event < 17) {
		resp = 'X';
	}
	if ((!rtp->resp && power) || (rtp->resp && (rtp->resp != resp))) {
		rtp->resp = resp;
		/* Why we should care on DTMF compensation at reception? */
		if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)) {
			f = create_dtmf_frame(instance, AST_FRAME_DTMF_BEGIN, 0);
			rtp->dtmfsamples = 0;
		}
	} else if ((rtp->resp == resp) && !power) {
		f = create_dtmf_frame(instance, AST_FRAME_DTMF_END, ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE));
		f->samples = rtp->dtmfsamples * (rtp->lastrxformat ? (rtp_get_rate(rtp->lastrxformat) / 1000) : 8);
		rtp->resp = 0;
	} else if (rtp->resp == resp)
		rtp->dtmfsamples += 20 * (rtp->lastrxformat ? (rtp_get_rate(rtp->lastrxformat) / 1000) : 8);

	rtp->dtmf_timeout = 0;

	return f;
}

static struct ast_frame *process_cn_rfc3389(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, struct ast_sockaddr *addr, int payloadtype, int mark)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Convert comfort noise into audio with various codecs.  Unfortunately this doesn't
	   totally help us out becuase we don't have an engine to keep it going and we are not
	   guaranteed to have it every 20ms or anything */
	if (rtpdebug)
		ast_debug(0, "- RTP 3389 Comfort noise event: Level %" PRId64 " (len = %d)\n", rtp->lastrxformat, len);

	if (ast_test_flag(rtp, FLAG_3389_WARNING)) {
		struct ast_sockaddr remote_address = { {0,} };

		ast_rtp_instance_get_remote_address(instance, &remote_address);

		ast_log(LOG_NOTICE, "Comfort noise support incomplete in Asterisk (RFC 3389). Please turn off on client if possible. Client address: %s\n",
			ast_sockaddr_stringify(&remote_address));
		ast_set_flag(rtp, FLAG_3389_WARNING);
	}

	/* Must have at least one byte */
	if (!len)
		return NULL;
	if (len < 24) {
		rtp->f.data.ptr = rtp->rawdata + AST_FRIENDLY_OFFSET;
		rtp->f.datalen = len - 1;
		rtp->f.offset = AST_FRIENDLY_OFFSET;
		memcpy(rtp->f.data.ptr, data + 1, len - 1);
	} else {
		rtp->f.data.ptr = NULL;
		rtp->f.offset = 0;
		rtp->f.datalen = 0;
	}
	rtp->f.frametype = AST_FRAME_CNG;
	rtp->f.subclass.integer = data[0] & 0x7f;
	rtp->f.samples = 0;
	rtp->f.delivery.tv_usec = rtp->f.delivery.tv_sec = 0;

	return &rtp->f;
}

static struct ast_frame *ast_rtcp_read_fd(int fd, struct ast_rtp_instance *instance);
struct ast_frame *ast_rtcp_read(struct ast_rtp_instance *instance);

#ifdef NOT_NEEDED_ANYMORE
static int p2p_rtcp_callback(int *id, int fd, short events, void *cbdata)
{
	struct ast_rtp *rtp = cbdata;
	ast_rtcp_read_fd(fd, instance);	
	/* For now, skip any frames that is output. Which is bad for FUR's, but well. DEBUG */
	return 1;
}
#endif

struct ast_frame *ast_rtcp_read(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return ast_rtcp_read_fd(rtp->rtcp->s, instance);
}

static struct ast_frame *ast_rtcp_read_fd(int fd, struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr addr;
	unsigned int rtcpdata[8192 + AST_FRIENDLY_OFFSET];
	unsigned int *rtcpheader = (unsigned int *)(rtcpdata + AST_FRIENDLY_OFFSET);
	int j, res, packetwords, position = 0;
	char *sdes;
	unsigned int sdeslength, sdestype;
	struct ast_frame *f = &ast_null_frame;

	/* Read in RTCP data from the socket */

/* OEJ - ouch, we need to send a file handle here. Check this
	isntance replaces the fd
*/
	if ((res = rtcp_recvfrom(instance, rtcpdata + AST_FRIENDLY_OFFSET,
				sizeof(rtcpdata) - sizeof(unsigned int) * AST_FRIENDLY_OFFSET,
				0, &addr)) < 0) {
		ast_assert(errno != EBADF);
		if (errno != EAGAIN) {
			ast_log(LOG_WARNING, "RTCP Read error: %s.  Hanging up.\n", strerror(errno));
			return NULL;
		}
		return &ast_null_frame;
	}

	packetwords = res / 4;	 /* Each RTCP segment is 32 bits */

	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT)) {
		/* Send to whoever sent to us */
		if (ast_sockaddr_cmp(&rtp->rtcp->them, &addr)) {
			ast_sockaddr_copy(&rtp->rtcp->them, &addr);
			if (option_debug || rtpdebug)
				ast_debug(0, "RTCP NAT: Got RTCP from other end. Now sending to address %s\n",
					  ast_sockaddr_stringify(&rtp->rtcp->them));
		}
	}

	if (rtcp_debug_test_addr(&addr)) {
		ast_debug(1, "Got RTCP report of %d bytes - %d messages\n", res, packetwords);
	}

	/* Process a compound packet 
	   - A compound packet should start with a sender or receiver report. BYE can start as well
		(seen in implementations) 
	   -  Packet length should be a multiple of four bytes
	*/
	while (position < packetwords) {
		int i, pt, rc;
		unsigned int length, dlsr, lsr, msw, lsw, comp;
		struct timeval now;
		double rttsec, reported_jitter, reported_normdev_jitter_current, normdevrtt_current, reported_lost, reported_normdev_lost_current;
		uint64_t rtt = 0;

		i = position;
		if (rtcp_debug_test_addr(&addr)) {
			ast_debug(3, "***** Debug - position = %d\n", position     );
		}
		length = ntohl(rtcpheader[i]);
		pt = (length & 0xff0000) >> 16;		/* Packet type */
		rc = (length & 0x1f000000) >> 24;	/* Number of chunks, i.e. streams reported */
		length &= 0xffff;

		if ((i + length) > packetwords) {
			if (option_debug || rtpdebug) {
				ast_debug(2, "RTCP Read too short - packet type %d position %d\n", pt, i);
			}
			//return &ast_null_frame;
			return f;
		}

		if (rtcp_debug_test_addr(&addr)) {
			ast_verbose("\n\nGot RTCP from %s\n",
				    ast_sockaddr_stringify(&addr));
			ast_verbose("PT: %d(%s)\n", pt, find_rtcp_pt(pt)); 
			ast_verbose("Reception reports: %d\n", rc);
			ast_verbose("   SSRC of packet sender: %u (%x)", ntohl(rtcpheader[i + 1]), ntohl(rtcpheader[i + 1]));
			ast_verbose("   (Position %d of %d)\n", i, packetwords);
			if (rc == 0) {  
				ast_verbose("   Empty - no reports! \n");
			}
		}

		i += 2; /* Advance past header and ssrc */
		if (rc == 0 && pt == RTCP_PT_RR) {      /* We're receiving a receiver report with no reports, which is ok */
			position += (length + 1);
			continue;
		}


		if (rc == 0 && pt == RTCP_PT_RR) {	/* We're receiving a receiver report with no reports, which is ok */
			position += (length + 1);
			continue;
		}
		if (pt == RTCP_PT_SR) {
			rtp->rtcp->rec_sr_count++;
		} else if (pt == RTCP_PT_RR) {
			rtp->rtcp->rec_rr_count++;
		}
		switch (pt) {
		case RTCP_PT_SR:	/* Sender's report - about what they have sent us */
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("    - RTCP SR (sender report) from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
			/* Don't handle multiple reception reports (rc > 1) yet */
			gettimeofday(&rtp->rtcp->rxlsr, NULL); /* To be able to populate the dlsr */
			rtp->rtcp->spc = ntohl(rtcpheader[i + 3]);	/* Sender packet count */
			rtp->rtcp->soc = ntohl(rtcpheader[i + 4]);	/* Sender octet count */

 			rtp->rtcp->themrxlsr = ((ntohl(rtcpheader[i]) & 0x0000ffff) << 16) | ((ntohl(rtcpheader[i + 1]) & 0xffff0000) >> 16); /* Going to LSR in RR*/
     
 			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("      NTP timestamp: %lu.%010lu\n", (unsigned long) ntohl(rtcpheader[i]), (unsigned long) ntohl(rtcpheader[i + 1]) * 4096);
				ast_verbose("      RTP timestamp: %lu\n", (unsigned long) ntohl(rtcpheader[i + 2]));
				ast_verbose("      SPC: %lu\tSOC: %lu\n", (unsigned long) ntohl(rtcpheader[i + 3]), (unsigned long) ntohl(rtcpheader[i + 4]));
				ast_verbose("      RC (number of reports) %d\n", rc);
 			}
			i += 5;	/* Sender's info report is five bytes */
 			if (rc < 1)
 				break;

		case RTCP_PT_RR:	/* Receiver report - data about what we have sent to them */
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("Received a RTCP RR (receiver report) from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
			/* Calculate RTT per RFC */
			gettimeofday(&now, NULL);
			timeval2ntp(now, &msw, &lsw);
			/* Get timing */ 
			if (ntohl(rtcpheader[i + 4]) && ntohl(rtcpheader[i + 5])) { /* We must have the LSR && DLSR */
				comp = ((msw & 0xffff) << 16) | ((lsw & 0xffff0000) >> 16);
				lsr = ntohl(rtcpheader[i + 4]);
				dlsr = ntohl(rtcpheader[i + 5]);
				rtt = comp - lsr - dlsr;

				/* Convert end to end delay to usec (keeping the calculation in 64bit space)
				   sess->ee_delay = (eedelay * 1000) / 65536; */
				if (rtt < 4294) {
					rtt = (rtt * 1000000) >> 16;
				} else {
					rtt = (rtt * 1000) >> 16;
					rtt *= 1000;
				}
				rtt = rtt / 1000.;
				rttsec = rtt / 1000.;
				rtp->rtcp->rtt = rttsec;

				if (comp - dlsr >= lsr) {
					rtp->rtcp->accumulated_transit += rttsec;

					if (rtp->rtcp->rtt_count == 0) {
						rtp->rtcp->minrtt = rttsec;
					}

					if (rtp->rtcp->maxrtt<rttsec) {
						rtp->rtcp->maxrtt = rttsec;
					}
					if (rtp->rtcp->minrtt > rttsec || rtp->rtcp->minrtt == 0) {
						rtp->rtcp->minrtt = rttsec;
					}

					normdevrtt_current = normdev_compute(rtp->rtcp->normdevrtt, rttsec, rtp->rtcp->rtt_count);

					rtp->rtcp->stdevrtt = stddev_compute(rtp->rtcp->stdevrtt, rttsec, rtp->rtcp->normdevrtt, normdevrtt_current, rtp->rtcp->rtt_count);

					rtp->rtcp->normdevrtt = normdevrtt_current;

					rtp->rtcp->rtt_count++;
				} else if (rtcp_debug_test_addr(&addr)) {
					ast_verbose("Internal RTCP NTP clock skew detected: "
							   "lsr=%u, now=%u, dlsr=%u (%d:%03dms), "
						    "diff=%d\n",
						    lsr, comp, dlsr, dlsr / 65536,
						    (dlsr % 65536) * 1000 / 65536,
						    dlsr - (comp - lsr));
				}
			}

			rtp->rtcp->reported_jitter = ntohl(rtcpheader[i + 3]);
			reported_jitter = (double) rtp->rtcp->reported_jitter;

			if (rtp->rtcp->reported_jitter_count == 0)
				rtp->rtcp->reported_minjitter = reported_jitter;

			if (reported_jitter < rtp->rtcp->reported_minjitter)
				rtp->rtcp->reported_minjitter = reported_jitter;

			if (reported_jitter > rtp->rtcp->reported_maxjitter)
				rtp->rtcp->reported_maxjitter = reported_jitter;

			reported_normdev_jitter_current = normdev_compute(rtp->rtcp->reported_normdev_jitter, reported_jitter, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_stdev_jitter = stddev_compute(rtp->rtcp->reported_stdev_jitter, reported_jitter, rtp->rtcp->reported_normdev_jitter, reported_normdev_jitter_current, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_normdev_jitter = reported_normdev_jitter_current;

			rtp->rtcp->reported_lost = ntohl(rtcpheader[i + 1]) & 0xffffff;	/* Lost packets for HOLE session, not for report time */

			reported_lost = (double) rtp->rtcp->reported_lost;

			/* using same counter as for jitter */
			if (rtp->rtcp->reported_jitter_count == 0)
				rtp->rtcp->reported_minlost = reported_lost;

			if (reported_lost < rtp->rtcp->reported_minlost)	/* OEJ: Min and max are not really interesting here. */
				rtp->rtcp->reported_minlost = reported_lost;

			if (reported_lost > rtp->rtcp->reported_maxlost)
				rtp->rtcp->reported_maxlost = reported_lost;
			reported_normdev_lost_current = normdev_compute(rtp->rtcp->reported_normdev_lost, reported_lost, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_stdev_lost = stddev_compute(rtp->rtcp->reported_stdev_lost, reported_lost, rtp->rtcp->reported_normdev_lost, reported_normdev_lost_current, rtp->rtcp->reported_jitter_count);

			rtp->rtcp->reported_normdev_lost = reported_normdev_lost_current;

			rtp->rtcp->reported_jitter_count++;

			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("  Fraction lost: %ld\n", (((long) ntohl(rtcpheader[i + 1]) & 0xff000000) >> 24));
				ast_verbose("  Packets lost so far: %d\n", rtp->rtcp->reported_lost);
				ast_verbose("  Highest sequence number: %ld\n", (long) (ntohl(rtcpheader[i + 2]) & 0xffff));
				ast_verbose("  Sequence number cycles: %ld\n", (long) (ntohl(rtcpheader[i + 2]) & 0xffff) >> 16);
				ast_verbose("  Interarrival jitter: %u\n", rtp->rtcp->reported_jitter);
				ast_verbose("  Last SR(our NTP): %lu.%010lu\n",(unsigned long) ntohl(rtcpheader[i + 4]) >> 16,((unsigned long) ntohl(rtcpheader[i + 4]) << 16) * 4096);
				ast_verbose("  DLSR: %4.4f (sec)\n",ntohl(rtcpheader[i + 5])/65536.0);
				if (rtt)
					ast_verbose("  RTT: %lu(sec)\n", (unsigned long) rtt);
			}
			if (rtt) {
				manager_event(EVENT_FLAG_REPORTING, "RTCPReceived", "From: %s\r\n"
								    "PT: %d(%s)\r\n"
								    "ReceptionReports: %d\r\n"
								    "SenderSSRC: %u\r\n"
								    "FractionLost: %ld\r\n"
								    "PacketsLost: %d\r\n"
								    "HighestSequence: %ld\r\n"
								    "SequenceNumberCycles: %ld\r\n"
								    "IAJitter: %u\r\n"
								    "LastSR: %lu.%010lu\r\n"
								    "DLSR: %4.4f(sec)\r\n"
					      "RTT: %llu(sec)\r\n",
					      ast_sockaddr_stringify(&addr),
					      pt, (pt == 200) ? "Sender Report" : (pt == 201) ? "Receiver Report" : (pt == 192) ? "H.261 FUR" : "Unknown",
					      rc,
					      rtcpheader[i + 1],
					      (((long) ntohl(rtcpheader[i + 1]) & 0xff000000) >> 24),
					      rtp->rtcp->reported_lost,
					      (long) (ntohl(rtcpheader[i + 2]) & 0xffff),
					      (long) (ntohl(rtcpheader[i + 2]) & 0xffff) >> 16,
					      rtp->rtcp->reported_jitter,
					      (unsigned long) ntohl(rtcpheader[i + 4]) >> 16, ((unsigned long) ntohl(rtcpheader[i + 4]) << 16) * 4096,
					      ntohl(rtcpheader[i + 5])/65536.0,
					      (unsigned long long)rtt);
			} else {
				manager_event(EVENT_FLAG_REPORTING, "RTCPReceived", "From: %s\r\n"
								    "PT: %d(%s)\r\n"
								    "ReceptionReports: %d\r\n"
								    "SenderSSRC: %u\r\n"
								    "FractionLost: %ld\r\n"
								    "PacketsLost: %d\r\n"
								    "HighestSequence: %ld\r\n"
								    "SequenceNumberCycles: %ld\r\n"
								    "IAJitter: %u\r\n"
								    "LastSR: %lu.%010lu\r\n"
					      "DLSR: %4.4f(sec)\r\n",
					      ast_sockaddr_stringify(&addr),
					      pt, (pt == 200) ? "Sender Report" : (pt == 201) ? "Receiver Report" : (pt == 192) ? "H.261 FUR" : "Unknown",
					      rc,
					      rtcpheader[i + 1],
					      (((long) ntohl(rtcpheader[i + 1]) & 0xff000000) >> 24),
					      rtp->rtcp->reported_lost,
					      (long) (ntohl(rtcpheader[i + 2]) & 0xffff),
					      (long) (ntohl(rtcpheader[i + 2]) & 0xffff) >> 16,
					      rtp->rtcp->reported_jitter,
					      (unsigned long) ntohl(rtcpheader[i + 4]) >> 16,
					      ((unsigned long) ntohl(rtcpheader[i + 4]) << 16) * 4096,
					      ntohl(rtcpheader[i + 5])/65536.0);
			}
			break;
		case RTCP_PT_FUR:
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("Received an RTCP Fast Update Request from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
			rtp->f.frametype = AST_FRAME_CONTROL;
			rtp->f.subclass.integer = AST_CONTROL_VIDUPDATE;
			rtp->f.datalen = 0;
			rtp->f.samples = 0;
			rtp->f.mallocd = 0;
			rtp->f.src = "RTP";
			f = &rtp->f;
			break;
		case RTCP_PT_SDES:
			/* SDES messages are divided into chunks, each one containing one or
			   several items. Each chunk is for a different CSRC, so it is not really
			   relevant in most cases of voip calls - unless you have an advanced
			   mixer in the network that separates the different streams with CSRC 

			   A chunk starts with SSRC/CSRC (four bytes), then SDES items 
			   In the SDES message, there can be several items, ending with SDES_END
			   The length of the all items is length - header 
			   Chunk starts on a 32-bit boundary and needs padding by 0's
		
			   the "rc" variable contains the number of chunks 
			   When we start, we're beyond the SSRC and starts with SDES items in the
			   first chunk.
			
				an SDES item is one byte of type, one byte of length then data 
				(no null termination). Text is UTF-8.
				the last item is a zero (END) type with no length indication.
			*/
			
			j = i * 4;
			sdes = (char *) &rtcpheader[i];
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("   Received an SDES from %s - Total length %d (%d bytes)\n", ast_sockaddr_stringify(&rtp->rtcp->them), length-i, ((length-i)*4) - 6);
			}
			while (j < length * 4) {
				sdestype = (uint8_t) *sdes;
				sdes++;
				sdeslength = (uint8_t) *sdes;
				sdes++;
				if (rtcp_debug_test_addr(&addr)) {
					ast_verbose(" --- SDES Type %u, Length %u Curj %d)\n", sdestype, sdeslength, j);
				}
				switch (sdestype) {
				case SDES_CNAME:
					if (!ast_strlen_zero(rtp->rtcp->theircname)) {
						if (sdeslength > sizeof(rtp->rtcp->theircname)) {
							sdeslength = sizeof(rtp->rtcp->theircname) - 1;
						}
						if (strncmp(rtp->rtcp->theircname, sdes, sdeslength)) {
							ast_log(LOG_WARNING, "New RTP stream received (new RTCP CNAME for session. Old name: %s\n", rtp->rtcp->theircname);
						}
					}
					strncpy(rtp->rtcp->theircname, sdes, sdeslength);
					rtp->rtcp->theircname[sdeslength + 1] = '\0';
					rtp->rtcp->theircnamelength = sdeslength;
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES CNAME (utf8) %s\n", rtp->rtcp->theircname);
					}
					break;
				case SDES_TOOL:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES TOOL \n");
					}
					break;
				case SDES_NAME:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES NAME \n");
					}
					break;
				case SDES_EMAIL:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES EMAIL \n");
					}
					break;
				case SDES_PHONE:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES PHONE \n");
					}
					break;
				case SDES_LOC:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES LOC \n");
					}
					break;
				case SDES_NOTE:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES NOTE \n");
					}
					break;
				case SDES_PRIV:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES PRIV \n");
					}
					break;
				case SDES_END:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES END \n");
					}
					break;
				case SDES_APSI:
					if (rtcp_debug_test_addr(&addr)) {
						ast_verbose(" --- SDES APSI \n");
					}
					break;
				}
				j += 2 + sdeslength;	/* Header (1 byte) + length */
				sdes += sdeslength;
				if (sdestype == SDES_END) {
					break;	/* The while loop */
				}
			}

			break;
		case RTCP_PT_NACK:
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("   Received a RTCP NACK from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
			break;
 		case RTCP_PT_BYE:
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("   Received a RTCP BYE from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
 			break;
		case RTCP_PT_XR:
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("   Received a RTCP Extended Report (XR) packet from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
			break;
		case RTCP_PT_APP:
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("   Received a RTCP APP packet from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
			break;
		case RTCP_PT_IJ:
			if (rtcp_debug_test_addr(&addr)) {
				ast_verbose("   Received a RTCP IJ from %s\n", ast_sockaddr_stringify(&rtp->rtcp->them));
			}
			break;
		default:
			ast_debug(1, "Unknown RTCP packet (pt=%d) received from %s\n", pt, ast_sockaddr_stringify(&rtp->rtcp->them));
			break;
		}
		position += (length + 1);
	}	/* While loop */

	/* OEJ CHECK next line */
	rtp->rtcp->rtcp_info = 1;

	return f;
}

static int bridge_p2p_rtp_write(struct ast_rtp_instance *instance, unsigned int *rtpheader, int len, int hdrlen)
{
	struct ast_rtp_instance *instance1 = ast_rtp_instance_get_bridged(instance);
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance), *bridged = ast_rtp_instance_get_data(instance1);
	int res = 0, payload = 0, bridged_payload = 0, mark;
	struct ast_rtp_payload_type payload_type;
	int reconstruct = ntohl(rtpheader[0]);
	struct ast_sockaddr remote_address = { {0,} };
	struct timeval rxtime;
	unsigned int timestamp;
	int rate;
	unsigned int ms;

	/* Get fields from packet */
	payload = (reconstruct & 0x7f0000) >> 16;
	mark = (((reconstruct & 0x800000) >> 23) != 0);

	/* Check what the payload value should be */
	payload_type = ast_rtp_codecs_payload_lookup(ast_rtp_instance_get_codecs(instance), payload);

	/* Otherwise adjust bridged payload to match */
	bridged_payload = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance1), payload_type.asterisk_format, payload_type.code);

	/* If the payload coming in is not one of the negotiated ones then send it to the core, this will cause formats to change and the bridge to break */
	if (!(ast_rtp_instance_get_codecs(instance1)->payloads[bridged_payload].code)) {
		return -1;
	}

	/* If the marker bit has been explicitly set turn it on */
	if (ast_test_flag(rtp, FLAG_NEED_MARKER_BIT)) {
		mark = 1;
		ast_clear_flag(rtp, FLAG_NEED_MARKER_BIT);
	}

	/* Calculate timestamp for reception of the packet */
	timestamp = ntohl(rtpheader[1]);
	calc_rxstamp(&rxtime, rtp, timestamp, mark);

 	rate = rtp_get_rate(bridged_payload) / 1000;

	/* Now, calculate tx timestamp */
	ms = calc_txstamp(rtp, &rxtime);
	if (bridged_payload == AST_FRAME_VOICE) {
		bridged->lastts = bridged->lastts + ms * rate;
	} else if (bridged_payload == AST_FRAME_VIDEO) {
		bridged->lastts = bridged->lastts + ms * 90;
		/* This is not exact, but a best effort example that can be improved */
	}

	/* Reconstruct part of the packet */
	reconstruct &= 0xFF80FFFF;
	reconstruct |= (bridged_payload << 16);
	reconstruct |= (mark << 23);
	rtpheader[0] = htonl(reconstruct);

	bridged->lasttxformat = rtp->lastrxformat = bridged_payload;

	ast_rtp_instance_get_remote_address(instance1, &remote_address);

	if (ast_sockaddr_isnull(&remote_address)) {
		ast_debug(1, "Remote address is null, most likely RTP has been stopped\n");
		return 0;
	}

	/* Send the packet back out */
	res = rtp_sendto(instance1, (void *)rtpheader, len, 0, &remote_address);
	if (res < 0) {
		if (!ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_NAT) || (ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_NAT) && (ast_test_flag(bridged, FLAG_NAT_ACTIVE) == FLAG_NAT_ACTIVE))) {
			ast_log(LOG_WARNING,
				"RTP Transmission error of packet to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		} else if (((ast_test_flag(bridged, FLAG_NAT_ACTIVE) == FLAG_NAT_INACTIVE) || rtpdebug) && !ast_test_flag(bridged, FLAG_NAT_INACTIVE_NOWARN)) {
			if (option_debug || rtpdebug)
				ast_log(LOG_WARNING,
					"RTP NAT: Can't write RTP to private "
					"address %s, waiting for other end to "
					"send audio...\n",
					ast_sockaddr_stringify(&remote_address));
			ast_set_flag(bridged, FLAG_NAT_INACTIVE_NOWARN);
		}
		return 0;
	}

	bridged->txcount++;
	bridged->txoctetcount += (res - hdrlen);

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent RTP P2P packet to %s (type %-2.2d, len %-6.6u)\n",
			    ast_sockaddr_stringify(&remote_address),
			    bridged_payload, len - hdrlen);
	}

	return 0;
}

static struct ast_frame *ast_rtp_read(struct ast_rtp_instance *instance, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr addr;
	int res, hdrlen = 12, version, payloadtype, padding, mark, ext, cc, prev_seqno;
	unsigned int *rtpheader = (unsigned int*)(rtp->rawdata + AST_FRIENDLY_OFFSET), seqno, ssrc, timestamp;
	struct ast_rtp_payload_type payload;
	struct ast_sockaddr remote_address = { {0,} };
	struct frame_list frames;

	/* If this is actually RTCP let's hop on over and handle it */
	if (rtcp) {
		if (rtp->rtcp) {
			return ast_rtcp_read(instance);
		}
		return &ast_null_frame;
	}

	/* If we are currently sending DTMF to the remote party send a continuation packet */
	if (rtp->sending_dtmf) {
		ast_rtp_dtmf_cont(instance);
	}

	/* Actually read in the data from the socket */
	if ((res = rtp_recvfrom(instance, rtp->rawdata + AST_FRIENDLY_OFFSET,
				sizeof(rtp->rawdata) - AST_FRIENDLY_OFFSET, 0,
				&addr)) < 0) {
		ast_assert(errno != EBADF);
		if (errno != EAGAIN) {
			ast_log(LOG_WARNING, "RTP Read error: %s. Hanging up.\n", strerror(errno));
			return NULL;
		}
		return &ast_null_frame;
	}

	/* Make sure the data that was read in is actually enough to make up an RTP packet */
	if (res < hdrlen) {
		ast_log(LOG_WARNING, "RTP Read too short (%d expecting %d)\n", res, hdrlen);
		return &ast_null_frame;
	}

	/* If strict RTP protection is enabled see if we need to learn the remote address or if we need to drop the packet */
	if (rtp->strict_rtp_state == STRICT_RTP_LEARN) {
		ast_debug(1, "%p -- start learning mode pass with addr = %s\n", rtp, ast_sockaddr_stringify(&addr));
		/* For now, we always copy the address. */
		ast_sockaddr_copy(&rtp->strict_rtp_address, &addr);

		/* Send the rtp and the seqno from header to rtp_learning_rtp_seq_update to see whether we can exit or not*/
		if (rtp_learning_rtp_seq_update(rtp, ntohl(rtpheader[0]))) {
			ast_debug(1, "%p -- Condition for learning hasn't exited, so reject the frame.\n", rtp);
			return &ast_null_frame;
		}

		ast_debug(1, "%p -- Probation Ended. Set strict_rtp_state to STRICT_RTP_CLOSED with address %s\n", rtp, ast_sockaddr_stringify(&addr));
		rtp->strict_rtp_state = STRICT_RTP_CLOSED;
	} else if (rtp->strict_rtp_state == STRICT_RTP_CLOSED) {
		if (ast_sockaddr_cmp(&rtp->strict_rtp_address, &addr)) {
			/* Hmm, not the strict addres. Perhaps we're getting audio from the alternate? */
			if (!ast_sockaddr_cmp(&rtp->alt_rtp_address, &addr)) {
				/* ooh, we did! You're now the new expected address, son! */
				ast_sockaddr_copy(&rtp->strict_rtp_address,
						  &addr);
			} else  {
				const char *real_addr = ast_strdupa(ast_sockaddr_stringify(&addr));
				const char *expected_addr = ast_strdupa(ast_sockaddr_stringify(&rtp->strict_rtp_address));

				ast_debug(1, "Received RTP packet from %s, dropping due to strict RTP protection. Expected it to be from %s\n",
						real_addr, expected_addr);

				return &ast_null_frame;
			}
		}
	}

	/* Get fields and verify this is an RTP packet */
	seqno = ntohl(rtpheader[0]);

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (!(version = (seqno & 0xC0000000) >> 30)) {
		struct sockaddr_in addr_tmp;
		struct ast_sockaddr addr_v4;
		if (ast_sockaddr_is_ipv4(&addr)) {
			ast_sockaddr_to_sin(&addr, &addr_tmp);
		} else if (ast_sockaddr_ipv4_mapped(&addr, &addr_v4)) {
			ast_debug(1, "Using IPv6 mapped address %s for STUN\n",
				  ast_sockaddr_stringify(&addr));
			ast_sockaddr_to_sin(&addr_v4, &addr_tmp);
		} else {
			ast_debug(1, "Cannot do STUN for non IPv4 address %s\n",
				  ast_sockaddr_stringify(&addr));
			return &ast_null_frame;
		}
		if ((ast_stun_handle_packet(rtp->s, &addr_tmp, rtp->rawdata + AST_FRIENDLY_OFFSET, res, NULL, NULL) == AST_STUN_ACCEPT) &&
		    ast_sockaddr_isnull(&remote_address)) {
			ast_sockaddr_from_sin(&addr, &addr_tmp);
			ast_rtp_instance_set_remote_address(instance, &addr);
		}
		return &ast_null_frame;
	}

	/* If symmetric RTP is enabled see if the remote side is not what we expected and change where we are sending audio */
	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT)) {
		if (ast_sockaddr_cmp(&remote_address, &addr)) {
			ast_rtp_instance_set_remote_address(instance, &addr);
			ast_sockaddr_copy(&remote_address, &addr);
			if (rtp->rtcp) {
				ast_sockaddr_copy(&rtp->rtcp->them, &addr);
				ast_sockaddr_set_port(&rtp->rtcp->them, ast_sockaddr_port(&addr) + 1);
			}
			rtp->rxseqno = 0;
			ast_set_flag(rtp, FLAG_NAT_ACTIVE);
			if (option_debug || rtpdebug)
				ast_debug(0, "RTP NAT: Got audio from other end. Now sending to address %s\n",
					  ast_sockaddr_stringify(&remote_address));
		}
	}


	/* If the version is not what we expected by this point then just drop the packet */
	if (version != 2) {
		return &ast_null_frame;
	}

	/* Pull out the various other fields we will need */
	payloadtype = (seqno & 0x7f0000) >> 16;
	padding = seqno & (1 << 29);
	mark = seqno & (1 << 23);
	ext = seqno & (1 << 28);
	cc = (seqno & 0xF000000) >> 24;
	seqno &= 0xffff;
	timestamp = ntohl(rtpheader[1]);
	ssrc = ntohl(rtpheader[2]);

	AST_LIST_HEAD_INIT_NOLOCK(&frames);
	/* Force a marker bit and change SSRC if the SSRC changes */
	if (rtp->rxssrc && rtp->rxssrc != ssrc) {
		struct ast_frame *f, srcupdate = {
			AST_FRAME_CONTROL,
			.subclass.integer = AST_CONTROL_SRCCHANGE,
		};

		if (!mark) {
			if (option_debug || rtpdebug) {
				ast_debug(1, "Forcing Marker bit, because SSRC has changed\n");
			}
			mark = 1;
		}

		f = ast_frisolate(&srcupdate);
		AST_LIST_INSERT_TAIL(&frames, f, frame_list);
	}

	rtp->rxssrc = ssrc;

	/* Schedule RTCP report transmissions if possible */
	ast_rtcp_schedule(instance);

	/* This needs to be after RTCP calculations to get more RTCP data */
	/* If we are directly bridged to another instance send the audio directly out */
	if (ast_rtp_instance_get_bridged(instance) && !bridge_p2p_rtp_write(instance, rtpheader, res, hdrlen)) {
		return &ast_null_frame;
	}

	/* Remove any padding bytes that may be present */
	if (padding) {
		res -= rtp->rawdata[AST_FRIENDLY_OFFSET + res - 1];
	}

	/* Skip over any CSRC fields */
	if (cc) {
		hdrlen += cc * 4;
	}

	/* Look for any RTP extensions, currently we do not support any */
	if (ext) {
		hdrlen += (ntohl(rtpheader[hdrlen/4]) & 0xffff) << 2;
		hdrlen += 4;
		if (option_debug) {
			int profile;
			profile = (ntohl(rtpheader[3]) & 0xffff0000) >> 16;
			if (profile == 0x505a)
				ast_debug(1, "Found Zfone extension in RTP stream - zrtp - not supported.\n");
			else
				ast_debug(1, "Found unknown RTP Extensions %x\n", profile);
		}
	}

	/* Make sure after we potentially mucked with the header length that it is once again valid */
	if (res < hdrlen) {
		ast_log(LOG_WARNING, "RTP Read too short (%d, expecting %d\n", res, hdrlen);
		return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
	}

	rtp->rxcount++;
	if (rtp->rxcount == 1) {
		rtp->seedrxseqno = seqno;
	}

	/* Do not schedule RR if RTCP isn't run */
	if (rtp->rtcp && !ast_sockaddr_isnull(&rtp->rtcp->them) && rtp->rtcp->schedid < 1) {
		/* Schedule transmission of Receiver Report */
		ao2_ref(instance, +1);
		rtp->rtcp->schedid = ast_sched_add(rtp->sched, ast_rtcp_calc_interval(rtp), ast_rtcp_write, instance);
		if (rtp->rtcp->schedid < 0) {
			ao2_ref(instance, -1);
			ast_log(LOG_WARNING, "scheduling RTCP transmission failed.\n");
		}
	}
	if ((int)rtp->lastrxseqno - (int)seqno  > 100) /* if so it would indicate that the sender cycled; allow for misordering */
		rtp->cycles += RTP_SEQ_MOD;

	prev_seqno = rtp->lastrxseqno;
	rtp->lastrxseqno = seqno;

	if (!rtp->themssrc) {
		rtp->themssrc = ntohl(rtpheader[2]); /* Record their SSRC to put in future RR */
	}

	if (rtp_debug_test_addr(&addr)) {
		ast_verbose("Got  RTP packet from    %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
			    ast_sockaddr_stringify(&addr),
			    payloadtype, seqno, timestamp,res - hdrlen);
	}

	payload = ast_rtp_codecs_payload_lookup(ast_rtp_instance_get_codecs(instance), payloadtype);

	/* If the payload is not actually an Asterisk one but a special one pass it off to the respective handler */
	if (!payload.asterisk_format) {
		struct ast_frame *f = NULL;
		if (payload.code == AST_RTP_DTMF) {
			/* process_dtmf_rfc2833 may need to return multiple frames. We do this
			 * by passing the pointer to the frame list to it so that the method
			 * can append frames to the list as needed.
			 */
			process_dtmf_rfc2833(instance, rtp->rawdata + AST_FRIENDLY_OFFSET + hdrlen, res - hdrlen, seqno, timestamp, &addr, payloadtype, mark, &frames);
		} else if (payload.code == AST_RTP_CISCO_DTMF) {
			f = process_dtmf_cisco(instance, rtp->rawdata + AST_FRIENDLY_OFFSET + hdrlen, res - hdrlen, seqno, timestamp, &addr, payloadtype, mark);
		} else if (payload.code == AST_RTP_CN) {
			f = process_cn_rfc3389(instance, rtp->rawdata + AST_FRIENDLY_OFFSET + hdrlen, res - hdrlen, seqno, timestamp, &addr, payloadtype, mark);
		} else {
			ast_log(LOG_NOTICE, "Unknown RTP codec %d received from '%s'\n",
				payloadtype,
				ast_sockaddr_stringify(&remote_address));
		}

		if (f) {
			AST_LIST_INSERT_TAIL(&frames, f, frame_list);
		}
		/* Even if no frame was returned by one of the above methods,
		 * we may have a frame to return in our frame list
		 */
		if (!AST_LIST_EMPTY(&frames)) {
			return AST_LIST_FIRST(&frames);
		}
		return &ast_null_frame;
	}

	rtp->lastrxformat = rtp->f.subclass.codec = payload.code;
	rtp->f.frametype = (rtp->f.subclass.codec & AST_FORMAT_AUDIO_MASK) ? AST_FRAME_VOICE : (rtp->f.subclass.codec & AST_FORMAT_VIDEO_MASK) ? AST_FRAME_VIDEO : AST_FRAME_TEXT;

	rtp->rxseqno = seqno;

	if (rtp->dtmf_timeout && rtp->dtmf_timeout < timestamp) {
		rtp->dtmf_timeout = 0;

		if (rtp->resp) {
			struct ast_frame *f;
			f = create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0);
			f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.codec)), ast_tv(0, 0));
			rtp->resp = 0;
			rtp->dtmf_timeout = rtp->dtmf_duration = 0;
			AST_LIST_INSERT_TAIL(&frames, f, frame_list);
			return AST_LIST_FIRST(&frames);
		}
	}

	rtp->lastrxts = timestamp;

	rtp->f.src = "RTP";
	rtp->f.mallocd = 0;
	rtp->f.datalen = res - hdrlen;
	rtp->f.data.ptr = rtp->rawdata + hdrlen + AST_FRIENDLY_OFFSET;
	rtp->f.offset = hdrlen + AST_FRIENDLY_OFFSET;
	rtp->f.seqno = seqno;

	if (rtp->f.subclass.codec == AST_FORMAT_T140 && (int)seqno - (prev_seqno+1) > 0 && (int)seqno - (prev_seqno+1) < 10) {
		unsigned char *data = rtp->f.data.ptr;

		memmove(rtp->f.data.ptr+3, rtp->f.data.ptr, rtp->f.datalen);
		rtp->f.datalen +=3;
		*data++ = 0xEF;
		*data++ = 0xBF;
		*data = 0xBD;
	}

	if (rtp->f.subclass.codec == AST_FORMAT_T140RED) {
		unsigned char *data = rtp->f.data.ptr;
		unsigned char *header_end;
		int num_generations;
		int header_length;
		int len;
		int diff =(int)seqno - (prev_seqno+1); /* if diff = 0, no drop*/
		int x;

		rtp->f.subclass.codec = AST_FORMAT_T140;
		header_end = memchr(data, ((*data) & 0x7f), rtp->f.datalen);
		if (header_end == NULL) {
			return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
		}
		header_end++;

		header_length = header_end - data;
		num_generations = header_length / 4;
		len = header_length;

		if (!diff) {
			for (x = 0; x < num_generations; x++)
				len += data[x * 4 + 3];

			if (!(rtp->f.datalen - len))
				return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;

			rtp->f.data.ptr += len;
			rtp->f.datalen -= len;
		} else if (diff > num_generations && diff < 10) {
			len -= 3;
			rtp->f.data.ptr += len;
			rtp->f.datalen -= len;

			data = rtp->f.data.ptr;
			*data++ = 0xEF;
			*data++ = 0xBF;
			*data = 0xBD;
		} else {
			for ( x = 0; x < num_generations - diff; x++)
				len += data[x * 4 + 3];

			rtp->f.data.ptr += len;
			rtp->f.datalen -= len;
		}
	}

	if (rtp->f.subclass.codec & AST_FORMAT_AUDIO_MASK) {
		rtp->f.samples = ast_codec_get_samples(&rtp->f);
		if ((rtp->f.subclass.codec == AST_FORMAT_SLINEAR) || (rtp->f.subclass.codec == AST_FORMAT_SLINEAR16)) {
			ast_frame_byteswap_be(&rtp->f);
		}
		calc_rxstamp(&rtp->f.delivery, rtp, timestamp, mark);
		/* Add timing data to let ast_generic_bridge() put the frame into a jitterbuf */
		ast_set_flag(&rtp->f, AST_FRFLAG_HAS_TIMING_INFO);
		rtp->f.ts = timestamp / (rtp_get_rate(rtp->f.subclass.codec) / 1000);
		rtp->f.len = rtp->f.samples / ((ast_format_rate(rtp->f.subclass.codec) / 1000));
	} else if (rtp->f.subclass.codec & AST_FORMAT_VIDEO_MASK) {
		/* Video -- samples is # of samples vs. 90000 */
		if (!rtp->lastividtimestamp)
			rtp->lastividtimestamp = timestamp;
		rtp->f.samples = timestamp - rtp->lastividtimestamp;
		rtp->lastividtimestamp = timestamp;
		rtp->f.delivery.tv_sec = 0;
		rtp->f.delivery.tv_usec = 0;
		/* Pass the RTP marker bit as bit 0 in the subclass field.
		 * This is ok because subclass is actually a bitmask, and
		 * the low bits represent audio formats, that are not
		 * involved here since we deal with video.
		 */
		if (mark)
			rtp->f.subclass.codec |= 0x1;
	} else {
		/* TEXT -- samples is # of samples vs. 1000 */
		if (!rtp->lastitexttimestamp)
			rtp->lastitexttimestamp = timestamp;
		rtp->f.samples = timestamp - rtp->lastitexttimestamp;
		rtp->lastitexttimestamp = timestamp;
		rtp->f.delivery.tv_sec = 0;
		rtp->f.delivery.tv_usec = 0;
	}

	AST_LIST_INSERT_TAIL(&frames, &rtp->f, frame_list);
	return AST_LIST_FIRST(&frames);
}

static void ast_rtp_prop_set(struct ast_rtp_instance *instance, enum ast_rtp_property property, int value)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (property == AST_RTP_PROPERTY_RTCP) {
		if (value) {
			if (rtp->rtcp) {
				ast_debug(1, "Ignoring duplicate RTCP property on RTP instance '%p'\n", instance);
				return;
			}
			/* Setup RTCP to be activated on the next RTP write */
			if (!(rtp->rtcp = ast_calloc(1, sizeof(*rtp->rtcp)))) {
				return;
			}

			/* Grab the IP address and port we are going to use */
			ast_rtp_instance_get_local_address(instance, &rtp->rtcp->us);
			ast_sockaddr_set_port(&rtp->rtcp->us,
					      ast_sockaddr_port(&rtp->rtcp->us) + 1);

			if ((rtp->rtcp->s =
			     create_new_socket("RTCP",
					       ast_sockaddr_is_ipv4(&rtp->rtcp->us) ?
					       AF_INET :
					       ast_sockaddr_is_ipv6(&rtp->rtcp->us) ?
					       AF_INET6 : -1)) < 0) {
				ast_debug(1, "Failed to create a new socket for RTCP on instance '%p'\n", instance);
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
				return;
			}

			/* Try to actually bind to the IP address and port we are going to use for RTCP, if this fails we have to bail out */
			if (ast_bind(rtp->rtcp->s, &rtp->rtcp->us)) {
				ast_debug(1, "Failed to setup RTCP on RTP instance '%p'\n", instance);
				close(rtp->rtcp->s);
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
				return;
			}

			ast_debug(1, "Setup RTCP on RTP instance '%p'\n", instance);
			rtp->rtcp->schedid = -1;

			return;
		} else {
			if (rtp->rtcp) {
				if (rtp->rtcp->schedid > 0) {
					if (!ast_sched_del(rtp->sched, rtp->rtcp->schedid)) {
						/* Successfully cancelled scheduler entry. */
						ao2_ref(instance, -1);
					} else {
						/* Unable to cancel scheduler entry */
						ast_debug(1, "Failed to tear down RTCP on RTP instance '%p'\n", instance);
						return;
					}
					rtp->rtcp->schedid = -1;
				}
				close(rtp->rtcp->s);
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
			}
			return;
		}
	}

	return;
}

static int ast_rtp_fd(struct ast_rtp_instance *instance, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtcp ? (rtp->rtcp ? rtp->rtcp->s : -1) : rtp->s;
}

static void ast_rtp_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (rtp->rtcp) {
		ast_debug(1, "Setting RTCP address on RTP instance '%p'\n", instance);
		ast_sockaddr_copy(&rtp->rtcp->them, addr);
		if (!ast_sockaddr_isnull(addr)) {
			ast_sockaddr_set_port(&rtp->rtcp->them,
					      ast_sockaddr_port(addr) + 1);
		}
	}

	rtp->rxseqno = 0;

	if (strictrtp) {
		rtp->strict_rtp_state = STRICT_RTP_LEARN;
		rtp_learning_seq_init(rtp, rtp->seqno);
	}

	return;
}

static void ast_rtp_alt_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* No need to futz with rtp->rtcp here because ast_rtcp_read is already able to adjust if receiving
	 * RTCP from an "unexpected" source
	 */
	ast_sockaddr_copy(&rtp->alt_rtp_address, addr);

	return;
}

/*! \brief Write t140 redundacy frame
 * \param data primary data to be buffered
 */
static int red_write(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance*) data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ast_rtp_write(instance, &rtp->red->t140);

	return 1;
}

static int rtp_red_init(struct ast_rtp_instance *instance, int buffer_time, int *payloads, int generations)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int x;

	if (!(rtp->red = ast_calloc(1, sizeof(*rtp->red)))) {
		return -1;
	}

	rtp->red->t140.frametype = AST_FRAME_TEXT;
	rtp->red->t140.subclass.codec = AST_FORMAT_T140RED;
	rtp->red->t140.data.ptr = &rtp->red->buf_data;

	rtp->red->t140.ts = 0;
	rtp->red->t140red = rtp->red->t140;
	rtp->red->t140red.data.ptr = &rtp->red->t140red_data;
	rtp->red->t140red.datalen = 0;
	rtp->red->ti = buffer_time;
	rtp->red->num_gen = generations;
	rtp->red->hdrlen = generations * 4 + 1;
	rtp->red->prev_ts = 0;

	for (x = 0; x < generations; x++) {
		rtp->red->pt[x] = payloads[x];
		rtp->red->pt[x] |= 1 << 7; /* mark redundant generations pt */
		rtp->red->t140red_data[x*4] = rtp->red->pt[x];
	}
	rtp->red->t140red_data[x*4] = rtp->red->pt[x] = payloads[x]; /* primary pt */
	rtp->red->schedid = ast_sched_add(rtp->sched, generations, red_write, instance);

	rtp->red->t140.datalen = 0;

	return 0;
}

static int rtp_red_buffer(struct ast_rtp_instance *instance, struct ast_frame *frame)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (frame->datalen > -1) {
		struct rtp_red *red = rtp->red;
		memcpy(&red->buf_data[red->t140.datalen], frame->data.ptr, frame->datalen);
		red->t140.datalen += frame->datalen;
		red->t140.ts = frame->ts;
	}

	return 0;
}

static int ast_rtp_local_bridge(struct ast_rtp_instance *instance0, struct ast_rtp_instance *instance1)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance0);

	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);

	return 0;
}

static int ast_rtp_get_stat(struct ast_rtp_instance *instance, struct ast_rtp_instance_stats *stats, enum ast_rtp_instance_stat stat)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp->rtcp) {
		return -1;
	}

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXCOUNT, -1, stats->txcount, rtp->txcount);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXCOUNT, -1, stats->rxcount, rtp->rxcount);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->txploss, rtp->rtcp->reported_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->rxploss, rtp->rtcp->expected_prior - rtp->rtcp->received_prior);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MAXRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_maxrxploss, rtp->rtcp->reported_maxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MINRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_minrxploss, rtp->rtcp->reported_minlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_NORMDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_normdevrxploss, rtp->rtcp->reported_normdev_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_STDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_stdevrxploss, rtp->rtcp->reported_stdev_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MAXRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_maxrxploss, rtp->rtcp->maxrxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MINRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_minrxploss, rtp->rtcp->minrxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_NORMDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_normdevrxploss, rtp->rtcp->normdev_rxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_STDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_stdevrxploss, rtp->rtcp->stdev_rxlost);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_LOSS);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->txjitter, rtp->rxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->rxjitter, rtp->rtcp->reported_jitter / (unsigned int) 65536.0);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MAXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_maxjitter, rtp->rtcp->reported_maxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MINJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_minjitter, rtp->rtcp->reported_minjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_NORMDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_normdevjitter, rtp->rtcp->reported_normdev_jitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_STDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_stdevjitter, rtp->rtcp->reported_stdev_jitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MAXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_maxjitter, rtp->rtcp->maxrxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MINJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_minjitter, rtp->rtcp->minrxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_NORMDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_normdevjitter, rtp->rtcp->normdev_rxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_STDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_stdevjitter, rtp->rtcp->stdev_rxjitter);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_JITTER);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->rtt, rtp->rtcp->rtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_MAX_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->maxrtt, rtp->rtcp->maxrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_MIN_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->minrtt, rtp->rtcp->minrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_NORMDEVRTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->normdevrtt, rtp->rtcp->normdevrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_STDEVRTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->stdevrtt, rtp->rtcp->stdevrtt);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_RTT);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_SSRC, -1, stats->local_ssrc, rtp->ssrc);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_SSRC, -1, stats->remote_ssrc, rtp->themssrc);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_START, -1, stats->start, rtp->start);
	if (stat == AST_RTP_INSTANCE_STAT_IP || stat == AST_RTP_INSTANCE_STAT_ALL) {
		memcpy(&stats->them, &rtp->rtcp->them, sizeof(stats->them));
	}
	if (stat == AST_RTP_INSTANCE_STAT_LOCAL_CNAME || stat == AST_RTP_INSTANCE_STAT_ALL) {
		memcpy(&stats->ourcname, &rtp->rtcp->ourcname, rtp->rtcp->ourcnamelength);	/* UTF8 safe */
		stats->ourcnamelength = rtp->rtcp->ourcnamelength;
	}
	if (stat == AST_RTP_INSTANCE_STAT_REMOTE_CNAME || stat == AST_RTP_INSTANCE_STAT_ALL) {
		memcpy(&stats->theircname, &rtp->rtcp->theircname, rtp->rtcp->theircnamelength);	/* UTF8 safe */
		stats->theircnamelength = rtp->rtcp->theircnamelength;
	}

	/* To fix */
	stats->numberofreports = rtp->rtcp->rec_rr_count + rtp->rtcp->rec_sr_count;
	stats->readcost = rtp->rtcp->readcost;
        stats->writecost = rtp->rtcp->writecost;
	stats->lasttxformat = rtp->lasttxformat;
	stats->lastrxformat = rtp->lastrxformat;
	if (!ast_strlen_zero(rtp->rtcp->readtranslator)) {
		ast_copy_string(stats->readtranslator, rtp->rtcp->readtranslator, sizeof(stats->readtranslator));
	}
	if (!ast_strlen_zero(rtp->rtcp->writetranslator)) {
		ast_copy_string(stats->writetranslator, rtp->rtcp->writetranslator, sizeof(stats->writetranslator));
	}
	if (!ast_strlen_zero(rtp->rtcp->readtranslator)) {
		ast_copy_string(stats->readtranslator, rtp->rtcp->readtranslator, sizeof(stats->readtranslator));
	}
	if (!ast_strlen_zero(rtp->rtcp->channel)) {
		ast_copy_string(stats->channel, rtp->rtcp->channel, sizeof(stats->channel));
	}
	if (!ast_strlen_zero(rtp->rtcp->bridgedchannel)) {
		ast_copy_string(stats->bridgedchannel, rtp->rtcp->bridgedchannel, sizeof(stats->bridgedchannel));
	}
	if (!ast_strlen_zero(rtp->rtcp->uniqueid)) {
		ast_copy_string(stats->uniqueid, rtp->rtcp->uniqueid, sizeof(stats->uniqueid));
	}
	if (!ast_strlen_zero(rtp->rtcp->bridgeduniqueid)) {
		ast_copy_string(stats->bridgeduniqueid, rtp->rtcp->bridgeduniqueid, sizeof(stats->bridgeduniqueid));
	}
	return 0;
}

static int ast_rtp_dtmf_compatible(struct ast_channel *chan0, struct ast_rtp_instance *instance0, struct ast_channel *chan1, struct ast_rtp_instance *instance1)
{
	/* If both sides are not using the same method of DTMF transmission
	 * (ie: one is RFC2833, other is INFO... then we can not do direct media.
	 * --------------------------------------------------
	 * | DTMF Mode |  HAS_DTMF  |  Accepts Begin Frames |
	 * |-----------|------------|-----------------------|
	 * | Inband    | False      | True                  |
	 * | RFC2833   | True       | True                  |
	 * | SIP INFO  | False      | False                 |
	 * --------------------------------------------------
	 */
	return (((ast_rtp_instance_get_prop(instance0, AST_RTP_PROPERTY_DTMF) != ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_DTMF)) ||
		 (!chan0->tech->send_digit_begin != !chan1->tech->send_digit_begin)) ? 0 : 1);
}

static void ast_rtp_stun_request(struct ast_rtp_instance *instance, struct ast_sockaddr *suggestion, const char *username)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct sockaddr_in suggestion_tmp;

	ast_sockaddr_to_sin(suggestion, &suggestion_tmp);
	ast_stun_request(rtp->s, &suggestion_tmp, username, NULL);
	ast_sockaddr_from_sin(suggestion, &suggestion_tmp);
}

/* \brief Put stream on/off hold, mute outbound RTP but keep
	RTP keepalives and RTCP going
 */
static void ast_rtp_hold(struct ast_rtp_instance *instance, int status)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	if (status) {
		ast_debug(1, "##### HOLDING RTCP, Have a nice day \n");
		ast_set_flag(rtp, FLAG_HOLD);
	} else {
		/* CLEAR */
		ast_debug(1, "##### UNHOLDING RTCP, You will get audio now. \n");
		ast_clear_flag(rtp, FLAG_HOLD);
	}
}

static void ast_rtp_stop(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr addr = { {0,} };

	ast_debug(1, "##### Stopping RTP, Sending good bye \n");

	/* Send RTCP goodbye packet */
	if (rtp->isactive && rtp->rtcp) {
		ast_rtcp_write_sr(instance, 1);
		ast_debug(1, "##### Stopping RTCP, Sent good bye \n");
	}
	if (rtp->rtcp && rtp->rtcp->schedid > 0) {
		if (!ast_sched_del(rtp->sched, rtp->rtcp->schedid)) {
			/* successfully cancelled scheduler entry. */
			ao2_ref(instance, -1);
		}
		rtp->rtcp->schedid = -1;
		ast_debug(1, "##### Stopping RTCP, Removing scheduler \n");
	}

	if (rtp->red) {
		AST_SCHED_DEL(rtp->sched, rtp->red->schedid);
		free(rtp->red);
		rtp->red = NULL;
	}

	ast_rtp_instance_set_remote_address(instance, &addr);
	if (rtp->rtcp) {
		ast_sockaddr_setnull(&rtp->rtcp->them);
	}

	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);
	rtp->isactive = 0;
}

static int ast_rtp_qos_set(struct ast_rtp_instance *instance, int tos, int cos, const char *desc)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return ast_set_qos(rtp->s, tos, cos, desc);
}


/*! \brief set RTP cname used to describe session in RTCP sdes messages */
void ast_rtcp_setcname(struct ast_rtp_instance *instance, const char *cname, size_t length)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp || !rtp->rtcp) {
		return;
	}
	if (length > 255) {
		length=255;
	}
	ast_copy_string(rtp->rtcp->ourcname, cname, length+1);
	rtp->rtcp->ourcnamelength = length;
	if (option_debug > 3) {
		ast_log(LOG_DEBUG, "--- Copied CNAME %s to RTCP structure (length %d)\n", cname, (int) length);
	}
}

/*! \brief set the name of the bridged channel

At the time when we write the report there might not be a bridge, so we need
to store this so we can correlate the reports. If a channel changes bridge,
it can be reset by first setting it to an empty string, then setting to 
a new name 
*/
void ast_rtcp_set_bridged(struct ast_rtp_instance *instance, const char *channel, const char *uniqueid, const char *bridgedchan, const char *bridgeduniqueid)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp) {		/* For some reason, there's no RTP */
		ast_debug(1, "??????????????? NO RTP \n");
		return;
	}
	if (!rtp->rtcp) {	/* No RTCP? Strange */
		ast_debug(1, "??????????????? NO RTCP \n");
		return;
	}
	/* If we already have data, don't replace it. 
		NOTE: Should we replace it at a masquerade or something? Hmm.
	*/
	if (!ast_strlen_zero(channel) && !rtp->rtcp->channel[0]) {
		ast_debug(1, "!!!!!! Setting channel name to %s\n", channel);
		ast_copy_string(rtp->rtcp->channel, channel, sizeof(rtp->rtcp->channel));
	}
	if (!ast_strlen_zero(uniqueid) && !rtp->rtcp->uniqueid[0]) {
		ast_debug(1, "!!!!!! Setting unique id to %s\n", uniqueid);
		ast_copy_string(rtp->rtcp->uniqueid, uniqueid, sizeof(rtp->rtcp->uniqueid));
	}
	if (!ast_strlen_zero(bridgedchan)) {
		ast_debug(1, "!!!!!! Setting bridged channel name to %s\n", bridgedchan);
		ast_copy_string(rtp->rtcp->bridgedchannel, bridgedchan, sizeof(rtp->rtcp->bridgedchannel));
	} else {
		if(rtp->rtcp->bridgedchannel[0] != '\0') {
			ast_debug(1, "!!!!!! Keeping bridged channel name %s\n", rtp->rtcp->bridgedchannel);
		}
		//rtp->rtcp->bridgedchan[0] = '\0';
	}
	if (!ast_strlen_zero(bridgeduniqueid)) {
		ast_debug(1, "!!!!!! Setting bridged unique id to %s\n", bridgeduniqueid);
		ast_copy_string(rtp->rtcp->bridgeduniqueid, bridgeduniqueid, sizeof(rtp->rtcp->bridgeduniqueid));
	} else {
		if(rtp->rtcp->bridgeduniqueid[0] != '\0') {
			ast_debug(1, "!!!!!! Keeping bridged unique id \n");
		}
	}
}


/*! \brief Set the transcoding variables for the QoS reports */
void ast_rtcp_set_translator(struct ast_rtp_instance *instance, const char *readtranslator, const int readcost, const char *writetranslator, const int writecost)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	if (!rtp || !rtp->rtcp) {
		return;
	}
	ast_copy_string(rtp->rtcp->readtranslator, S_OR(readtranslator,""), sizeof(rtp->rtcp->readtranslator));
	ast_copy_string(rtp->rtcp->writetranslator, S_OR(writetranslator,""), sizeof(rtp->rtcp->writetranslator));
	rtp->rtcp->readcost = readcost;
	rtp->rtcp->writecost = writecost;
	
}



/*! \brief generate comfort noice (CNG) */
static int ast_rtp_sendcng(struct ast_rtp_instance *instance, int level)
{
	unsigned int *rtpheader;
	int hdrlen = 12;
	int res;
	struct ast_rtp_payload_type payload;
	char data[256];
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	payload = ast_rtp_codecs_payload_lookup(ast_rtp_instance_get_codecs(instance), AST_RTP_CN);

	level = 127 - (level & 0x7f);
	
	/* This is not related to CNG...
		rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, 500000));
	*/

	/* Get a pointer to the header */
	rtpheader = (unsigned int *)data;
	rtpheader[0] = htonl((2 << 30) | (1 << 23) | (payload.code << 16) | (rtp->seqno++));
	rtpheader[1] = htonl(rtp->lastts);
	rtpheader[2] = htonl(rtp->ssrc); 
	data[12] = level;

	res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 1, 0, &remote_address);

	if (res < 0) {
		ast_log(LOG_ERROR, "RTP Comfort Noise Transmission error to %s: %s\n", ast_sockaddr_stringify(&remote_address), strerror(errno));
	} else if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent Comfort Noise RTP packet to %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6u)\n",
				ast_sockaddr_stringify(&remote_address),
				AST_RTP_CN, rtp->seqno, rtp->lastdigitts, res - hdrlen);
	}

	return res;
}

/*! \brief Check if rtp stream is active */
static int ast_rtp_isactive(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->isactive ? 0 : 1;
}

/*! \brief Basically add SSRC */
static int add_sdes_header(struct ast_rtp *rtp, unsigned int *rtcp_packet, int len)
{
	/* 2 is version, 1 is number of chunks, then RTCP packet type (SDES) and length */
	*rtcp_packet = htonl((2 << 30) | (1 << 24) | (RTCP_PT_SDES << 16) | ((len/4)-1));

	rtcp_packet++;	/* Move 32 bits ahead for the header */
	*rtcp_packet = htonl(rtp->ssrc);               /* Our SSRC */
	rtcp_packet ++;

	/* Header + SSRC */
	return len + 8;
}

static int add_sdes_bodypart(struct ast_rtp *rtp, unsigned int *rtcp_packet, int len, int type)
{
	int cnamelen;
	int sdeslen = 0;
	char *sdes;

	sdes = (char *) rtcp_packet;
	switch (type) {
	case SDES_CNAME:
		cnamelen = (int) rtp->rtcp->ourcnamelength;

		*sdes = SDES_CNAME;
		sdes++;
		*sdes = (char) cnamelen;
		sdes++;
		strncpy(sdes, rtp->rtcp->ourcname, cnamelen);	/* NO terminating 0 */

		/* THere must be a multiple of four bytes in the packet */
		sdeslen = cnamelen;
		break;
	case SDES_END:
		*sdes = SDES_END;
		sdes++;
		*sdes = (char) 0;
		sdes++;
		sdeslen = 2;
	}
	len += sdeslen + (sdeslen % 4 == 0 ? 0 : 4 - (sdeslen % 4)) ;

	return len;
}

/*! \brief Send emtpy RTCP receiver's report and SDES message 
 	Mainly used to open NAT sessions  */
static int ast_rtcp_write_empty_frame(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	char bdata[512];
	unsigned int *rtcpheader, *start;
	int fd, len, res;

	if (!rtp || !rtp->rtcp) {
		return 0;
	} 
	ast_debug(1,  "************ ---- About to send empty RTCP packet\n");
	fd = rtp->rtcp->s;
	
	if (fd == -1) {
		ast_debug(1, "--- No file descriptor to use \n");
	}
	
	if (!ast_sockaddr_isnull(&rtp->rtcp->them)) { /* This'll stop rtcp for this rtp session */
		ast_verbose("RTCP SR transmission error, rtcp halted\n");
		AST_SCHED_DEL(rtp->sched, rtp->rtcp->schedid);
		return 0;
	}
	if (rtcp_debug_test_addr(&rtp->rtcp->them)) {
		ast_debug(1,  "---- About to send empty RTCP packet\n");
	}
	rtcpheader = (unsigned int *)bdata;
	/* Add a RR header with no reports (chunks = 0) - The RFC says that it's always needed 
		first in a compound packet.
	 */
	rtcpheader[0] = htonl((2 << 30) | (0 << 24) | (RTCP_PT_RR << 16) | 1);
	rtcpheader[1] = htonl(rtp->ssrc);
	len = 8;
	start = &rtcpheader[len/4];
	len +=8; /* SKip header for now */
	len = add_sdes_bodypart(rtp, &rtcpheader[len/4], len, SDES_CNAME);
	len = add_sdes_bodypart(rtp, &rtcpheader[len/4], len, SDES_END);
	/* Now, add header when we know the actual length */
	add_sdes_header(rtp, start, len);

	res = sendto(fd, (unsigned int *)rtcpheader, len, 0, (struct sockaddr *)&rtp->rtcp->them, sizeof(rtp->rtcp->them));

	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP RR transmission error, rtcp halted: %s\n",strerror(errno));
		/* Remove the scheduler */
		AST_SCHED_DEL(rtp->sched, rtp->rtcp->schedid);
		return 0;
	}

	rtp->rtcp->rr_count++;

	if (rtcp_debug_test_addr(&rtp->rtcp->them)) {
		ast_verbose("\n* Sending Empty RTCP RR to %s  Our SSRC: %u\n",
			ast_sockaddr_stringify(&rtp->rtcp->them),
			rtp->ssrc);
	}

	return res;
}

static char *rtp_do_debug_ip(struct ast_cli_args *a)
{
	char *arg = ast_strdupa(a->argv[4]);
	char *debughost = NULL;
	char *debugport = NULL;

	if (!ast_sockaddr_parse(&rtpdebugaddr, arg, 0) || !ast_sockaddr_split_hostport(arg, &debughost, &debugport, 0)) {
		ast_cli(a->fd, "Lookup failed for '%s'\n", arg);
		return CLI_FAILURE;
	}
	rtpdebugport = (!ast_strlen_zero(debugport) && debugport[0] != '0');
	ast_cli(a->fd, "RTP Debugging Enabled for address: %s\n", ast_sockaddr_stringify(&rtpdebugaddr));
	rtpdebug = 1;
	return CLI_SUCCESS;
}

static char *rtcp_do_debug_ip(struct ast_cli_args *a)
{
	char *arg = ast_strdupa(a->argv[4]);
	char *debughost = NULL;
	char *debugport = NULL;

	if (!ast_sockaddr_parse(&rtcpdebugaddr, arg, 0) || !ast_sockaddr_split_hostport(arg, &debughost, &debugport, 0)) {
		ast_cli(a->fd, "Lookup failed for '%s'\n", arg);
		return CLI_FAILURE;
	}
	rtcpdebugport = (!ast_strlen_zero(debugport) && debugport[0] != '0');
	ast_cli(a->fd, "RTCP Debugging Enabled for address: %s\n",
		ast_sockaddr_stringify(&rtcpdebugaddr));
	rtcpdebug = 1;
	return CLI_SUCCESS;
}

static char *handle_cli_rtp_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtp set debug {on|off|ip}";
		e->usage =
			"Usage: rtp set debug {on|off|ip host[:port]}\n"
			"       Enable/Disable dumping of all RTP packets. If 'ip' is\n"
			"       specified, limit the dumped packets to those to and from\n"
			"       the specified 'host' with optional port.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == e->args) { /* set on or off */
		if (!strncasecmp(a->argv[e->args-1], "on", 2)) {
			rtpdebug = 1;
			memset(&rtpdebugaddr, 0, sizeof(rtpdebugaddr));
			ast_cli(a->fd, "RTP Debugging Enabled\n");
			return CLI_SUCCESS;
		} else if (!strncasecmp(a->argv[e->args-1], "off", 3)) {
			rtpdebug = 0;
			ast_cli(a->fd, "RTP Debugging Disabled\n");
			return CLI_SUCCESS;
		}
	} else if (a->argc == e->args +1) { /* ip */
		return rtp_do_debug_ip(a);
	}

	return CLI_SHOWUSAGE;   /* default, failure */
}

static char *handle_cli_rtcp_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtcp set debug {on|off|ip}";
		e->usage =
			"Usage: rtcp set debug {on|off|ip host[:port]}\n"
			"       Enable/Disable dumping of all RTCP packets. If 'ip' is\n"
			"       specified, limit the dumped packets to those to and from\n"
			"       the specified 'host' with optional port.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == e->args) { /* set on or off */
		if (!strncasecmp(a->argv[e->args-1], "on", 2)) {
			rtcpdebug = 1;
			memset(&rtcpdebugaddr, 0, sizeof(rtcpdebugaddr));
			ast_cli(a->fd, "RTCP Debugging Enabled\n");
			return CLI_SUCCESS;
		} else if (!strncasecmp(a->argv[e->args-1], "off", 3)) {
			rtcpdebug = 0;
			ast_cli(a->fd, "RTCP Debugging Disabled\n");
			return CLI_SUCCESS;
		}
	} else if (a->argc == e->args +1) { /* ip */
		return rtcp_do_debug_ip(a);
	}

	return CLI_SHOWUSAGE;   /* default, failure */
}

static char *handle_cli_rtcp_set_stats(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtcp set stats {on|off}";
		e->usage =
			"Usage: rtcp set stats {on|off}\n"
			"       Enable/Disable dumping of RTCP stats.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != e->args)
		return CLI_SHOWUSAGE;

	if (!strncasecmp(a->argv[e->args-1], "on", 2))
		rtcpstats = 1;
	else if (!strncasecmp(a->argv[e->args-1], "off", 3))
		rtcpstats = 0;
	else
		return CLI_SHOWUSAGE;

	ast_cli(a->fd, "RTCP Stats %s\n", rtcpstats ? "Enabled" : "Disabled");
	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_rtp[] = {
	AST_CLI_DEFINE(handle_cli_rtp_set_debug,  "Enable/Disable RTP debugging"),
	AST_CLI_DEFINE(handle_cli_rtcp_set_debug, "Enable/Disable RTCP debugging"),
	AST_CLI_DEFINE(handle_cli_rtcp_set_stats, "Enable/Disable RTCP stats"),
};

static int rtp_reload(int reload)
{
	struct ast_config *cfg;
	const char *s;
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

	cfg = ast_config_load2("rtp.conf", "rtp", config_flags);
	if (cfg == CONFIG_STATUS_FILEMISSING || cfg == CONFIG_STATUS_FILEUNCHANGED || cfg == CONFIG_STATUS_FILEINVALID) {
		return 0;
	}

	rtpstart = DEFAULT_RTP_START;
	rtpend = DEFAULT_RTP_END;
	dtmftimeout = DEFAULT_DTMF_TIMEOUT;
	strictrtp = STRICT_RTP_OPEN;
	learning_min_sequential = DEFAULT_LEARNING_MIN_SEQUENTIAL;
	if (cfg) {
		if ((s = ast_variable_retrieve(cfg, "general", "rtpstart"))) {
			rtpstart = atoi(s);
			if (rtpstart < MINIMUM_RTP_PORT)
				rtpstart = MINIMUM_RTP_PORT;
			if (rtpstart > MAXIMUM_RTP_PORT)
				rtpstart = MAXIMUM_RTP_PORT;
		}
		if ((s = ast_variable_retrieve(cfg, "general", "rtpend"))) {
			rtpend = atoi(s);
			if (rtpend < MINIMUM_RTP_PORT)
				rtpend = MINIMUM_RTP_PORT;
			if (rtpend > MAXIMUM_RTP_PORT)
				rtpend = MAXIMUM_RTP_PORT;
		}
		if ((s = ast_variable_retrieve(cfg, "general", "rtcpinterval"))) {
			rtcpinterval = atoi(s);
			if (rtcpinterval == 0)
				rtcpinterval = 0; /* Just so we're clear... it's zero */
			if (rtcpinterval < RTCP_MIN_INTERVALMS)
				rtcpinterval = RTCP_MIN_INTERVALMS; /* This catches negative numbers too */
			if (rtcpinterval > RTCP_MAX_INTERVALMS)
				rtcpinterval = RTCP_MAX_INTERVALMS;
		}
		if ((s = ast_variable_retrieve(cfg, "general", "rtpchecksums"))) {
#ifdef SO_NO_CHECK
			nochecksums = ast_false(s) ? 1 : 0;
#else
			if (ast_false(s))
				ast_log(LOG_WARNING, "Disabling RTP checksums is not supported on this operating system!\n");
#endif
		}
		if ((s = ast_variable_retrieve(cfg, "general", "dtmftimeout"))) {
			dtmftimeout = atoi(s);
			if ((dtmftimeout < 0) || (dtmftimeout > 64000)) {
				ast_log(LOG_WARNING, "DTMF timeout of '%d' outside range, using default of '%d' instead\n",
					dtmftimeout, DEFAULT_DTMF_TIMEOUT);
				dtmftimeout = DEFAULT_DTMF_TIMEOUT;
			};
		}
		if ((s = ast_variable_retrieve(cfg, "general", "strictrtp"))) {
			strictrtp = ast_true(s);
		}
		if ((s = ast_variable_retrieve(cfg, "general", "probation"))) {
			if ((sscanf(s, "%d", &learning_min_sequential) <= 0) || learning_min_sequential <= 0) {
				ast_log(LOG_WARNING, "Value for 'probation' could not be read, using default of '%d' instead\n",
					DEFAULT_LEARNING_MIN_SEQUENTIAL);
			}
		}
		ast_config_destroy(cfg);
	}
	if (rtpstart >= rtpend) {
		ast_log(LOG_WARNING, "Unreasonable values for RTP start/end port in rtp.conf\n");
		rtpstart = DEFAULT_RTP_START;
		rtpend = DEFAULT_RTP_END;
	}
	ast_verb(2, "RTP Allocating from port range %d -> %d\n", rtpstart, rtpend);
	return 0;
}

static int reload_module(void)
{
	rtp_reload(1);
	return 0;
}

static int load_module(void)
{
	if (ast_rtp_engine_register(&asterisk_rtp_engine)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	if (ast_cli_register_multiple(cli_rtp, ARRAY_LEN(cli_rtp))) {
		ast_rtp_engine_unregister(&asterisk_rtp_engine);
		return AST_MODULE_LOAD_DECLINE;
	}

	rtp_reload(0);

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_rtp_engine_unregister(&asterisk_rtp_engine);
	ast_cli_unregister_multiple(cli_rtp, ARRAY_LEN(cli_rtp));

	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Asterisk RTP Stack",
		.load = load_module,
		.unload = unload_module,
		.reload = reload_module,
		.load_pri = AST_MODPRI_CHANNEL_DEPEND,
		);
