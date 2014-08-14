/* Inteno AB, Stockholm, Sweden
 * Channel for Broadcom FXS ports and Dect interface
 */

#ifndef CHAN_BRCM_H
#define CHAN_BRCM_H

#include <endpointdrv.h>
#include <pcmshimdrv.h>

/* Change this value when needed */
#define CHANNEL_VERSION "1.2"

#define DEFAULT_CALLER_ID "Unknown"
#define PHONE_MAX_BUF 480

/* Gain min/max values */
#define GAIN_MIN -96
#define GAIN_MAX 32
#define GAIN_DEFAULT 0

#define TIMEMSEC 1000

#define PCMU 0
#define G726 2
#define G723 4
#define PCMA 8
#define G729 18
#define DTMF_PAYLOAD 101
#define DTMF 128
#define RTCP 200

#define NOT_INITIALIZED -1
#define EPSTATUS_DRIVER_ERROR -1
#define MAX_NUM_LINEID 30
#define PACKET_BUFFER_SIZE 1024
#define NUM_SUBCHANNELS 2

#define BEGIN 0
#define CONT  1
#define END   2

enum channel_state {
    ONHOOK,
    OFFHOOK,
    DIALING,
    CALLING,
    INCALL,
    ANSWER,
	CALLENDED,
	RINGING,
	CALLWAITING,
	ONHOLD,
	TRANSFERING,
	RINGBACK,
	AWAITONHOOK,
	ALLOCATED,
};

enum endpoint_type {
	FXS,
	FXO,
	DECT,
};

typedef enum dialtone_state {
	DIALTONE_OFF = 0,
	DIALTONE_ON,
	DIALTONE_CONGESTION,
	DIALTONE_UNKNOWN,
	DIALTONE_LAST,
} dialtone_state;

struct brcm_subchannel {
	int id;
	struct ast_channel *owner;		/* Channel we belong to, possibly NULL */
	int connection_id;		/* Current connection id, may be -1 */
	unsigned int channel_state;	/* Channel states */
	unsigned int connection_init;	/* State for endpoint id connection initialization */
	struct ast_frame fr;		/* Frame */
	unsigned int sequence_number;	/* Endpoint RTP sequence number state */
	unsigned int time_stamp;	/* Endpoint RTP time stamp state */
	unsigned int period;		/* Endpoint RTP period */
	unsigned int ssrc;		/* Endpoint RTP synchronization source */
	int codec;			/* Used codec */
	struct brcm_pvt *parent;	/* brcm_line owning this subchannel */
	int cw_timer_id;			/* Current call waiting timer id, -1 if no active timer */
	int cw_rejected;            /* True if a previous waiting call has been rejected during current call */
	int r4_hangup_timer_id;		/* Current R4 hangup timer id, -1 if no active timer */
	int dtmf_duration;		/* Duration of the DTMF currently sending. Should be zero when not sending */
	int dtmf_lastwasend;		/* A marker to suppress the end messages. Brcm correctly sends three of them
					   in sequence and we only need to react on the first one */
	int dtmf_sending;		/* A marker if we are sending DTMF or not */
	int dtmf_timestamp;		/* When a dtmf begin is detected save and use this timestamp for the rest of the dtmf packets */
	struct timeval dtmf_tv;         /*!< The time that an in process digit began, or the last digit ended */
	int conference_initiator;       /* True if this subchannel is the original leg in a 3-way conference */
};


struct brcm_channel_tech {
	int (* signal_ringing)(struct brcm_pvt *p);
	int (* signal_ringing_callerid_pending)(struct brcm_pvt *p);
	int (* signal_callerid)(const struct ast_channel *chan, struct brcm_subchannel *s);
	int (* stop_ringing)(struct brcm_pvt *p);
	int (* stop_ringing_callerid_pending)(struct brcm_pvt *p);
};


struct brcm_pvt {
	ast_mutex_t lock;
	int fd;							/* Raw file descriptor for this device */
	int line_id;				/* Maps to the correct port */
	char dtmfbuf[AST_MAX_EXTENSION];/* DTMF buffer per channel */
	int dtmf_len;					/* Length of DTMF buffer */
	int dtmf_first;					/* DTMF control state, button pushes generate 2 events, one on button down and one on button up */
	format_t lastformat;            /* Last output format */
	format_t lastinput;             /* Last input format */
	struct brcm_pvt *next;			/* Next channel in list */
	char offset[AST_FRIENDLY_OFFSET];
	char buf[PHONE_MAX_BUF];					/* Static buffer for reading frames */
	int txgain, rxgain;             /* gain control for playing, recording  */
									/* 0x100 - 1.0, 0x200 - 2.0, 0x80 - 0.5 */
	int silencesupression;
	char context_direct[AST_MAX_EXTENSION];
	char context[AST_MAX_EXTENSION];
	char obuf[PHONE_MAX_BUF * 2];
	char ext[AST_MAX_EXTENSION];
	char language[MAX_LANGUAGE];
	char cid_num[AST_MAX_EXTENSION];
	char cid_name[AST_MAX_EXTENSION];
	unsigned int last_early_onhook_ts;	/* For detecting hook flash */
	int	endpoint_type;				/* Type of the endpoint fxs, fxo, dect */

	struct brcm_subchannel *sub[NUM_SUBCHANNELS];	/* List of sub-channels, needed for callwaiting and 3-way support */
	int hf_detected;			/* Hook flash detected */
	dialtone_state dialtone;		/* Set by manager command */
	struct brcm_channel_tech *tech;
	int dialtone_extension_cb_id;
	int *dialtone_extension_cb_data;
	char dialtone_extension_hint_context[AST_MAX_EXTENSION];
	char dialtone_extension_hint[AST_MAX_EXTENSION];

	int interdigit_timer_id;		/* Id of timer that tracks interdigit timeout */
	int autodial_timer_id;			/* Id of timer that tracks autodial timeout */
	int dialtone_timeout_timer_id;	/* Id of timer that tracks dialtone timeout */
};

enum rtp_type {
	BRCM_UNKNOWN,
	BRCM_AUDIO,
	BRCM_DTMFBE,
	BRCM_DTMF,
	BRCM_RTCP,
};



/* Mapping of DTMF to char/name/intval */
typedef struct DTMF_CHARNAME_MAP
{
	EPEVT	event;
	char	name[12];
	char	c;
	int		i;
} DTMF_CHARNAME_MAP;




/* List of supported country name, ISO 3166-1 alpha-3 codes */
typedef struct COUNTRY_TABLE
{
	VRG_COUNTRY	vrgCountry;
	char		isoCode[3];
} COUNTRY_MAP;


typedef struct DIALTONE_MAP
{
	dialtone_state	state;
	char		str[11];
} DIALTONE_MAP;

static const DIALTONE_MAP dialtone_map[] =
{
	{DIALTONE_OFF,		"off"},
	{DIALTONE_ON,		"on"},
	{DIALTONE_CONGESTION,	"congestion"},
	{DIALTONE_UNKNOWN,	"unknown"},
	{DIALTONE_LAST,		"-"},
};

/* Struct for individual endpoint settings */
typedef struct {
	int silence;
	char language[MAX_LANGUAGE];
	char cid_num[AST_MAX_EXTENSION];
	char cid_name[AST_MAX_EXTENSION];
	char context_direct[AST_MAX_EXTENSION]; //Context that will be checked for exact matches
	char context[AST_MAX_EXTENSION]; //Default context for dialtone mode
	char autodial_ext[AST_MAX_EXTENSION];
	int autodial_timeoutmsec;
	int echocancel;
	int txgain;
	int rxgain;
	int dtmf_relay;
	int dtmf_short;
	int dtmf_compatibility;
	int codec_list[6];
	int codec_nr;
	format_t capability;
	int rtp_payload_list[6];
	int ringsignal;
	int timeoutmsec;
	CODEC_PKT_PERIOD period;
	int comfort_noise;
	VRG_UINT32 jitterFixed;
	VRG_UINT32 jitterMin;
	VRG_UINT32 jitterMax;
	VRG_UINT32 jitterTarget;
	int hangup_xfer;
	char dialtone_extension_hint_context[AST_MAX_EXTENSION];
	char dialtone_extension_hint[AST_MAX_EXTENSION];
	int dialtone_timeoutmsec;
	int callwaiting;
	int clir;
} line_settings;


/* Caller ID */
#define CLID_MAX_DATE	10
#define CLID_MAX_NUMBER	16
#define CLID_MAX_NAME	16
typedef struct CLID_STRING
{
	char date[CLID_MAX_DATE];
	char number_name[CLID_MAX_NUMBER + CLID_MAX_NAME + 4]; // 4 = comma, quotation marks and null terminator
} CLID_STRING;


/* Global jitterbuffer configuration - by default, jb is disabled */
static struct ast_jb_conf default_jbconf =
{
	.flags = 0,
	.max_size = -1,
	.resync_threshold = -1,
	.impl = "",
	.target_extra = -1,
};


#define DEFAULT_CALL_WAITING_TIMEOUT 24 // In seconds, Telia uses 24s

#define DEFAULT_R4_HANGUP_TIMEOUT 5000 // In milliseconds
#define DEFAULT_MAX_HOOKFLASH_DELAY 500	// Max delay between early onhook and early offhook (in ms)


/* function declaration */

EPSTATUS vrgEndptDriverOpen(void);
EPSTATUS vrgEndptDriverClose(void);
EPSTATUS ovrgEndptSignal(ENDPT_STATE *endptState, int cnxId, EPSIG signal, unsigned int value, int duration, int period, int repetition);
EPSTATUS vrgEndptProvGet( int line, EPPROV provItemId, void* provItemValue, int provItemLength );
EPSTATUS vrgEndptProvSet( int line, EPPROV provItemId, void* provItemValue, int provItemLength );

static int cwtimeout_cb(const void *data);
static int r4hanguptimeout_cb(const void *data);
static void brcm_generate_rtp_packet(struct brcm_subchannel *p, UINT8 *packet_buf, int type, int marker, int dtmf_timestamp);
int brcm_create_connection(struct brcm_subchannel *p);
static int brcm_mute_connection(struct brcm_subchannel *p);
static int brcm_unmute_connection(struct brcm_subchannel *p);
static int brcm_close_connection(struct brcm_subchannel *p);
static int brcm_create_conference(struct brcm_pvt *p);
static int brcm_stop_conference(struct brcm_subchannel *p);
static int brcm_finish_transfer(struct ast_channel *owner, struct brcm_subchannel *p, int result);
int endpt_init(void);
int endpt_deinit(void);
void event_loop(void);
static int restart_monitor(void);
static struct ast_channel *brcm_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);
static int brcm_call(struct ast_channel *ast, char *dest, int timeout);
static int brcm_hangup(struct ast_channel *ast);
static int brcm_answer(struct ast_channel *ast);
static struct ast_frame *brcm_read(struct ast_channel *ast);
static int brcm_write(struct ast_channel *ast, struct ast_frame *frame);
static int brcm_send_text(struct ast_channel *ast, const char *text);
static int brcm_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen);
static int brcm_senddigit_begin(struct ast_channel *ast, char digit);
static int brcm_senddigit_continue(struct ast_channel *ast, char digit, unsigned int duration);
static int brcm_senddigit_end(struct ast_channel *ast, char digit, unsigned int duration);
static int brcm_get_endpoints_count(void);
static void brcm_provision_endpoints(void);
static void brcm_create_endpoints(void);
static void brcm_destroy_endpoints(void);
int brcm_signal_dialtone(struct brcm_pvt *p);
int brcm_signal_congestion(struct brcm_pvt *p);
int brcm_stop_dialtone(struct brcm_pvt *p);
int brcm_signal_ringing(struct brcm_pvt *p);
int brcm_stop_ringing(struct brcm_pvt *p);
int brcm_signal_ringing_callerid_pending(struct brcm_pvt *p);
int brcm_stop_ringing_callerid_pending(struct brcm_pvt *p);
int brcm_signal_callwaiting(const struct brcm_pvt *p);
int brcm_stop_callwaiting(const struct brcm_pvt *p);
int brcm_signal_callerid(const struct ast_channel *chan, struct brcm_subchannel *sub);
int brcm_signal_dtmf(struct brcm_subchannel *sub, char digit);
int brcm_signal_dtmf_ingress(struct brcm_subchannel *sub, int digit);
int brcm_stop_dtmf(struct brcm_subchannel *sub, char digit);
static int brcm_in_call(const struct brcm_pvt *p);
static int brcm_in_callwaiting(const struct brcm_pvt *p);
static int brcm_in_onhold(const struct brcm_pvt *p);
struct brcm_subchannel *brcm_get_idle_subchannel(const struct brcm_pvt *p);
struct brcm_subchannel* brcm_get_active_subchannel(const struct brcm_pvt *p);
static void brcm_subchannel_set_state(struct brcm_subchannel *sub, enum channel_state state);
static int brcm_subchannel_is_idle(const struct brcm_subchannel const * const sub);
struct brcm_subchannel *brcm_subchannel_get_peer(const struct brcm_subchannel const * const sub);
struct brcm_pvt* brcm_get_pvt_from_lineid(struct brcm_pvt *p, int line_id);
void handle_dtmf(EPEVT event, struct brcm_subchannel *sub, struct brcm_subchannel *sub_peer, struct ast_channel *owner, struct ast_channel *peer_owner);
void handle_dtmf_calling(struct brcm_subchannel *sub);
void handle_hookflash(struct brcm_subchannel *sub, struct brcm_subchannel *sub_peer, struct ast_channel *owner, struct ast_channel *peer_owner);
void brcm_cancel_dialing_timeouts(struct brcm_pvt *p);

int brcm_should_relay_dtmf(const struct brcm_subchannel *sub);
int get_dtmf_relay_type(struct brcm_subchannel *sub);

#endif /* CHAN_BRCM_H */
