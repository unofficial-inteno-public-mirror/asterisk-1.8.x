#include <endpointdrv.h>

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
#define DTMF 128
#define RTCP 200

#define NOT_INITIALIZED -1
#define EPSTATUS_DRIVER_ERROR -1
#define MAX_NUM_LINEID 3
#define PACKET_BUFFER_SIZE 1024
#define NUM_SUBCHANNELS 2


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
	struct ast_channel *owner;	/* Channel we belong to, possibly NULL */
	int connection_id;		/* Current connection id, may be -1 */
	unsigned int channel_state;	/* Channel states */
	unsigned int connection_init;	/* State for endpoint id connection initialization */
	struct ast_frame fr;		/* Frame */
	unsigned int sequence_number;	/* Endpoint RTP sequence number state */
	unsigned int time_stamp;	/* Endpoint RTP time stamp state */
	unsigned int ssrc;		/* Endpoint RTP synchronization source */
	int codec;			/* Used codec */
	struct brcm_pvt *parent;	/* brcm_line owning this subchannel */
	int timer_id;			/* Current timer id, -1 if no active timer*/
};

static struct brcm_pvt {
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
	unsigned int last_dtmf_ts;		/* Timer for initiating dialplan extention lookup */
	unsigned int last_early_onhook_ts;	/* For detecting hook flash */
	int	endpoint_type;				/* Type of the endpoint fxs, fxo, dect */
	char autodial[AST_MAX_EXTENSION];	/* Extension to automatically dial when the phone is of hook */

	struct brcm_subchannel *sub[NUM_SUBCHANNELS];	/* List of sub-channels, needed for callwaiting and 3-way support */
	int hf_detected;			/* Hook flash detected */
	dialtone_state dialtone;		/* Set by manager command */
} *iflist = NULL;

enum rtp_type {
	BRCM_UNKNOWN,
	BRCM_AUDIO,
	BRCM_DTMFBE,
	BRCM_DTMF,
	BRCM_RTCP,
};


/* function declaration */

EPSTATUS vrgEndptDriverOpen(void);
EPSTATUS vrgEndptDriverClose(void);
EPSTATUS ovrgEndptSignal(ENDPT_STATE *endptState, int cnxId, EPSIG signal, unsigned int value, int duration, int period, int repetition);
EPSTATUS vrgEndptProvGet( int line, EPPROV provItemId, void* provItemValue, int provItemLength );
EPSTATUS vrgEndptProvSet( int line, EPPROV provItemId, void* provItemValue, int provItemLength );

static void brcm_generate_rtp_packet(struct brcm_subchannel *p, UINT8 *packet_buf, int type);
static int brcm_create_connection(struct brcm_subchannel *p);
static int brcm_mute_connection(struct brcm_subchannel *p);
static int brcm_unmute_connection(struct brcm_subchannel *p);
static int brcm_close_connection(struct brcm_subchannel *p);
static int brcm_create_conference(struct brcm_pvt *p);
static int brcm_stop_conference(struct brcm_subchannel *p);
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
static int brcm_senddigit_begin(struct ast_channel *ast, char digit);
static int brcm_senddigit_end(struct ast_channel *ast, char digit, unsigned int duration);
static int brcm_get_endpoints_count(void);
static void brcm_create_fxs_endpoints(void);
static void brcm_provision_endpoints(void);
int brcm_signal_dialtone(struct brcm_pvt *p);
int brcm_stop_dialtone(struct brcm_pvt *p);
int brcm_signal_ringing(struct brcm_pvt *p);
int brcm_stop_ringing(struct brcm_pvt *p);
int brcm_signal_ringing_callerid_pending(struct brcm_pvt *p);
int brcm_stop_ringing_callerid_pending(struct brcm_pvt *p);
int brcm_signal_callwaiting(const struct brcm_pvt *p);
int brcm_stop_callwaiting(const struct brcm_pvt *p);
int brcm_signal_callerid(struct brcm_subchannel *sub);
int brcm_signal_dtmf(struct brcm_subchannel *sub, char digit);
int brcm_stop_dtmf(struct brcm_subchannel *sub, char digit);
static int brcm_in_call(const struct brcm_pvt *p);
static int brcm_in_callwaiting(const struct brcm_pvt *p);
static int brcm_in_onhold(const struct brcm_pvt *p);
static struct brcm_subchannel *brcm_get_idle_subchannel(const struct brcm_pvt *p);
static struct brcm_subchannel* brcm_get_active_subchannel(const struct brcm_pvt *p);
static void brcm_subchannel_set_state(struct brcm_subchannel *sub, enum channel_state state);
