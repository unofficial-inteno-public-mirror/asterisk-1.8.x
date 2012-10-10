#include <endpointdrv.h>

/* Change this value when needed */
#define CHANNEL_VERSION "1.2"

#define DEFAULT_CALLER_ID "Unknown"
#define PHONE_MAX_BUF 480
#define DEFAULT_GAIN 0x100

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
#define MAX_NUM_LINEID 2
#define PACKET_BUFFER_SIZE 1024

#define NOT_INITIALIZED -1
#define EPSTATUS_DRIVER_ERROR -1
#define MAX_NUM_LINEID 2


enum channel_state {
    ONHOOK,
    OFFHOOK,
    DIALING,
    INCALL,
    ANSWER,
	CALLENDED,
	RINGING,
};

enum endpoint_type {
	FXS,
	FXO,
	DECT,
};


static struct brcm_pvt {
	ast_mutex_t lock;
	int fd;							/* Raw file descriptor for this device */
	struct ast_channel *owner;		/* Channel we belong to, possibly NULL */
	int connection_id;				/* Id of the connection, used to map the correct port, lineid matching parameter */
	char dtmfbuf[AST_MAX_EXTENSION];/* DTMF buffer per channel */
	int dtmf_len;					/* Length of DTMF buffer */
	int dtmf_first;					/* DTMF control state, button pushes generate 2 events, one on button down and one on button up */
	format_t lastformat;            /* Last output format */
	format_t lastinput;             /* Last input format */
	struct brcm_pvt *next;			/* Next channel in list */
	struct ast_frame fr;			/* Frame */
	char offset[AST_FRIENDLY_OFFSET];
	char buf[PHONE_MAX_BUF];					/* Static buffer for reading frames */
	int txgain, rxgain;             /* gain control for playing, recording  */
									/* 0x100 - 1.0, 0x200 - 2.0, 0x80 - 0.5 */
	int silencesupression;
	char context[AST_MAX_EXTENSION];
	char obuf[PHONE_MAX_BUF * 2];
	char ext[AST_MAX_EXTENSION];
	char language[MAX_LANGUAGE];
	char cid_num[AST_MAX_EXTENSION];
	char cid_name[AST_MAX_EXTENSION];
	unsigned int last_dtmf_ts;		/* Timer for initiating dialplan extention lookup */
	unsigned int channel_state;		/* Channel states */
	unsigned int connection_init;	/* State for endpoint id connection initialization */
	unsigned int last_dialtone_ts;	/* Timestamp to send a continious dialtone */
	int	endpoint_type;				/* Type of the endpoint fxs, fxo, dect */
	unsigned int sequence_number;	/* Endpoint RTP sequence number state */
	unsigned int time_stamp;		/* Endpoint RTP time stamp state */
	unsigned int ssrc;				/* Endpoint RTP synchronization source */
	int codec;						/* Used codec */
	unsigned int dt_counter;		/* dialtone counter */
	char autodial[AST_MAX_EXTENSION];	/* Extension to automatically dial when the phone is of hook */
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

static void brcm_generate_rtp_packet(struct brcm_pvt *p, UINT8 *packet_buf, int type);
static int brcm_create_connection(struct brcm_pvt *p);
static int brcm_close_connection(struct brcm_pvt *p);
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
static int brcm_get_endpoints_count(void);
static void brcm_create_fxs_endpoints(void);
int brcm_signal_ringing(struct brcm_pvt *p);
int brcm_stop_ringing(struct brcm_pvt *p);
int brcm_signal_ringing_callerid_pending(struct brcm_pvt *p);
int brcm_stop_ringing_callerid_pending(struct brcm_pvt *p);
int brcm_signal_callerid(struct brcm_pvt *p);
