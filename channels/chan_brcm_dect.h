#ifndef CHAN_BRCM_DECT_H
#define CHAN_BRCM_DECT_H



#ifndef RSOFFSETOF
/*! \def RSOFFSETOF(type, field)
 * Computes the byte offset of \a field from the beginning of \a type. */
#define RSOFFSETOF(type, field) ((size_t)(&((type*)0)->field))
#endif

#define SINGLE_CODECLIST_LENGTH         (sizeof(ApiCodecListType))
#define NBWB_CODECLIST_LENGTH           (SINGLE_CODECLIST_LENGTH + sizeof(ApiCodecInfoType))



#define MAX_MAIL_SIZE 4098

#define PACKET_HEADER \
	uint32_t size; \
	uint32_t type;

struct dect_packet {
	PACKET_HEADER
	uint8_t data[MAX_MAIL_SIZE];
};



typedef struct packet_header {
	PACKET_HEADER
} packet_header_t;


void *brcm_monitor_dect(void *data);

EPSTATUS vrgEndptSendCasEvtToEndpt( ENDPT_STATE *endptState, CAS_CTL_EVENT_TYPE eventType, CAS_CTL_EVENT event );
EPSTATUS vrgEndptConsoleCmd( ENDPT_STATE *endptState, EPCONSOLECMD cmd, EPCMD_PARMS *consoleCmdParams );
void dectSetupPingingCall(int handset);
void dectDrvWrite(void *data, int size);

void dectRingHandSet( int destHandset, int dspChannel, char *cid);
void dect_hangup(int handset);
int dect_signal_ringing(struct brcm_pvt *p);
static void connect_cfm(unsigned char *buf);
static void alert_ind(unsigned char *buf);
static void connect_ind(unsigned char *buf);
static void nvs_update_ind(unsigned char *mail);
static void nvs_get_data( unsigned char *pNvsData);


#endif /* CHAN_BRCM_DECT_H */
