#ifndef BRCM_DECT_H
#define BRCM_DECT_H



#ifndef RSOFFSETOF
/*! \def RSOFFSETOF(type, field)
 * Computes the byte offset of \a field from the beginning of \a type. */
#define RSOFFSETOF(type, field) ((size_t)(&((type*)0)->field))
#endif

#define SINGLE_CODECLIST_LENGTH         (sizeof(ApiCodecListType))
#define NBWB_CODECLIST_LENGTH           (SINGLE_CODECLIST_LENGTH + sizeof(ApiCodecInfoType))



/* Mapping of DTMF to char/name */
typedef struct DTMF_CHARNAME_MAP
{
	EPEVT	event;
	char	name[12];
	char	c;
} DTMF_CHARNAME_MAP;


void *brcm_monitor_dect(void *data);

EPSTATUS vrgEndptSendCasEvtToEndpt( ENDPT_STATE *endptState, CAS_CTL_EVENT_TYPE eventType, CAS_CTL_EVENT event );
EPSTATUS vrgEndptConsoleCmd( ENDPT_STATE *endptState, EPCONSOLECMD cmd, EPCMD_PARMS *consoleCmdParams );
void dectSetupPingingCall(int handset);
void dectDrvWrite(void *data, int size);

void dectRingHandSet( int destHandset, int dspChannel);
static void connect_cfm(unsigned char *buf);
static void alert_ind(unsigned char *buf);
static void connect_ind(unsigned char *buf);
static void nvs_update_ind(unsigned char *mail);
static void dectNvsCtlGetData( unsigned char *pNvsData);


#endif
