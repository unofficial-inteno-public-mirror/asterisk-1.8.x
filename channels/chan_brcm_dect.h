#ifndef CHAN_BRCM_DECT_H
#define CHAN_BRCM_DECT_H


#define CID_MAX_LEN 40
#define MAX_NR_HANDSETS 10

void *brcm_monitor_dect(void *data);

EPSTATUS vrgEndptSendCasEvtToEndpt( ENDPT_STATE *endptState, CAS_CTL_EVENT_TYPE eventType, CAS_CTL_EVENT event );
EPSTATUS vrgEndptConsoleCmd( ENDPT_STATE *endptState, EPCONSOLECMD cmd, EPCMD_PARMS *consoleCmdParams );

int dect_release(struct brcm_pvt *p);
int dect_signal_ringing(struct brcm_pvt *p);
int dect_signal_ringing_callerid_pending(struct brcm_pvt *p);
int dect_signal_callerid(const struct ast_channel *chan, struct brcm_subchannel *s);

void dect_ring_handset(int handset);

#endif /* CHAN_BRCM_DECT_H */
