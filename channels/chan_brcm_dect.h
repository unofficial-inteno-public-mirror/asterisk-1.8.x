#ifndef CHAN_BRCM_DECT_H
#define CHAN_BRCM_DECT_H

#include "chan_brcm.h"


#define CID_MAX_LEN 40
#define MAX_NR_HANDSETS 10

extern const struct brcm_channel_tech dect_tech;

void *brcm_monitor_dect(void *data);

#endif /* CHAN_BRCM_DECT_H */
