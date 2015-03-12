/*
 * brcm.h
 *
 *  Created on: Mar 12, 2015
 *      Author: kj
 */

#ifndef BRCM_H_
#define BRCM_H_

#include <string.h>

//These are used to map SIP peer name to a port
//CPE may be configured to share the same SIP-account for several ports or to use individual accounts
typedef enum BRCM_PORT
{
	BRCM_PORT0 = 0,
	BRCM_PORT1,
	BRCM_PORT2,
	BRCM_PORT3,
	BRCM_PORT4,
	BRCM_PORT5,
	BRCM_PORT_ALL,
	BRCM_PORT_UNKNOWN
} BRCM_PORT;

typedef struct BRCM_SUBCHANNEL
{
	char		state[80];
} BRCM_SUBCHANNEL;

#define BRCM_MAX_PORT_NAME	10
typedef struct BRCM_PORT_MAP
{
	char				name[BRCM_MAX_PORT_NAME];
	BRCM_PORT			port;
	int					off_hook;
	BRCM_SUBCHANNEL		sub[2]; //TODO define for number of subchannels?
	struct ubus_object *ubus_object;
} BRCM_PORT_MAP;

void brcm_port_init_all(BRCM_PORT_MAP *ports);

int brcm_subchannel_active(const BRCM_PORT_MAP *port);

#endif /* BRCM_H_ */
