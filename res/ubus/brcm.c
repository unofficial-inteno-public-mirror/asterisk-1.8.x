/*
 * brcm.c
 *
 *  Created on: Mar 12, 2015
 *      Author: kj
 */

#include "brcm.h"

static BRCM_PORT_MAP ports[] =
{
	{"brcm0",	BRCM_PORT0,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm1",	BRCM_PORT1,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm2",	BRCM_PORT2,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm3",	BRCM_PORT3,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm4",	BRCM_PORT4,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"brcm5",	BRCM_PORT5,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	//Add other ports here as needed
	{"port_all",BRCM_PORT_ALL,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
	{"-",		BRCM_PORT_UNKNOWN,	0,	{ {"ONHOOK"}, {"ONHOOK"} }, NULL },
};

void brcm_port_init_all(BRCM_PORT_MAP *brcm_ports)
{
	BRCM_PORT_MAP *tmp = ports;

	while (tmp->port != BRCM_PORT_UNKNOWN) {

		strcpy(brcm_ports->name, tmp->name);
		brcm_ports->off_hook = tmp->off_hook;
		brcm_ports->port = tmp->port;
		strcpy(brcm_ports->sub[0].state, tmp->sub[0].state);
		strcpy(brcm_ports->sub[1].state, tmp->sub[1].state);
		brcm_ports->ubus_object = tmp->ubus_object;

		brcm_ports++;
		tmp++;
	}
}

int brcm_subchannel_active(const BRCM_PORT_MAP *port)
{
	int subchannel_id;
	for (subchannel_id=0; subchannel_id<2; subchannel_id++) {
		if (strcmp(port->sub[subchannel_id].state, "ONHOOK") && strcmp(port->sub[subchannel_id].state, "CALLENDED")) {
			return 1;
		}
		return 0;
	}

	return 0;
}
