/*
 * leds.h
 *
 *  LED management
 *
 *  Created on: Mar 12, 2015
 *      Author: kj
 */

#ifndef LEDS_H_
#define LEDS_H_

#include <libubus.h>

typedef struct Led Led;
typedef struct SIP_PEER SIP_PEER;
typedef struct BRCM_PORT_MAP BRCM_PORT_MAP;

struct leds;

struct leds *leds_create(struct ubus_context *ctx,
		SIP_PEER *sip_peers,
		BRCM_PORT_MAP *brcm_ports,
		unsigned int fxs_line_count,
		unsigned int dect_line_count,
		unsigned int brcm_loaded);

void leds_configure(struct leds *leds);

void leds_delete(struct leds *leds);

void leds_manage(struct leds *leds);

void leds_ubus_connected(struct leds *leds, struct ubus_context *ctx);

void leds_ubus_disconnected(struct leds *leds);

int leds_dect_line_count(struct leds *leds);

int leds_fxs_line_count(struct leds *leds);

void leds_set_ready(struct leds *leds, unsigned int);

#endif /* LEDS_H_ */
