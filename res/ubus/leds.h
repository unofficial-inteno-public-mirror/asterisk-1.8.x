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

struct leds {
	unsigned int voice_led_count; //Number of voice leds on board
	unsigned int fxs_line_count; //Number of FXS ports on board
	unsigned int dect_line_count; //Number of DECT ports on board
	Led* led_config; //Array of led configs (one for each led)
	SIP_PEER *sip_peers;
	BRCM_PORT_MAP *brcm_ports;
	struct ubus_context *ctx;
	struct blob_buf b_led;
	unsigned int brcm_loaded; //True if chan_brcm is loaded
};

struct leds *leds_create(struct ubus_context *ctx,
		SIP_PEER *sip_peers,
		BRCM_PORT_MAP *brcm_ports,
		unsigned int fxs_line_count,
		unsigned int dect_line_count,
		unsigned int brcm_loaded);

void leds_configure(struct leds *leds);

void leds_delete(struct leds *leds);

void leds_manage(struct leds *leds);

void leds_set_brcm_loaded(struct leds *leds, unsigned int);

void leds_ubus_disconnected(struct leds *leds);

#endif /* LEDS_H_ */
