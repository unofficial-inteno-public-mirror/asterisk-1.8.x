#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * leds.c
 *
 *  LED management
 *
 *  Created on: Mar 12, 2015
 *      Author: kj
 */

#include "leds.h"
#include "brcm.h"
#include "uci.h"
#include "sip.h"

#include <asterisk.h>
#include <asterisk/logger.h>
#include <asterisk/utils.h>
#include <string.h>

struct leds {
	unsigned int voice_led_count; //Number of voice leds on board
	unsigned int fxs_line_count; //Number of FXS ports on board
	unsigned int dect_line_count; //Number of DECT ports on board
	Led* led_config; //Array of led configs (one for each led)
	SIP_PEER *sip_peers;
	BRCM_PORT_MAP *brcm_ports;
	struct ubus_context *ctx;
	struct blob_buf b_led;
	unsigned int ready;
};

typedef enum LED_STATE
{
	LS_OK,
	LS_NOTICE,
	LS_ALERT,
	LS_ERROR,
	LS_OFF,
	LS_UNKNOWN
} LED_STATE;

#define MAX_LED_STATE	10
typedef struct LED_STATE_MAP
{
	LED_STATE	state;
	char		str[MAX_LED_STATE];
} LED_STATE_MAP;

static const LED_STATE_MAP led_states[] =
{
	{LS_OK,		"ok"},
	{LS_NOTICE,	"notice"},
	{LS_ALERT,	"alert"},
	{LS_ERROR,	"error"},
	{LS_OFF,	"off"},
	{LS_UNKNOWN,	"-"},
};

typedef enum LED_NAME
{
	LN_DSL,
	LN_WIFI,
	LN_WPS,
	LN_LAN,
	LN_STATUS,
	LN_DECT,
	LN_TV,
	LN_USB,
	LN_WAN,
	LN_INTERNET,
	LN_VOICE1,
	LN_VOICE2,
	LN_ECO,
	LN_ALL,
	LN_UNKNOWN
} LED_NAME;

#define MAX_LED_NAME	13
typedef struct LED_NAME_MAP
{
	LED_NAME	name;
	char		str[MAX_LED_NAME];
} LED_NAME_MAP;

static const LED_NAME_MAP led_names[]  =
{
	{LN_DSL,		"led.dsl"},
	{LN_WIFI,		"led.wifi"},
	{LN_WPS,		"led.wps"},
	{LN_LAN,		"led.lan"},
	{LN_STATUS,		"led.status"},
	{LN_DECT,		"led.dect"},
	{LN_TV,			"led.tv"},
	{LN_USB,		"led.usb"},
	{LN_WAN,		"led.wan"},
	{LN_INTERNET,	"led.internet"},
	{LN_VOICE1,		"led.voice1"},
	{LN_VOICE2,		"led.voice2"},
	{LN_ECO,		"led.eco"},
	{LN_ALL,		"All"},
	{LN_UNKNOWN,	"-"}
};

typedef struct LED_CURRENT_STATE_MAP
{
	LED_NAME	name;
	LED_STATE	state;
} LED_CURRENT_STATE_MAP;

static LED_CURRENT_STATE_MAP led_current_states[]  =
{
	{LN_VOICE1,		LS_UNKNOWN},
	{LN_VOICE2,		LS_UNKNOWN},
	{LN_UNKNOWN,	LS_UNKNOWN}
};

/*
 * Struct that stores configuration for a LED
 */
typedef struct Led {
	LED_STATE state;
	LED_NAME name;
	int num_ports;
	BRCM_PORT_MAP** ports; //Array of pointers to brcm ports that govern this leds state
	int num_peers;
	SIP_PEER** peers; //Array of pointers to sip peers that govern this leds state
} Led;

/********************/
/* Static functions */
/********************/
static void manage_led(struct leds *leds, LED_NAME led, LED_STATE state);
static void free_led_config(struct leds *leds);
static LED_STATE get_led_state(Led *led);

/********************/
/* Public interface */
/********************/
struct leds *leds_create(struct ubus_context *ctx,
		SIP_PEER *sip_peers,
		BRCM_PORT_MAP *brcm_ports,
		unsigned int fxs_line_count,
		unsigned int dect_line_count,
		unsigned int ready)
{
	struct leds *leds = malloc(sizeof(struct leds));
	memset(leds, 0, sizeof(struct leds));

	leds->ctx = ctx;

	leds->voice_led_count = uci_get_voice_led_count();
	leds->fxs_line_count = fxs_line_count;
	leds->dect_line_count = dect_line_count;

	leds->sip_peers = sip_peers;
	leds->brcm_ports = brcm_ports;

	leds->ready = ready;

	leds_configure(leds);

	return leds;
}

/*
 * leds_configure
 *
 * Configure which lines and peers that should determine the state of the
 * voice led(s). The configuration is then used by manage_leds.
 *
 * led_config is rebuilt whenever a new line config is read from chan_brcm
 */
void leds_configure(struct leds *leds)
{
	if (leds->led_config) {
		free_led_config(leds);
	}

	leds->led_config = calloc(leds->voice_led_count, sizeof(Led));
	int i;

	if (leds->voice_led_count == 1) {
		/*
		 * Single LED - all ports govern status
		 */
		ast_debug(5, "Single LED configuration\n");

		BRCM_PORT_MAP** all_ports = calloc(leds->dect_line_count + leds->fxs_line_count, sizeof(BRCM_PORT_MAP*));
		for (i = 0; i < (leds->dect_line_count + leds->fxs_line_count); i++) {
			all_ports[i] = &leds->brcm_ports[i];
		}
		leds->led_config[0].state = LS_UNKNOWN;
		leds->led_config[0].name = LN_VOICE1;
		leds->led_config[0].ports = all_ports;
		leds->led_config[0].num_ports = leds->dect_line_count + leds->fxs_line_count;
	}
	else if (leds->voice_led_count > 1) {
		/*
		 * Two LEDs, make best use of them!
		 * (Assume two leds, if there are more, we currently do not use them)
		 */
		if (leds->dect_line_count > 0) {
			/*
			 * LED1  = FXS, LED2 = DECT
			 * dects are lower numbered, fxs higher
			 */
			ast_debug(5, "Dual LED configuration, FXS and DECT\n");
			BRCM_PORT_MAP** dect_ports = calloc(leds->dect_line_count, sizeof(BRCM_PORT_MAP*));
			for (i = 0; i < leds->dect_line_count; i++) {
				dect_ports[i] = &leds->brcm_ports[i];
			}
			leds->led_config[1].state = LS_UNKNOWN;
			leds->led_config[1].name = LN_VOICE2;
			leds->led_config[1].ports = dect_ports;
			leds->led_config[1].num_ports = leds->dect_line_count;

			BRCM_PORT_MAP** fxs_ports = calloc(leds->fxs_line_count, sizeof(BRCM_PORT_MAP*));
			for (i = 0; i < leds->fxs_line_count; i++) {
				fxs_ports[i] = &leds->brcm_ports[leds->dect_line_count + i];
			}
			leds->led_config[0].state = LS_UNKNOWN;
			leds->led_config[0].name = LN_VOICE1;
			leds->led_config[0].ports = fxs_ports;
			leds->led_config[0].num_ports = leds->fxs_line_count;
		}
		else {
			/*
			 * LED1 = FXS1, LED2 = FXS2
			 */
			ast_debug(5, "Dual LED configuration, FXS1 and FXS2\n");
			BRCM_PORT_MAP** fxs1 = calloc(1, sizeof(BRCM_PORT_MAP*));
			fxs1[0] = &leds->brcm_ports[0];
			leds->led_config[0].state = LS_UNKNOWN;
			leds->led_config[0].name = LN_VOICE1;
			leds->led_config[0].ports = fxs1;
			leds->led_config[0].num_ports = 1;

			BRCM_PORT_MAP** fxs2 = calloc(1, sizeof(BRCM_PORT_MAP*));
			fxs2[0] = &leds->brcm_ports[1];
			leds->led_config[1].state = LS_UNKNOWN;
			leds->led_config[1].name = LN_VOICE2;
			leds->led_config[1].ports = fxs2;
			leds->led_config[1].num_ports = 1;
		}
	}

	//Now add all accounts that have incoming calls to one of the governing ports
	for (i = 0; i < leds->voice_led_count; i++) {
		Led* led = &leds->led_config[i];
		led->peers = calloc(SIP_MAX_PEERS, sizeof(SIP_PEER*));
		led->num_peers = 0;

		SIP_PEER *peers = leds->sip_peers;
		while (peers->account.id != SIP_ACCOUNT_UNKNOWN) {
			int is_added = 0;
			/* Skip if SIP account is not enabled */
			if (!uci_get_peer_enabled(peers)) {
				peers++;
				continue;
			}

			const char* call_lines = uci_get_called_lines(peers);
			if (call_lines) {
				char buf[20];
				char *delimiter = " ";
				char *value;
				int line_id = -1;
				strncpy(buf, call_lines, 20);
				value = strtok(buf, delimiter);

				//Check all ports called by this account (numbers 0 to x)
				while (value != NULL) {
					line_id = atoi(value);
					//Check if this port is among the governing ports for this led
					int j;
					for (j = 0; j < led->num_ports; j++) {
						if (led->ports[j]->port == line_id) {

							//ast_debug(5, "LED %d governed by PEER %s\n", led->name, peers->account.name);
							//This is a matching peer
							led->peers[led->num_peers] = peers;
							led->num_peers++;
							is_added = 1;
							break;
						}
					}
					if (is_added) {
						break; //break out here if peer has been added
					}
					else {
						value = strtok(NULL, delimiter);
					}
				}
			}
			peers++;
		}
	}
}

void leds_delete(struct leds *leds)
{
	free_led_config(leds);
	free(leds);
}

void leds_manage(struct leds *leds)
{
	int i;

	for (i = 0; i < leds->voice_led_count; i++) {
		Led* led = &leds->led_config[i];
		LED_STATE new_state = LS_OFF;
		if (leds->ready) {
			new_state = get_led_state(led);
		}
		if (new_state != led->state) {
			manage_led(leds, led->name, new_state);
		}
		led->state = new_state;
	}
}

void leds_ubus_connected(struct leds *leds, struct ubus_context *ctx)
{
	leds->ctx = ctx;
}

void leds_ubus_disconnected(struct leds *leds)
{
	leds->ctx = NULL;
}

int leds_dect_line_count(struct leds *leds)
{
	return leds->dect_line_count;
}

int leds_fxs_line_count(struct leds *leds)
{
	return leds->fxs_line_count;
}

void leds_set_ready(struct leds *leds, unsigned int ready)
{
	leds->ready = ready;
}

/**************************/
/* Private implementation */
/**************************/
void manage_led(struct leds *leds, LED_NAME led, LED_STATE state)
{
	const LED_NAME_MAP *names = led_names;
	const LED_STATE_MAP *states = led_states;
	LED_CURRENT_STATE_MAP *current_state = led_current_states;

	//Check and set current state
	while (current_state->name != LN_UNKNOWN) {
		if (current_state->name == led) {
			if (current_state->state == state) {
				//No need to update led
				return;
			}
			current_state->state = state;
			break;
		}
		current_state++;
	}

	//Lookup led name
	while (names->name != led) {
		names++;
		if (names->name == LN_UNKNOWN) {
			ast_log(LOG_WARNING, "Unknown led name\n");
			return;
		}
	}

	//Lookup led state
	while (states->state != state) {
		states++;
		if (states->state == LS_UNKNOWN) {
			ast_log(LOG_WARNING, "Unknown led state\n");
			return;
		}
	}

	if (leds->ctx == NULL) {
		ast_log(LOG_WARNING, "Can't manage led, no ubus connection\n");
		return;
	}

	//Lookup the id of led object
	uint32_t id;
	if (ubus_lookup_id(leds->ctx, names->str, &id)) {
		ast_log(LOG_ERROR, "Failed to look up %s object\n", names->str);
		return;
	}

	//Specify the state we want to set
	blob_buf_init(&leds->b_led, 0);
	blobmsg_add_string(&leds->b_led, "state", states->str);

	//Invoke state change
	ast_debug(5, "Setting LED %s state to %s\n", names->str, states->str);
	ubus_invoke(leds->ctx, id, "set", leds->b_led.head, NULL, 0, 1000);
}

/*
 * Calculate a new state for a Led, based on the state of governing lines and accounts.
 */
LED_STATE get_led_state(Led* led)
{
	//If one of the governing lines are active, led should be in notice mode
	int i;
	for(i = 0; i < led->num_ports; i++) {
		if (brcm_subchannel_active(led->ports[i])) {
			ast_debug(5, "LED %d, PORT %s is active => LS_NOTICE\n", led->name, led->ports[i]->name);
			return LS_NOTICE;
		}
	}

	//Check state of governing accounts
	LED_STATE tmp = LS_OFF;
	for(i = 0; i < led->num_peers; i++) {
		SIP_PEER* peer = led->peers[i];
		if (!peer->sip_registry_registered) {
			ast_debug(5, "LED %d: PEER (%s) is not registered => LS_ERROR\n", led->name, peer->account.name);
			return LS_ERROR;
		}
		else {
			ast_debug(5, "LED %d: PEER (%s) is registered => LS_OK\n", led->name, peer->account.name);
			tmp = LS_OK;
		}
	}
	return tmp;
}

void free_led_config(struct leds *leds)
{
	int i;
	for (i = 0; i < leds->voice_led_count; i++) {
		Led* led = &leds->led_config[i];
		free(led->peers);
		free(led->ports);
	}
	free(leds->led_config);
	leds->led_config = NULL;
}
