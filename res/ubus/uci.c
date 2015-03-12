/*
 * uci.c
 *
 *  UCI interface functions
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#include "uci.h"
#include "codec.h"
#include "ucix.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define UCI_VOICE_PACKAGE "voice_client"
#define UCI_CODEC_PACKAGE "voice_codecs"

static struct uci_context *uci_voice_client_ctx = NULL;
static struct uci_context *uci_voice_codecs_ctx = NULL;

static void ucix_reload(void);

/*
 * Create list of supported codecs, used by ubus_codecs_cb()
 */
struct codec *uci_get_codecs(void)
{
	/* Create space for first codec */
	struct codec *c = codec_create();

	ucix_reload();
	ucix_for_each_section_type(uci_voice_codecs_ctx, UCI_CODEC_PACKAGE, "supported_codec", uci_codec_cb, c);
	return c;
}

/*
 * callback, called for each "supported_codec" found
 */
void uci_codec_cb(const char * name, void *priv)
{
	struct codec *c = (struct codec *) priv;

	/* Store key/value to last codec in list */
	while (c->next) {
		c = c->next;
	}
	c->key = strdup(name);
	c->value = strdup(ucix_get_option(uci_voice_codecs_ctx, UCI_CODEC_PACKAGE, name, "name"));
	const char *bitrate = ucix_get_option(uci_voice_codecs_ctx, UCI_CODEC_PACKAGE, name, "bitrate");
	c->bitrate = bitrate ? atoi(bitrate) : 0;

	/* Create space for next codec */
	c->next = codec_create();
}

int uci_get_rtp_port_start()
{
	ucix_reload();
	return ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, "SIP", "rtpstart", -1);
}

int uci_get_rtp_port_end()
{
	ucix_reload();
	return ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, "SIP", "rtpend", -1);
}

int uci_get_sip_proxy(struct list_head *proxies)
{
	ucix_reload();
	return ucix_get_option_list(uci_voice_client_ctx, UCI_VOICE_PACKAGE, "SIP", "sip_proxy", proxies);
}

const char* uci_get_peer_host(SIP_PEER *peer)
{
	ucix_reload();
	int enabled = ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "enabled", 0);
	if (enabled == 0) {
		return NULL;
	}
	return ucix_get_option(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "host");
}

const char* uci_get_peer_domain(SIP_PEER *peer)
{
	ucix_reload();
	int enabled = ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "enabled", 0);
	if (enabled == 0) {
		return NULL;
	}
	return ucix_get_option(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "domain");
}

int uci_get_peer_enabled(SIP_PEER* peer)
{
	ucix_reload();
	return ucix_get_option_int(uci_voice_client_ctx, UCI_VOICE_PACKAGE, peer->account.name, "enabled", 0);
}

/*
 * Reload uci context, as any changes to config will not be read otherwise
 */
void ucix_reload(void)
{
	if (uci_voice_client_ctx) {
		ucix_cleanup(uci_voice_client_ctx);
	}
	uci_voice_client_ctx = ucix_init(UCI_VOICE_PACKAGE);

	if (uci_voice_codecs_ctx) {
		ucix_cleanup(uci_voice_codecs_ctx);
	}
	uci_voice_codecs_ctx = ucix_init(UCI_CODEC_PACKAGE);
}
