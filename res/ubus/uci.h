/*
 * uci.h
 *
 *  UCI interface functions
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#ifndef UCI_H_
#define UCI_H_

#include "list.h"
#include "sip.h"

struct codec *uci_get_codecs(void);
int uci_get_rtp_port_start(void);
int uci_get_rtp_port_end(void);
int uci_get_sip_proxy(struct list_head *proxies);
const char* uci_get_peer_host(SIP_PEER *peer);
const char* uci_get_peer_domain(SIP_PEER *peer);
int uci_get_peer_enabled(SIP_PEER* peer);
void uci_codec_cb(const char * name, void *priv);

#endif /* UCI_H_ */
