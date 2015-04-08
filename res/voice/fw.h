/*
 * fw.h
 *
 *  Dynamic firewall functions
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#ifndef FW_H_
#define FW_H_

#include "sip.h"

struct fw;

struct fw *fw_create(void);
void fw_delete(struct fw *fw);
int fw_manage(struct fw *fw, SIP_PEER *peer, int doResolv);

#endif /* FW_H_ */
