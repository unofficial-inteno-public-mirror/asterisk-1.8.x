/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013 Olle E. Johansson, Edvina AB
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file rtcp.h
 *
 * \brief RTCP additional functions
 *
 * \author Olle E. Johansson <oej@edvina.net>
 */

#include "asterisk.h"

#include "asterisk/utils.h"
#include "asterisk/rtp_engine.h"
#include "sip.h"

#ifndef _SIP_RTCP_H
#define _SIP_RTCP_H

/*! \brief Set various data items in the RTP structure, like channel identifier.
 */
void sip_rtcp_set_data(struct sip_pvt *dialog, struct ast_rtp_instance *instance, enum media_type type);

int send_rtcp_events(const void *data);
void start_rtcp_events(struct sip_pvt *dialog, struct sched_context *sched);
/*
# For 1.4:
# static void sip_rtcp_report(struct sip_pvt *p, struct ast_rtp *rtp, enum media_type type, int reporttype);
*/

void sip_rtcp_report(struct sip_pvt *dialog, struct ast_rtp_instance *instance, enum media_type type, int reporttype);
//void qos_write_realtime(struct sip_pvt *dialog, struct ast_rtp_quality *qual);
void qos_write_realtime(struct sip_pvt *dialog, struct ast_rtp_instance_stats *qual);



#endif /* _SIP_RTCP_H */
