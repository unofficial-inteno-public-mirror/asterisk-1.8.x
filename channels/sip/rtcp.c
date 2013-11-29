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

/*! \file rtcp.c
*
* \brief RTCP additional functions
*
* \author Olle E. Johansson <oej@edvina.net>
*/

/*** MODULEINFO
	<support_level>core</support_level>
***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/utils.h"
#include "asterisk/manager.h"
#include "asterisk/logger.h"
#include "asterisk/translate.h"
#include "asterisk/rtp_engine.h"
#include "include/sip.h"
#include "include/rtcp.h"

/*! \brief Set various data items in the RTP structure, like channel identifier.
 */
void sip_rtcp_set_data(struct sip_pvt *dialog, struct ast_rtp_instance *instance, enum media_type type)
{

	if (dialog && dialog->owner) {
 		int readtrans = FALSE, writetrans = FALSE;
		struct ast_channel *bridgepeer = ast_bridged_channel(dialog->owner);

		if (bridgepeer) {
			/* Store the bridged peer data while we have it */
			ast_rtp_instance_set_bridged_chan(instance, dialog->owner->name, dialog->owner->uniqueid, S_OR(bridgepeer->name,""), S_OR(bridgepeer->uniqueid,""));
			ast_debug(1, "---- Setting bridged peer name to %s\n", bridgepeer->name);
		} else {
			ast_rtp_instance_set_bridged_chan(instance, dialog->owner->name, dialog->owner->uniqueid, NULL, NULL);
		}
		ast_debug(1, "---- Setting channel name to %s\n", dialog->owner->name);

 		/* Try to find out if there's active transcoding */
		/* Currently, the only media stream that has translation is the audio stream. At some point
		   we might have transcoding for other types of media. */
		if (type == SDP_AUDIO) {
			struct ast_channel *chan = dialog->owner;
			const char *rtname = NULL, *wtname = NULL;
			/* if we have a translator, the bridge delay is increased, which affects the QoS of the call.  */
 			readtrans = (chan->readtrans != NULL);
 			writetrans = (chan->writetrans != NULL);
			if (readtrans) {
				rtname = chan->readtrans->t->name;
			}
			if (writetrans) {
				wtname = chan->writetrans->t->name;
			}
			if (readtrans || writetrans) {
				ast_rtp_instance_set_translator(instance, rtname, readtrans ? chan->readtrans->t->cost : (const int) 0,
					wtname, writetrans ? chan->writetrans->t->cost : (const int) 0);
			}
		
			if (option_debug > 1) {
 				if (readtrans && dialog->owner->readtrans->t) {
 					ast_debug(1, "--- Audio Read translator: %s Cost %d\n", dialog->owner->readtrans->t->name, dialog->owner->readtrans->t->cost);
 				}
 				if (writetrans && dialog->owner->writetrans->t) {
 					ast_debug(1, "--- Audio Write translator: %s Cost %d\n", dialog->owner->writetrans->t->name, dialog->owner->writetrans->t->cost);
 				}
			}
		}

	} else {
 		ast_debug(1, "######## Not setting rtcp media data. Dialog %s Dialog owner %s \n", dialog ? "set" : "unset",  dialog->owner ? "set" : "unset");
	}
}

/*! \brief send manager report of RTCP 
	reporttype = 0  means report during call (if configured)
	reporttype = 1  means endof-call (hangup) report
	reporttype = 10  means report at end of call leg (like transfer)
*/
void sip_rtcp_report(struct sip_pvt *dialog, struct ast_rtp_instance *instance, enum media_type media, int reporttype)
{
	struct ast_rtp_instance_stats qual;
	//char *rtpqstring = NULL;
	//int qosrealtime = ast_check_realtime("rtpcqr");
	unsigned int duration;	/* Duration in secs */
	memset(&qual, 0, sizeof(qual));
	
	sip_rtcp_set_data(dialog, instance, media);

	if (ast_rtp_instance_get_stats(instance, &qual, AST_RTP_INSTANCE_STAT_ALL)) {
 		ast_debug(1, "######## Did not get any statistics... bad, bad, RTP instance\n");
		/* Houston, we got a problem */
		return;
	}
	
	if (dialog->sip_cfg->rtcpevents) {
		/* 
		   If numberofreports == 0 we have no incoming RTCP active, thus we can't
		   get any reliable data to handle packet loss or any RTT timing.
		*/

		duration = (unsigned int)(ast_tvdiff_ms(ast_tvnow(), qual.start) / 1000);
		manager_event(EVENT_FLAG_CALL, "RTPQuality", 
			"Channel: %s\r\n"			/* AST_CHANNEL for this call */
			"Uniqueid: %s\r\n"			/* AST_CHANNEL for this call */
			"BridgedChannel: %s\r\n"
			"BridgedUniqueid: %s\r\n"
			"RTPreporttype: %s\r\n"
			"RTPrtcpstatus: %s\r\n"
			"Duration: %u\r\n"		/* used in cdr_manager */
			"PvtCallid: %s\r\n"		/* ??? Generic PVT identifier */
			"RTPipaddress: %s\r\n"
			"RTPmedia: %s\r\n"		/* Audio, video, text */
			"RTPsendformat: %s\r\n"
			"RTPrecvformat: %s\r\n"
			"RTPlocalssrc: %u\r\n"
			"RTPremotessrc: %u\r\n"
			"RTPrtt: %f\r\n"
			"RTPrttMax: %f\r\n"
			"RTPrttMin: %f\r\n"
			"RTPLocalJitter: %f\r\n"
			"RTPRemoteJitter: %f\r\n" 
			"RTPInPacketLoss: %d\r\n" 
			"RTPInLocalPlPercent: %5.2f\r\n"
			"RTPOutPacketLoss: %d\r\n"
			"RTPOutPlPercent: %5.2f\r\n"
			"TranslateRead: %s\r\n"
			"TranslateReadCost: %d\r\n"
			"TranslateWrite: %s\r\n"
			"TranslateWriteCost: %d\r\n"
			"\r\n", 
			dialog->owner ? dialog->owner->name : "",
			dialog->owner ? dialog->owner->uniqueid : "",
			qual.bridgedchannel[0] ? qual.bridgedchannel : "" ,
			qual.bridgeduniqueid[0] ? qual.bridgeduniqueid : "",
			reporttype == 1 ? "Final" : "Update",
			qual.numberofreports == 0 ? "Inactive" : "Active",
			duration,
			dialog->callid, 
			ast_inet_ntoa(qual.them.sin_addr), 	
			media == SDP_AUDIO ? "audio" : (media == SDP_VIDEO ? "video" : "fax") ,
			ast_getformatname(qual.lasttxformat),
			ast_getformatname(qual.lastrxformat),
			qual.local_ssrc, 
			qual.remote_ssrc,
			qual.rtt,
			qual.maxrtt,
			qual.minrtt,
			qual.rxjitter,
			qual.txjitter,
			qual.rxploss,
			/* The local counter of lost packets in inbound stream divided with received packets plus lost packets */
			(qual.remote_txcount + qual.rxploss) > 0 ? (double) qual.rxploss / (qual.remote_txcount + qual.rxploss) * 100 : 0,
			qual.txploss,
			/* The remote counter of lost packets (if we got the reports)
			   divided with our counter of sent packets
			 */
			(qual.rxcount + qual.txploss) > 0 ? (double) qual.txploss / qual.rxcount  * 100 : 0,
			qual.readtranslator, qual.readcost,
			qual.writetranslator, qual.writecost
		);
	}

	/* CDR records are not reliable when it comes to near-death-of-channel events, so we need to store the RTCP
	   report in realtime when we have it.
	   Tests have proven that storing to realtime from the call thread is NOT a good thing. Therefore, we just save
	   the quality report structure in the PVT and let the function that kills the pvt store the stuff in the
	   monitor thread instead.
	 */
	if (reporttype == 1) {
		ast_log(LOG_DEBUG, "---- Activation qual structure in dialog \n");
		qual.end = ast_tvnow();
 		qual.mediatype = media;
		if (media == SDP_AUDIO) {  /* Audio */
			dialog->audioqual = ast_calloc(1, sizeof(struct ast_rtp_instance_stats));
			(* dialog->audioqual) = qual;
		} else if (media == SDP_VIDEO) {  /* Video */
			dialog->videoqual = ast_calloc(1,sizeof(struct ast_rtp_instance_stats));
			(* dialog->videoqual) = qual;
		}
	}
}

/*! \brief Write quality report to realtime storage */
void qos_write_realtime(struct sip_pvt *dialog, struct ast_rtp_instance_stats *qual)
{
	unsigned int duration;	/* Duration in secs */
	char buf_duration[10], buf_lssrc[30], buf_rssrc[30];
	char buf_rtt[10], buf_rttmin[10], buf_rttmax[10];
	char localjitter[10], remotejitter[10];
	char buf_readcost[5], buf_writecost[5];
	char buf_mediatype[10];
	char buf_remoteip[25];
	char buf_inpacketloss[25], buf_outpacketloss[25];
	char buf_outpackets[25], buf_inpackets[25];
	int qosrealtime = ast_check_realtime("rtpcqr");

	ast_log(LOG_DEBUG, "************* QOS END REPORTS: The final countdown!!!!! Yeah. \n");

	if (!qual) {
		ast_log(LOG_ERROR, "No CQR data provided \n");
		return;
	}

	/* Since the CDR is already gone, we need to calculate our own duration.
	   The CDR duration is the definitive resource for billing, this is
	   the RTP stream duration which may include early media (ringing and
	   provider messages). Only useful for measurements.
	 */
	if (!ast_tvzero(qual->end) && !ast_tvzero(qual->start)) {
		duration = (unsigned int)(ast_tvdiff_ms(qual->end, qual->start) / 1000);
	} else {
		ast_log(LOG_DEBUG, "**** WTF? No duration? What type of call is THAT? \n");
		duration = 0;
	}

	/* Realtime is based on strings, so let's make strings */
	sprintf(localjitter, "%f", qual->rxjitter);
	sprintf(remotejitter, "%f", qual->txjitter);
	sprintf(buf_lssrc, "%u", qual->local_ssrc);
	sprintf(buf_rssrc, "%u", qual->remote_ssrc);
	sprintf(buf_rtt, "%.0f", qual->rtt);
	sprintf(buf_rttmax, "%.0f", qual->maxrtt);
	sprintf(buf_rttmin, "%.0f", qual->minrtt);
	sprintf(buf_duration, "%u", duration);
	sprintf(buf_readcost, "%d", qual->readcost);
	sprintf(buf_writecost, "%d", qual->writecost);
	sprintf(buf_mediatype,"%s", qual->mediatype == SDP_AUDIO ? "audio" : (qual->mediatype == SDP_VIDEO ? "video" : "fax") );
	sprintf(buf_remoteip,"%s", ast_inet_ntoa(qual->them.sin_addr));
	sprintf(buf_inpacketloss, "%d", qual->rxploss);
	sprintf(buf_outpacketloss, "%d", qual->txploss);
	sprintf(buf_inpackets, "%d", qual->rxcount);		/* Silly value. Need to check this */
	sprintf(buf_outpackets, "%d", qual->txcount);
	//sprintf(buf_inpackets, "%d", qual->remote_count);	/* Do check again */
	//sprintf(buf_outpackets, "%d", qual->local_count);

	ast_log(LOG_DEBUG, "************* QOS END REPORTS: Probing new logging channel LOG_CQR!!!!! Yeah. \n");
	ast_log(LOG_CQR, "CQR Channel: %s Uid %s Bch %s Buid %s Pvt %s Media %s Lssrc %s Rssrc %s Rip %s Rtt %s:%s:%s Ljitter %s Rjitter %s Rtcpstatus %s Dur %s Pout %s Plossout %s Pin %s Plossin %s\n",
		qual->channel[0] ? qual->channel : "",
		qual->uniqueid[0] ? qual->uniqueid : "",
		qual->bridgedchannel[0] ? qual->bridgedchannel : "" ,
		qual->bridgeduniqueid[0] ? qual->bridgeduniqueid : "",
		dialog->callid,
		buf_mediatype,
		buf_lssrc,
		buf_rssrc,
		buf_remoteip,
		buf_rtt, buf_rttmax, buf_rttmin,
		localjitter,
		remotejitter,
		qual->numberofreports == 0 ? "Inactive" : "Active",
		buf_duration,
		buf_outpackets,
		buf_outpacketloss,
		buf_inpackets,
		buf_inpacketloss);

	if (!qosrealtime) {
		return;
	}
/* Example database schema for MySQL:
CREATE TABLE `astcqr` (
  `channel` varchar(50) NOT NULL,
  `uniqueid` varchar(35) NOT NULL,
  `bridgedchannel` varchar(50) NOT NULL,
  `bridgeduniqueid` varchar(35) NOT NULL,
  `pvtcallid` varchar(80) NOT NULL,
  `rtpmedia` varchar(50) NOT NULL,
  `localssrc` varchar(50) NOT NULL,
  `remotessrc` varchar(50) NOT NULL,
  `rtt` varchar(10) NOT NULL,
  `localjitter` varchar(10) NOT NULL,
  `remotejitter` varchar(10) NOT NULL,
  `sendformat` varchar(10) NOT NULL,
  `receiveformat` varchar(10) NOT NULL,
  `rtcpstatus` varchar(10) NOT NULL,
  `duration` varchar(10) NOT NULL,
  `packetsent` varchar(30) NOT NULL,
  `packetreceived` varchar(30) NOT NULL,
  `packetlossin` varchar(30) NOT NULL,
  `packetlossout` varchar(30) NOT NULL,
  `rttmax` varchar(12) NOT NULL,
  `rttmin` varchar(12) NOT NULL,
  `writetranslator` varchar(15) NOT NULL,
  `readtranslator` varchar(15) NOT NULL,
  `writecost` varchar(10) NOT NULL,
  `readcost` varchar(10) NOT NULL,
  `remoteip` varchar(25) NOT NULL,
  KEY `ChannelUnique` (`channel`,`uniqueid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='FOr pinefrog stats'
*/

	ast_store_realtime("rtpcqr", 
		"channel", qual->channel[0] ? qual->channel : "--no channel--",
		"uniqueid", qual->uniqueid[0] ? qual->uniqueid : "--no uniqueid --",
		"bridgedchannel", qual->bridgedchannel[0] ? qual->bridgedchannel : "" ,
		"bridgeduniqueid", qual->bridgeduniqueid[0] ? qual->bridgeduniqueid : "",
		"pvtcallid", dialog->callid, 
		"rtpmedia", buf_mediatype, 
		"localssrc", buf_lssrc, 
		"remotessrc", buf_rssrc,
		"remoteip", buf_remoteip,
		"rtt", buf_rtt, 
		"rttmax", buf_rttmax, 
		"rttmin", buf_rttmin, 
		"localjitter", localjitter, 
		"remotejitter", remotejitter, 
		"sendformat", ast_getformatname(qual->lasttxformat),
		"receiveformat", ast_getformatname(qual->lastrxformat),
		"rtcpstatus", qual->numberofreports == 0 ? "Inactive" : "Active",
		"duration", buf_duration,
		"writetranslator", qual->writetranslator[0] ? qual->writetranslator : "",
		"writecost", buf_writecost,
		"readtranslator", qual->readtranslator[0] ? qual->readtranslator : "",
		"readcost", buf_readcost,
		"packetlossin", buf_inpacketloss,
		"packetlossout", buf_outpacketloss,
		"packetsent", buf_outpackets,
		"packetreceived", buf_inpackets,
		NULL);
}

/*! \brief Send RTCP manager events */
int send_rtcp_events(const void *data)
{
	struct sip_pvt *dialog = (struct sip_pvt *) data;
	ast_log(LOG_DEBUG, "***** SENDING RTCP EVENT \n");

	if (dialog->rtp && !ast_rtp_instance_isactive(dialog->rtp)) {
		ast_debug(1, "          ***** Activating RTCP report \n");
		sip_rtcp_report(dialog, dialog->rtp, SDP_AUDIO, FALSE);
	} else {
		ast_debug(1, "          ***** NOT Activating RTCP report \n");
	}
	if (dialog->vrtp && !ast_rtp_instance_isactive(dialog->vrtp)) {
		sip_rtcp_report(dialog, dialog->vrtp, SDP_VIDEO, FALSE);
	}
	return (dialog->sip_cfg ? dialog->sip_cfg->rtcptimer : 0);
}

/*! \brief Activate RTCP events at start of call */
void start_rtcp_events(struct sip_pvt *dialog, struct sched_context *sched)
{
	ast_debug(2, "***** STARTING SENDING RTCP EVENT \n");
	/* Check if it's already active */

	if (dialog->rtp && !ast_rtp_instance_isactive(dialog->rtp)) {
		sip_rtcp_set_data(dialog, dialog->rtp, SDP_AUDIO);
	}
	if (dialog->vrtp && !ast_rtp_instance_isactive(dialog->vrtp)) {
		sip_rtcp_set_data(dialog, dialog->vrtp, SDP_VIDEO);
	}

	if (!dialog->sip_cfg->rtcpevents || !dialog->sip_cfg->rtcptimer) {
		ast_debug(2, "***** NOT SENDING RTCP EVENTS \n");
		return;
	}

	if (dialog->rtcpeventid != -1) {
		return;
	}


	/*! \brief Schedule events */
	dialog->rtcpeventid = ast_sched_add(sched, dialog->sip_cfg->rtcptimer * 1000, send_rtcp_events, dialog);
}
