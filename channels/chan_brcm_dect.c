
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 284597 $")

#include <math.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/cli.h"
#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/utils.h"
#include "asterisk/callerid.h"
#include "asterisk/causes.h"
#include "asterisk/stringfields.h"
#include "asterisk/musiconhold.h"
#include "asterisk/indications.h"
#include "asterisk/manager.h"
#include "asterisk/sched.h"

#include <ApiFpProject.h>
#include <dectUtils.h>
#include <dectshimdrv.h>
#include <dectNvsCtl.h>

#include "chan_brcm.h"
#include "chan_brcm_dect.h"


int s;

char nbwbCodecList[NBWB_CODECLIST_LENGTH]={0x01, 0x02, 0x03, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x04};
char nbCodecList[]={0x01, 0x01, 0x02, 0x00, 0x00, 0x04};
char wbCodecList[]={0x01, 0x01, 0x03, 0x00, 0x00, 0x01};

extern VRG_ENDPT_STATE endptObjState[MAX_NUM_LINEID];
extern const DTMF_CHARNAME_MAP dtmf_to_charname[];
extern struct brcm_pvt *iflist;


ApiInfoElementType* ApiGetNextInfoElement(ApiInfoElementType *IeBlockPtr,
                                          rsuint16 IeBlockLength,
                                          ApiInfoElementType *IePtr)
{
	ApiInfoElementType *pEnd = (ApiInfoElementType*)((rsuint8*)IeBlockPtr + IeBlockLength);

	if (IePtr == NULL) {
		// return the first info element
		IePtr = IeBlockPtr;
		
	} else {
		// calc the address of the next info element
		IePtr = (ApiInfoElementType*)((rsuint8*)IePtr + RSOFFSETOF(ApiInfoElementType, IeData) + IePtr->IeLength);
	}

	if (IePtr < pEnd) {
		
		return IePtr; // return the pointer to the next info element
	}
	return NULL; // return NULL to indicate that we have reached the end
}


void ApiBuildInfoElement(ApiInfoElementType **IeBlockPtr,
                         rsuint16 *IeBlockLengthPtr,
                         ApiIeType Ie,
                         rsuint8 IeLength,
                         rsuint8 *IeData)
{

	rsuint16 newLength = *IeBlockLengthPtr + RSOFFSETOF(ApiInfoElementType, IeData) + IeLength;

	/* Ie is in little endian inside the infoElement list while all arguments to function are in bigEndian */
	rsuint16 targetIe = Ie;
	//  RevertByteOrder( sizeof(ApiIeType),(rsuint8*)&targetIe   );          

	/* Allocate / reallocate a heap block to store (append) the info elemte in. */
	ApiInfoElementType *p = malloc(newLength);

	if (p == NULL) {

		// We failed to get e new block.
		// We free the old and return with *IeBlockPtr == NULL.
		ApiFreeInfoElement(IeBlockPtr);
		*IeBlockLengthPtr = 0;
	} else {
		// Update *IeBlockPointer with the address of the new block
		//     *IeBlockPtr = p;
		if( *IeBlockPtr != NULL ) {
		
			/* Copy over existing block data */
			memcpy( (rsuint8*)p, (rsuint8*)*IeBlockPtr, *IeBlockLengthPtr);
		
			/* Free existing block memory */
			ApiFreeInfoElement(IeBlockPtr);
		}
    
		/* Assign newly allocated block to old pointer */
		*IeBlockPtr = p;

		// Append the new info element to the allocated block
		p = (ApiInfoElementType*)(((rsuint8*)p) + *IeBlockLengthPtr); // p now points to the first byte of the new info element

		p->Ie = targetIe;

		p->IeLength = IeLength;
		memcpy (p->IeData, IeData, IeLength);
		// Update *IeBlockLengthPtr with the new block length
		*IeBlockLengthPtr = newLength;
	}

}




void ApiFreeInfoElement(ApiInfoElementType **IeBlockPtr)
{
	ast_free((void*)*IeBlockPtr);

	*IeBlockPtr = NULL;
}



void dectSetupPingingCall(int handset)
{
	ApiCallingNameType * pCallingNameIe    = NULL;
	ApiInfoElementType * pingIeBlockPtr    = NULL;
	ApiFpCcSetupReqType * pingMailPtr      = NULL;
	unsigned short pingIeBlockLength       = 0;
	char callingName[]                     = "HANDSET LOCATOR";


	/************************************************
	 * create API_IE_CALLING_PARTY_NAME infoElement *
	 ************************************************/

	pCallingNameIe = malloc( (sizeof(ApiCallingNameType) - 1) + (strlen(callingName)+1) );

	if( pCallingNameIe != NULL )
		{
			pCallingNameIe->UsedAlphabet     = AUA_DECT;
			pCallingNameIe->PresentationInd  = API_PRESENTATION_HANSET_LOCATOR;
			pCallingNameIe->ScreeningInd     = API_NETWORK_PROVIDED;
			pCallingNameIe->NameLength       = strlen(callingName);
			memcpy( &(pCallingNameIe->Name[0]), callingName, (strlen(callingName)+1) );

			/* Add to infoElement block */
			ApiBuildInfoElement( &pingIeBlockPtr,
					     &pingIeBlockLength,
					     API_IE_CALLING_PARTY_NAME,
					     ((sizeof(ApiCallingNameType) - 1) + (strlen(callingName)+1) ),
					     (unsigned char*)pCallingNameIe);

			/* free infoElement */
			free(pCallingNameIe);

			if( pingIeBlockPtr == NULL )
				{
					ast_verbose("dectCallMgrSetupPingingCall:  ApiBuildInfoElement FAILED for API_IE_CALLING_PARTY_NAME!!\n");
					return;
				}
		}
	else
		{
			ast_verbose("dectCallMgrSetupPingingCall: malloc FAILED for API_IE_CALLING_PARTY_NAME!!\n");
			return;
		}

	/*****************************************************
	 * create API_FP_CC_SETUP_REQ mail *
	 *****************************************************/
	if( pingIeBlockLength > 0 )
		{
			/* Allocate memory for mail */
			pingMailPtr = (ApiFpCcSetupReqType *) malloc( (sizeof(ApiFpCcSetupReqType)-1) + pingIeBlockLength );
			if (pingMailPtr != NULL)
				{
					/* Fillout mail contents */
					((ApiFpCcSetupReqType *) pingMailPtr)->Primitive    = API_FP_CC_SETUP_REQ;
					((ApiFpCcSetupReqType *) pingMailPtr)->CallReference.HandsetId = handset;
					((ApiFpCcSetupReqType *) pingMailPtr)->BasicService = API_BASIC_SPEECH;
					((ApiFpCcSetupReqType *) pingMailPtr)->CallClass    = API_CC_NORMAL;
					((ApiFpCcSetupReqType *) pingMailPtr)->SourceId     = 0; /* 0 is the base station id */
					((ApiFpCcSetupReqType *) pingMailPtr)->Signal       = API_CC_SIGNAL_ALERT_ON_PATTERN_2;

					/* Copy over infoElements */
					memcpy( &(((ApiFpCcSetupReqType *) pingMailPtr)->InfoElement[0]), pingIeBlockPtr, pingIeBlockLength );
					ApiFreeInfoElement( &pingIeBlockPtr );

					/* Size must be in little endian  */
					//RevertByteOrder( sizeof(unsigned short),(unsigned char*)&pingIeBlockLength   );
					((ApiFpCcSetupReqType *) pingMailPtr)->InfoElementLength = pingIeBlockLength;
				}
			else
				{
					ast_verbose("dectCallMgrSetupPingingCall: No more memory available for API_FP_CC_SETUP_REQ!!!\n");
					return;
				}
		}
	else
		{
			ast_verbose("dectCallMgrSetupPingingCall: zero pingIeBlockLength!!!\n");
			ApiFreeInfoElement( &pingIeBlockPtr );
			return;
		}


	/* Send the mail */
	ast_verbose("OUTPUT: API_FP_CC_SETUP_REQ (ping)\n");
	dectDrvWrite((unsigned char *)pingMailPtr, ((sizeof(ApiFpCcSetupReqType)-1) + pingIeBlockLength));

}


void dectRingHandSet( int destHandset, int dspChannel, char *cid) //, int line, int cmCnxId )
{

	ApiCcBasicServiceType basicService;
	ApiInfoElementType *IeBlockPtr;
	unsigned short IeBlockLength;
	unsigned char *newMailPtr;
	int newMailSize;
	ApiCodecListType* codecList = NULL;
	unsigned char codecListLength;
	unsigned char callingNumLength;
	unsigned char callingNameLength;
	ApiCallingNumberType * callingNum = NULL;
	ApiCallingNameType * callingName  = NULL;


	ast_verbose("dectRingHandSet\n");
	
	/* Initialize block variables */
	IeBlockPtr    = NULL;
	IeBlockLength = 0;
   

	if (1) {
		basicService = API_WIDEBAND_SPEECH;
		codecList = (ApiCodecListType *)&nbwbCodecList[0];
		codecListLength = NBWB_CODECLIST_LENGTH;
	} else 	{
		basicService = API_BASIC_SPEECH;
		codecList = (ApiCodecListType *)&nbCodecList[0];
		codecListLength = SINGLE_CODECLIST_LENGTH;
	}


	/* get lengths of calling name and number */
	callingNumLength = strlen(cid);

	/**************************************************                                                                          
	 * create API_IE_CALLING_PARTY_NUMBER infoElement *                                                                          
	 **************************************************/
	callingNum = malloc( (sizeof(ApiCallingNumberType) - 1) + callingNumLength );

	if( callingNum != NULL ) {

		callingNum->NumberType        = ANT_NATIONAL;
		callingNum->Npi               = ANPI_NATIONAL;
		callingNum->PresentationInd   = API_PRESENTATION_ALLOWED;
		callingNum->ScreeningInd      = API_USER_PROVIDED_VERIFIED_PASSED;
		callingNum->NumberLength      = callingNumLength;
		memcpy( &(callingNum->Number[0]), cid, callingNumLength);

		/* Add to infoElement block */
		ApiBuildInfoElement( &IeBlockPtr,
				     &IeBlockLength,
				     API_IE_CALLING_PARTY_NUMBER,
				     (sizeof(ApiCallingNumberType) - 1) + callingNumLength ,
				     (unsigned char*)callingNum);

		/* free infoElement */
		free(callingNum);
	}


	/* Build API_IE_LINE_ID infoElement with the selected line */
	ApiLineIdListType lineIdIe;
	ApiCallStatusListType callStatus;
	lineIdIe.ApiLineId[0].ApiSubId = API_SUB_LINE_ID_EXT_LINE_ID;
	lineIdIe.ApiLineId[0].ApiLineValue.Info = 0x01; /* Significant delay in network + 2ndcalls use common parallel scenarios */
	lineIdIe.ApiLineId[0].ApiLineValue.Value = 0; //line;

	callStatus.ApiCallStatus[0].CallStatusSubId = API_SUB_CALL_STATUS;
	callStatus.ApiCallStatus[0].CallStatusValue.State  = API_CSS_CALL_SETUP;

	ApiBuildInfoElement( &IeBlockPtr,
			     &IeBlockLength,
			     API_IE_LINE_ID,
			     sizeof(ApiLineIdType),
			     (unsigned char*)&lineIdIe);

	/* Build API_IE_CODEC_LIST infoElement with all of our codecs */
	ApiBuildInfoElement( &IeBlockPtr,
			     &IeBlockLength,
			     API_IE_CODEC_LIST,
			     codecListLength,
			     (unsigned char*)codecList);

	/* Add to cc call status to infoElement block */
	ApiBuildInfoElement( &IeBlockPtr,
			     &IeBlockLength,
			     API_IE_CALL_STATUS,
			     sizeof(ApiCallStatusListType),
			     (unsigned char*)&callStatus);

	if( IeBlockPtr != NULL ) {
		/* Send connect request */
		newMailSize = (sizeof(ApiFpCcSetupReqType)-1) + IeBlockLength ;
		newMailPtr = (unsigned char *) malloc(newMailSize);

		if(newMailPtr != NULL) {
			((ApiFpCcSetupReqType *) newMailPtr)->Primitive = API_FP_CC_SETUP_REQ;
			((ApiFpCcSetupReqType *) newMailPtr)->CallReference.HandsetId  = destHandset;
			((ApiFpCcSetupReqType *) newMailPtr)->BasicService = basicService;
			((ApiFpCcSetupReqType *) newMailPtr)->CallClass = API_CC_NORMAL;
			((ApiFpCcSetupReqType *) newMailPtr)->SourceId = dspChannel;
			((ApiFpCcSetupReqType *) newMailPtr)->Signal = API_CC_SIGNAL_ALERT_ON_PATTERN_1;

		/* Copy over infoElements */
			memcpy( &(((ApiFpCcSetupReqType *) newMailPtr)->InfoElement[0]), IeBlockPtr, IeBlockLength );
			ApiFreeInfoElement( &IeBlockPtr );

			((ApiFpCcSetupReqType *) newMailPtr)->InfoElementLength = IeBlockLength;

			/* Send mail */
			ast_verbose("OUTPUT: API_FP_CC_SETUP_REQ");
			dectDrvWrite(newMailPtr, newMailSize);
			ast_free(newMailPtr);

		} else 	{
			ast_verbose("Failed to allocate mail API_FP_CC_SETUP_REQ!!!");
		}
	} else {
		ast_verbose("Failed to allocate info Element API_IE_CODEC_LIST!!!");
	}
}


void dectDrvWrite(void *data, int size)
{   
	int i;
	unsigned char* cdata = (unsigned char*)data;

	ast_verbose("\n[WDECT][%04d] - ",size);
	for (i=0 ; i<size ; i++) {
		ast_verbose("%02x ",cdata[i]);
	}
	ast_verbose("\n");

	if (write(s, data, size) == -1) {
		ast_verbose("write to API failed\n");
		return;
	}

	return;
}


EPSTATUS
vrgEndptSendCasEvtToEndpt(ENDPT_STATE *endptState, 
				   CAS_CTL_EVENT_TYPE eventType, 
				   CAS_CTL_EVENT event)
{
	ENDPOINTDRV_SENDCASEVT_CMD_PARM tCasCtlEvtParm;
	int fd;

	tCasCtlEvtParm.epStatus      = EPSTATUS_DRIVER_ERROR;
	tCasCtlEvtParm.casCtlEvtType = eventType;
	tCasCtlEvtParm.casCtlEvt     = event;
	tCasCtlEvtParm.lineId        = endptState->lineId;
	tCasCtlEvtParm.size          = sizeof(ENDPOINTDRV_SENDCASEVT_CMD_PARM);

	fd = open("/dev/bcmendpoint0", O_RDWR);

	if ( ioctl( fd, ENDPOINTIOCTL_SEND_CAS_EVT, &tCasCtlEvtParm ) != IOCTL_STATUS_SUCCESS )
		ast_verbose("%s: error during ioctl", __FUNCTION__);

	close(fd);
	return( tCasCtlEvtParm.epStatus );
}



static void dect_signal_dialtone(int i) {
	ovrgEndptSignal( (ENDPT_STATE*)&endptObjState[i], -1, EPSIG_DIAL, 1, -1, -1 , -1);
}






ApiInfoElementType *
ApiGetInfoElement(ApiInfoElementType *IeBlockPtr,
                                      rsuint16 IeBlockLength,
                                      ApiIeType Ie)
{
	/* Ie is in little endian inside the infoElement
	   list while all arguments to function are in bigEndian */
	ApiInfoElementType *pIe = NULL;
	rsuint16 targetIe = Ie;  

	while (NULL != (pIe = ApiGetNextInfoElement(IeBlockPtr, IeBlockLength, pIe))) {
		if (pIe->Ie == targetIe) {
			/* Return the pointer to the info element found */
			return pIe; 
		}
	}

	/* Return NULL to indicate that we did not
	   find an info element wirh the IE specified */
	return NULL; 
}




static void dectDumpHsetCodecList( ApiInfoElementType* IePtr)
{
   int i;
   ApiCodecListType * codecList = ((ApiCodecListType*)&(IePtr->IeData[0]));
   ApiCodecInfoType * codecInfo = NULL;

   ast_verbose("API_IE_CODEC_LIST\nNegotiationIndicator: %d\n", codecList->NegotiationIndicator );

   for( i=0; i< codecList->NoOfCodecs; i++ )
   {
      codecInfo = &(codecList->Codec[i]);
      ast_verbose("Codec         : %d\n",codecInfo->Codec);
      ast_verbose("MacDlcService : %d\n",codecInfo->MacDlcService);
      ast_verbose("CplaneRouting : %d\n",codecInfo->CplaneRouting);
      ast_verbose("SlotSize      : %d\n",codecInfo->SlotSize);
   }
}



static void dect_setup_ind(unsigned char *MailPtr) {

	ApiInfoElementType *IePtr;
	ApiInfoElementType *IeBlockPtr;
	unsigned short IeBlockLength = ((ApiFpCcSetupIndType*) MailPtr)->InfoElementLength;
	unsigned char o_buf[5];
	ApiCodecListType codecList;
	unsigned char *newMailPtr;
	int newMailSize;
	ApiCalledNumberType * calledNumber;
	ApiSystemCallIdType *callIdPtr;
	ApiHandsetIdType handset;
	int endpt_id;


	IeBlockPtr = (ApiInfoElementType *)&(((ApiFpCcSetupIndType*) MailPtr)->InfoElement[0]);
	ast_verbose("DECT: API_FP_CC_SETUP_IND\n");
	handset = ((ApiFpCcSetupIndType*) MailPtr)->CallReference.HandsetId;
	ast_verbose("handset: %d\n", (int) handset);
	
	/* Quick fix */
	endpt_id = handset - 1;
	
	/* Process API_IE_SYSTEM_CALL_ID if present */
	if( (IePtr =  ApiGetInfoElement(IeBlockPtr, IeBlockLength, API_IE_SYSTEM_CALL_ID)) ) {
		callIdPtr = (ApiSystemCallIdType*)&(IePtr->IeData[0]);
		ast_verbose("dectSetupOutgoingCall: SYSTEM_CALL_ID (%d) in IE\n", callIdPtr->ApiSystemCallId);
	}

	/* Process API_IE_CALLED_NUMBER if present */
	if( (IePtr =  ApiGetInfoElement(IeBlockPtr, IeBlockLength, API_IE_CALLED_NUMBER)) )
		calledNumber = ((ApiCalledNumberType*)&(IePtr->IeData[0]));

     
	/* Process API_IE_CODEC_LIST if present */
	if( (IePtr =  ApiGetInfoElement(IeBlockPtr, IeBlockLength, API_IE_CODEC_LIST)) ) {
		dectDumpHsetCodecList( IePtr );
	}


	/* Signal offhook to endpoint */
	vrgEndptSendCasEvtToEndpt( (ENDPT_STATE *)&(endptObjState[endpt_id]), CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_OFFHOOK );

	IeBlockPtr = NULL;

	/* write endpoint id to device */
	*(o_buf + 0) = ((API_FP_CC_SETUP_RES & 0xff00) >> 8);
	*(o_buf + 1) = ((API_FP_CC_SETUP_RES & 0x00ff) >> 0);
	*(o_buf + 2) = handset;
	*(o_buf + 3) = 0;
	*(o_buf + 4) = endpt_id;

	ast_verbose("API_FP_CC_SETUP_RES\n");
	dectDrvWrite(o_buf, 5);


	/* If the handset supports wideband audio we should probably use that.
	   However, all handsets seem to like the settings below. That includes
	   the handsets that don't explicily inform us of the codec parameters
	   they like. It's not clear if the mac & cplane values will always be
	   the ones used below for that codec setting. */

	/* Build API_IE_CODEC_LIST infoElement with a single codec in our list*/
	codecList.NegotiationIndicator = API_NI_POSSIBLE;
	codecList.NoOfCodecs = 1;

	codecList.Codec[0].Codec = API_CT_G726; /*!< G.726 ADPCM, information transfer rate 32 kbit/s */
	/* codecList.Codec[0].Codec = API_CT_G722; /\* G.722, information transfer rate 64 kbit/s *\/ */

	codecList.Codec[0].MacDlcService = API_MDS_1_MD; /* DLC service LU1, MAC service: In_minimum_delay */
	codecList.Codec[0].CplaneRouting = API_CPR_CS; /* CS only */

	/* codecList.Codec[0].SlotSize = API_SS_LS640; Long slot; j = 640, use with G722 */
	codecList.Codec[0].SlotSize = API_SS_FS; /* Full slot; */

	IeBlockLength = 0;
	ApiBuildInfoElement( &IeBlockPtr,
			     &IeBlockLength,
			     API_IE_CODEC_LIST,
			     sizeof(ApiCodecListType),
			     (unsigned char*)(&codecList));

	if( IeBlockPtr != NULL ) {
     
		/* Process API_IE_CODEC_LIST if present */
		if( (IePtr =  ApiGetInfoElement(IeBlockPtr, IeBlockLength, API_IE_CODEC_LIST)) ) {
			dectDumpHsetCodecList( IePtr );
		}


		/* Send connect request */
		newMailSize = (sizeof(ApiFpCcConnectReqType)-1) + IeBlockLength;
		newMailPtr = (unsigned char *) malloc( newMailSize );

		if (newMailPtr != NULL) {

			((ApiFpCcConnectReqType *) newMailPtr)->Primitive = API_FP_CC_CONNECT_REQ;
			((ApiFpCcConnectReqType *) newMailPtr)->CallReference.HandsetId = handset;
	 
			/* Copy over infoElements */
			memcpy( &(((ApiFpCcConnectReqType *) newMailPtr)->InfoElement[0]), IeBlockPtr, IeBlockLength );
			ApiFreeInfoElement( &IeBlockPtr );

			((ApiFpCcConnectReqType *) newMailPtr)->InfoElementLength = IeBlockLength;

			/* Send mail */
			ast_verbose("OUTPUT: API_FP_CC_CONNECT_REQ\n");
			dectDrvWrite(newMailPtr, newMailSize);

			ast_free(newMailPtr);
		}
	}
}


static void dect_release_ind(unsigned char *buf) {

	ApiHandsetIdType handset;
	unsigned char o_buf[5];
  
	ast_verbose("DECT: API_FP_CC_RELEASE_IND\n");

	/* Signal onhook to endpoint */
	handset = ((ApiFpCcConnectCfmType*) buf)->CallReference.HandsetId;
	vrgEndptSendCasEvtToEndpt((ENDPT_STATE *)&endptObjState[handset - 1], CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_ONHOOK );

	/* write endpoint id to device */
	*(o_buf + 0) = ((API_FP_CC_RELEASE_RES & 0xff00) >> 8);
	*(o_buf + 1) = ((API_FP_CC_RELEASE_RES & 0x00ff) >> 0);
	*(o_buf + 2) = handset;
	*(o_buf + 3) = 0;
	*(o_buf + 4) = 0;

	printf("API_FP_CC_RELEASE_RES\n");
	dectDrvWrite(o_buf, 5);

}



static void dect_release_cfm(unsigned char *buf) {

	ApiHandsetIdType handset;
	unsigned char o_buf[5];
  
	ast_verbose("DECT: API_FP_CC_RELEASE_CFM\n");

	/* Signal onhook to endpoint */
	handset = ((ApiFpCcConnectCfmType*) buf)->CallReference.HandsetId;
	vrgEndptSendCasEvtToEndpt((ENDPT_STATE *)&endptObjState[handset - 1], CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_ONHOOK );

}





void dect_hangup(int handset) {

	unsigned char o_buf[5];
  

	/* write endpoint id to device */
	*(o_buf + 0) = ((API_FP_CC_RELEASE_REQ & 0xff00) >> 8);
	*(o_buf + 1) = ((API_FP_CC_RELEASE_REQ & 0x00ff) >> 0);
	*(o_buf + 2) = handset;
	*(o_buf + 3) = 0;
	*(o_buf + 4) = 0;

	printf("API_FP_CC_RELEASE_REQ\n");
	dectDrvWrite(o_buf, 5);

}


static void 
dectProcessCCKeyPadInfo(unsigned char handset,
			ApiInfoElementType* IeBlockPtr,
			unsigned short IeBlockLength )
{
	ApiMultikeyPadType * keyPadEntry = NULL;
	unsigned char keyPadLen;
	ApiInfoElementType* IePtr = NULL;
	int i, j;
	struct brcm_pvt *p;
	struct brcm_subchannel *sub;
   
	if ((IeBlockPtr == NULL) || (IeBlockLength == 0))
		return;

	/* Process API_IE_MULTIKEYPAD if present */
	if((IePtr = ApiGetInfoElement(IeBlockPtr, IeBlockLength, API_IE_MULTIKEYPAD)) 
	    && (IePtr->IeLength != 0 )) {
			keyPadEntry = (ApiMultikeyPadType *) (&(IePtr->IeData[0]));
			keyPadLen = IePtr->IeLength;
	} else {
		/* no keypad info, should not come in here */
		return;
	}

	p = brcm_get_pvt_from_lineid(iflist, handset - 1);

	for (i = 0; i < keyPadLen; i++) {

		const DTMF_CHARNAME_MAP *dtmfMap = dtmf_to_charname;

		while (dtmfMap->c != IePtr->IeData[i]) {
			dtmfMap++;
			if (dtmfMap->event == EPEVT_LAST) {
				/* DTMF not found. Should not be reached. */
				ast_log(LOG_WARNING, "Failed to handle DTMF. Event not found.\n");
				return;
			}
		}

		ast_mutex_lock(&p->lock);
		sub = brcm_get_active_subchannel(p);

		if (!sub) {
			ast_mutex_unlock(&p->lock);
		} else {
			for (j = 0; j < 2; j++) { // we need to send two events: press and depress

				unsigned int old_state = sub->channel_state;
				handle_dtmf(dtmfMap->event, sub);
				if (sub->channel_state == DIALING && old_state != sub->channel_state) {

					/* DTMF event took channel state to DIALING. Stop dial tone. */
					ast_log(LOG_DEBUG, "Dialing. Stop dialtone.\n");
					brcm_stop_dialtone(p);
				}
			}
		}
		ast_mutex_unlock(&p->lock);
	}
}

static void dect_info_ind(unsigned char *MailPtr) {
	
	ApiHandsetIdType handset;
	ApiInfoElementType *ccInfoInd_IeBlockPtr  = (ApiInfoElementType *)&(((ApiFpCcInfoIndType*) MailPtr)->InfoElement[0]);
	unsigned short ccInfoInd_IeBlockLength    = ((ApiFpCcInfoIndType*) MailPtr)->InfoElementLength;
	ApiInfoElementType* ccInfoInd_IePtr       = NULL;


	ast_verbose("INPUT: API_FP_CC_INFO_IND:\n");



	handset = ((ApiFpCcInfoIndType*) MailPtr)->CallReference.HandsetId;

	if( (((ApiFpCcInfoIndType*) MailPtr)->InfoElementLength > 0) ) {

		ccInfoInd_IePtr = ApiGetInfoElement(ccInfoInd_IeBlockPtr, ccInfoInd_IeBlockLength, API_IE_MULTIKEYPAD);

		/* Process API_IE_MULTIKEYPAD if present */
		if(ccInfoInd_IePtr && ccInfoInd_IePtr->IeLength != 0)
			dectProcessCCKeyPadInfo(handset, ccInfoInd_IeBlockPtr, ccInfoInd_IeBlockLength);
	}
}





static void connect_cfm(unsigned char *buf) {  

	ApiHandsetIdType handset;
  
	handset = ((ApiFpCcConnectCfmType*) buf)->CallReference.HandsetId;
	ast_verbose("Connected to handset %d\n", handset );
}


static void alert_ind(unsigned char *buf) {

	ApiHandsetIdType handset;
  
	handset = ((ApiFpCcConnectCfmType*) buf)->CallReference.HandsetId;
	ast_verbose("handset %d ringing\n", handset );
	
	/* No CLIP, just send API_FP_CC_INFO_REQ with ring signal  */
	ApiFpCcInfoReqType * ringCcInfoReq =  malloc( sizeof(ApiFpCcInfoReqType) );
	ringCcInfoReq->Primitive                 = API_FP_CC_INFO_REQ;
	ringCcInfoReq->CallReference.HandsetId   = handset;
	ringCcInfoReq->ProgressInd               = API_IN_BAND_AVAILABLE;
	ringCcInfoReq->Signal                    = API_CC_SIGNAL_ALERT_ON_PATTERN_1;
	ringCcInfoReq->InfoElementLength         = 0;
	dectDrvWrite((unsigned char *)ringCcInfoReq, sizeof(ApiFpCcInfoReqType));
	ast_verbose("OUTPUT: API_FP_CC_INFO_REQ Ring on\n");

}


static init_cfm(unsigned char *buf) {

	ENDPT_STATE    endptState;
	EPCMD_PARMS    consoleCmdParams;
	int i;

	/* Dect stack initialized */
	/* Initialize dect procesing in enpoint driver */

	/* for (i = 0; i < 4; i++) { */
	memset( &consoleCmdParams,0, sizeof(consoleCmdParams) );
	memset( &endptState, 0, sizeof(endptState) );
	endptState.lineId = 0;
	vrgEndptConsoleCmd( &endptState,
			    EPCMD_DECT_START_BUFF_PROC,
			    &consoleCmdParams );
	/* } */

}


static void connect_ind(unsigned char *buf) {

	ApiHandsetIdType handset;
  	struct brcm_pvt *p;
	struct brcm_subchannel *sub;
	unsigned char o_buf[5];

	handset = ((ApiFpCcConnectCfmType*) buf)->CallReference.HandsetId;

	/* Signal offhook to endpoint */
	vrgEndptSendCasEvtToEndpt( (ENDPT_STATE *)&endptObjState[handset - 1], CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_OFFHOOK );

	ast_verbose("Handset %d answered\n", handset);

	//cmsLog_notice("OUTPUT: API_FP_CC_CONNECT_RES");                                                                                             
	//BUSM_SendMailP2NoInfoElements(0, USER_TASK, API_FP_CC_CONNECT_RES, handset , RSS_SUCCESS); 


	/* write endpoint id to device */
	*(o_buf + 0) = ((API_FP_CC_CONNECT_RES & 0xff00) >> 8);
	*(o_buf + 1) = ((API_FP_CC_CONNECT_RES & 0x00ff) >> 0);
	*(o_buf + 2) = handset;
	*(o_buf + 3) = 0;
	*(o_buf + 4) = handset - 1; /* endpoint id */

	ast_verbose("API_FP_CC_CONNECT_RES\n");
	dectDrvWrite(o_buf, 5);

	p = brcm_get_pvt_from_lineid(iflist, handset - 1);
	if (!p)
		return;


	ast_mutex_lock(&p->lock);
	sub = brcm_get_active_subchannel(p);

	if (!sub) {
		ast_verbose("Failed to get active subchannel\n");
		return;
	}

	/* Pick up call waiting */
	if (!sub->connection_init) {
		ast_verbose("create_connection()\n");
		brcm_create_connection(sub);
	}

	if (sub->owner) {
		ast_queue_control(sub->owner, AST_CONTROL_ANSWER);
		sub->channel_state = INCALL;
	}
	ast_mutex_unlock(&p->lock);

}


static void handset_present_ind(unsigned char *mail)
{
	
	int handset;

	handset = ((ApiFpMmHandsetPresentIndType*) mail)->HandsetId;
	ast_verbose("INPUT: API_FP_MM_HANDSET_PRESENT_IND from handset (%d)\n", handset);

	
	/* Retrieve MANIC and MODIC from Info elements */
	ApiInfoElementType *IeBlockPtr = (ApiInfoElementType *)&(((ApiFpMmHandsetPresentIndType*) mail)->InfoElement[0]);
	unsigned short IeBlockLength = ((ApiFpMmHandsetPresentIndType*) mail)->InfoElementLength;
	ApiInfoElementType* IePtr = NULL;



	/* Process API_IE_CODEC_LIST if present */
	if( (IePtr =  ApiGetInfoElement(IeBlockPtr, IeBlockLength, API_IE_CODEC_LIST)) ) {
		dectDumpHsetCodecList( IePtr );
	}









}



static void handle_data(unsigned char *buf) {

	RosPrimitiveType primitive;
	
	primitive = ((recDataType *) buf)->PrimitiveIdentifier;

	switch (primitive) {

	case API_FP_CC_RELEASE_IND:
		ast_verbose("API_FP_CC_RELEASE_IND\n");
		dect_release_ind(buf);
		break;

	case API_FP_CC_RELEASE_CFM:
		ast_verbose("API_FP_CC_RELEASE_CFM\n");
		dect_release_cfm(buf);
		break;

	case API_FP_CC_SETUP_IND:
		ast_verbose("API_FP_CC_SETUP_IND\n");
		dect_setup_ind(buf);
		break;

	case API_FP_CC_INFO_IND:
		ast_verbose("API_FP_CC_INFO_IND\n");
		dect_info_ind(buf);
		break;
      
	case API_FP_CC_REJECT_IND:
		ast_verbose("API_FP_CC_REJECT_IND\n");
		break;

	case API_FP_CC_CONNECT_CFM:
		ast_verbose("API_FP_CC_CONNECT_CFM\n");
		connect_cfm(buf);
		break;

	case API_FP_CC_CONNECT_IND:
		ast_verbose("API_FP_CC_CONNECT_IND\n");
		connect_ind(buf);
		break;

	case API_FP_MM_HANDSET_PRESENT_IND:
		ast_verbose("API_FP_MM_HANDSET_PRESENT_IND\n");
		handset_present_ind(buf);
		break;

	case API_FP_MM_SET_REGISTRATION_MODE_CFM:
		ast_verbose("API_FP_MM_SET_REGISTRATION_MODE_CFM\n");
		break;

	case API_FP_MM_REGISTRATION_COMPLETE_IND:
		ast_verbose("API_FP_MM_REGISTRATION_COMPLETE_IND\n");
		break;

	case API_FP_LINUX_INIT_CFM:
		ast_verbose("API_FP_LINUX_INIT_CFM\n");
		init_cfm(buf);
		break;

	case API_FP_CC_ALERT_IND:
		ast_verbose("API_FP_CC_ALERT_IND\n");
		alert_ind(buf);
		break;

	case API_FP_LINUX_NVS_UPDATE_IND:
		ast_verbose("API_FP_LINUX_NVS_UPDATE_IND\n");
		nvs_update_ind(buf);
		break;

	default:
		ast_verbose("dect event unknown\n");
	}


}






static void nvs_update_ind(unsigned char *mail)
{
	int fd, ret;
	unsigned char buf[API_FP_LINUX_NVS_SIZE];
	DECT_NVS_DATA nvs;

	nvs.offset = ((ApiFpLinuxNvsUpdateIndType *) mail)->NvsOffset;
	nvs.nvsDataLength = ((ApiFpLinuxNvsUpdateIndType *) mail)->NvsDataLength;
	nvs.nvsDataPtr = (unsigned char *)&((ApiFpLinuxNvsUpdateIndType *) mail)->NvsData;

	fd = open("/etc/dect/nvs", O_RDWR);
	if (fd == -1) {
		ast_verbose("Error: open\n");
		exit(EXIT_FAILURE);
	}

	if (nvs.offset + nvs.nvsDataLength > API_FP_LINUX_NVS_SIZE) {
		ast_verbose("Error: Invalid nvs update packet\n");
		exit(EXIT_FAILURE);
	}

	if (lseek(fd, nvs.offset, SEEK_SET) == -1) {
		ast_verbose("Error: lseek\n");
		exit(EXIT_FAILURE);
	}

	if (write(fd, nvs.nvsDataPtr, nvs.nvsDataLength) == -1) {
		ast_verbose("Error: write\n");
		exit(EXIT_FAILURE);
	}

	ret = close(fd);
	if (ret == -1) {
		ast_verbose("Error: close\n");
		exit(EXIT_FAILURE);
	}


}


static void nvs_get_data( unsigned char *pNvsData )
{
	int fd, ret;
	
	if (pNvsData == NULL) {
		
		printf("%s: error %d\n", __FUNCTION__, errno);
		return;
	}

	
	fd = open("/etc/dect/nvs", O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	ret = read(fd, pNvsData, API_FP_LINUX_NVS_SIZE);
	if (ret == -1) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	ret = close(fd);
	if (ret == -1) {
		perror("close");
		exit(EXIT_FAILURE);
	}


}



static int dect_init(void)
{
	int fd, r;
	ApiFpLinuxInitReqType *t = NULL;
	DECTSHIMDRV_INIT_PARAM parm;


	fd = open("/dev/dectshim", O_RDWR);
  
	if (fd == -1) {
		ast_verbose("%s: open error %d\n", __FUNCTION__, errno);
		return -1;
	}


	r = ioctl(fd, DECTSHIMIOCTL_INIT_CMD, &parm);
	if (r != 0) {
		ast_verbose("%s: ioctl error %d\n", __FUNCTION__, errno);
	}

	close(fd);
  
	ast_verbose("sizeof(ApiFpLinuxInitReqType): %d\n", sizeof(ApiFpLinuxInitReqType));

	/* download the eeprom values to the DECT driver*/
	t = (ApiFpLinuxInitReqType*) malloc(sizeof(ApiFpLinuxInitReqType));
	t->Primitive = API_FP_LINUX_INIT_REQ;
	nvs_get_data(t->NvsData);

	dectDrvWrite(t, sizeof(ApiFpLinuxInitReqType));
	

	return r;
}



EPSTATUS vrgEndptConsoleCmd( ENDPT_STATE *endptState, EPCONSOLECMD cmd, EPCMD_PARMS *consoleCmdParams )
{
	ENDPOINTDRV_CONSOLE_CMD_PARM tConsoleParm;
	int fileHandle;

	fileHandle = open("/dev/bcmendpoint0", O_RDWR);

	tConsoleParm.state      = endptState;
	tConsoleParm.cmd        = cmd;
	tConsoleParm.lineId     = endptState->lineId;
	tConsoleParm.consoleCmdParams = consoleCmdParams;
	tConsoleParm.epStatus   = EPSTATUS_DRIVER_ERROR;
	tConsoleParm.size       = sizeof(ENDPOINTDRV_CONSOLE_CMD_PARM);

	if ( ioctl( fileHandle, ENDPOINTIOCTL_ENDPT_CONSOLE_CMD, &tConsoleParm ) != IOCTL_STATUS_SUCCESS )
		ast_verbose("%s: error during ioctl", __FUNCTION__);

	close(fileHandle);

	return( tConsoleParm.epStatus );
}



int do_read(int fd, void *buf, int size) {

	int count = 0;

	while (count < size)
		count += read(fd, buf + count, size - count);
	return count;
}


void *brcm_monitor_dect(void *data) {
  
	int len, i, res;
	struct sockaddr_in remote_addr;
	unsigned char buf[API_FP_LINUX_MAX_MAIL_SIZE];
	int fdmax, pkt_len;
	fd_set rd_fdset;
	fd_set rfds;
  
	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_addr.s_addr = INADDR_ANY;
	remote_addr.sin_port = htons(7777);


	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	if (connect(s, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr)) < 0) {
		perror("connect");
		return -1;
	}


	fdmax = s;

	FD_SET(s, &rd_fdset);

	/* Initialize dectshim layer */
	dect_init();

	/* Read loop */
	while (1) {
    
		memcpy(&rfds, &rd_fdset, sizeof(fd_set));

		res = select(fdmax + 1, &rfds, NULL, NULL, NULL);
		if (res == -1) {
			ast_verbose("error: select");
			return NULL;
		}

		if (FD_ISSET(s, &rfds)) {

                        struct dect_packet p;
                        len = do_read(s, &p, sizeof(struct packet_header));

			if (p.size <= MAX_MAIL_SIZE)
				len = do_read(s, p.data, p.size - sizeof(struct packet_header));

			if (len > 0) {

				/* debug printout */
				ast_verbose("\n[RDECT][%04d] - ", len);
				for (i = 0; i < len; i++)
					ast_verbose("%02x ", p.data[i]);
				ast_verbose("\n");

			}

			handle_data(p.data);

		}
	}
}



