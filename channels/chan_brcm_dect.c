
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

/* #include <ApiFpProject.h> */
/* #include <dectUtils.h> */
#include <dectshimdrv.h>
/* #include <dectNvsCtl.h> */

#include <Api/CodecList/ApiCodecList.h>
#include <Api/FpCc/ApiFpCc.h>
//#include <Api/FpFwu/ApiFpFwu.h>
#include <Api/FpMm/ApiFpMm.h>
#include <Api/FpNoEmission/ApiFpNoEmission.h>
#include <Api/GenEveNot/ApiGenEveNot.h>
#include <Api/Las/ApiLas.h>
#include <Api/Linux/ApiLinux.h>
//#include <Api/Project/ApiProject.h>
#include <Api/FpAudio/ApiFpAudio.h>

#include "chan_brcm.h"
#include "chan_brcm_dect.h"

void dectSendClip(char* cid, int handset);

#define DECT_NVS_SIZE 4096
#define API_LINUX_MAX_MAIL_SIZE 0x100


typedef struct
{
	unsigned short offset;
	unsigned short nvsDataLength;
	unsigned char* nvsDataPtr;

} DECT_NVS_DATA;

int s;

char nbwbCodecList[NBWB_CODECLIST_LENGTH]={0x01, 0x02, 0x03, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x04};
char nbCodecList[]={0x01, 0x01, 0x02, 0x00, 0x00, 0x04};
char wbCodecList[]={0x01, 0x01, 0x03, 0x00, 0x00, 0x01};


rsuint8 NarrowCodecArr[30];
rsuint8 WideCodecArr[30];

ApiInfoElementType *NarrowBandCodecIe = (ApiInfoElementType*) NarrowCodecArr;
const rsuint16 NarrowBandCodecIeLen = (RSOFFSETOF(ApiInfoElementType, IeData) + 6);

ApiInfoElementType *WideBandCodecIe = (ApiInfoElementType*) WideCodecArr;
const rsuint16 WideBandCodecIeLen = (RSOFFSETOF(ApiInfoElementType, IeData) + 6);

ApiFpCcAudioIdType OutAudio;
ApiCallReferenceType OutCallReference;


extern VRG_ENDPT_STATE endptObjState[MAX_NUM_LINEID];
extern const DTMF_CHARNAME_MAP dtmf_to_charname[];
extern struct brcm_pvt *iflist;



struct dect_handset {
	enum channel_state state;
	char cid[CID_MAX_LEN];
	ApiCallReferenceType CallReference;
};

struct dect_handset handsets[MAX_NR_HANDSETS];


const struct brcm_channel_tech dect_tech = {
	.signal_ringing = dect_signal_ringing,
	.signal_ringing_callerid_pending = dect_signal_ringing_callerid_pending,
	.signal_callerid = dect_signal_callerid,
	.stop_ringing = dect_stop_ringing,
	.stop_ringing_callerid_pending = dect_stop_ringing_callerid_pending,
};


static int bad_handsetnr(int handset) {

	if ((handset <= 0) || (handset > MAX_NR_HANDSETS)) {
		ast_verbose("Bad handset nr: %d\n", handset);
		return 1;
	}
	return 0;
}


int dect_signal_ringing_callerid_pending(struct brcm_pvt *p) {
	dect_signal_ringing(p);
	return 0;
}

int dect_signal_callerid(const struct ast_channel *chan, struct brcm_subchannel *s) {
	
	int handset = s->parent->line_id + 1;
	ast_verbose("Caller id: %s\n", chan->connected.id.number.str);
	
	if (bad_handsetnr(handset))
		return;

	
	strncpy(handsets[handset].cid, chan->connected.id.number.str, CID_MAX_LEN);

	return 0;
}

int dect_stop_ringing(struct brcm_pvt *p) {
	dect_hangup(p->line_id + 1);
	return 0;
}

int dect_stop_ringing_callerid_pending(struct brcm_pvt *p) {
	dect_hangup(p->line_id + 1);
	return 0;
}



int dect_signal_ringing(struct brcm_pvt *p)
{
	ast_verbose("dect_signal_ringing\n");
	ast_verbose("line_id: %d\n", p->line_id); 

	dect_ring_handset(p->line_id + 1);
	return 0;
}


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

	
	if (bad_handsetnr(handset))
		return;

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
					((ApiFpCcSetupReqType *) pingMailPtr)->TerminalId = handset;
					((ApiFpCcSetupReqType *) pingMailPtr)->BasicService = API_BASIC_SPEECH;
					((ApiFpCcSetupReqType *) pingMailPtr)->CallClass    = API_CC_NORMAL;
					((ApiFpCcSetupReqType *) pingMailPtr)->AudioId.SourceTerminalId     = 0; /* 0 is the base station id */
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


void dectSendClip(char* cid, int handset)
{
	unsigned char callingNumLength;
	unsigned char callingNameLength;
	unsigned short clipMailLength = 0;
	ApiFpCcInfoReqType * clipMailPtr = NULL;
	ApiInfoElementType *clipIeBlockPtr = NULL;
	unsigned short clipIeBlockLength = 0;
	unsigned char *queuePtr;
	ApiCallingNumberType * callingNum = NULL;
	ApiCodecListType* codecList = NULL;
	ApiInfoElementType *IeBlockPtr;
	unsigned char codecListLength;
	unsigned short IeBlockLength;
	ApiCcBasicServiceType basicService;

	ast_verbose("dectSendClip:cid %s handset: %d\n", cid, handset);

	if (bad_handsetnr(handset))
		return;


	
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
		ApiBuildInfoElement( &clipIeBlockPtr,
				     &clipIeBlockLength,
				     API_IE_CALLING_PARTY_NUMBER,
				     (sizeof(ApiCallingNumberType) - 1) + callingNumLength ,
				     (unsigned char*)callingNum);

		/* free infoElement */
		free(callingNum);
	}
	

	/*****************************************************
	 * create API_FP_CC_INFO_REQ mail queue element *
	 *****************************************************/
	
	/* Allocate memory for queue element */
	clipMailLength = ((sizeof(ApiFpCcInfoReqType)-1) + clipIeBlockLength );
	queuePtr = (unsigned char *) malloc( 2 + clipMailLength );


	if (queuePtr != NULL) {

		memset(queuePtr, 0, 2 + clipMailLength);
		queuePtr[0] = (unsigned char)(clipMailLength >>8);
		queuePtr[1] = (unsigned char)(clipMailLength & 0x00FF);

		/* Assign mail pointer */
		clipMailPtr = (ApiFpCcInfoReqType *) (queuePtr + 2);
		

		/* Fillout mail contents */
		((ApiFpCcInfoReqType *) clipMailPtr)->Primitive                 = API_FP_CC_INFO_REQ;
		((ApiFpCcInfoReqType *) clipMailPtr)->CallReference = handsets[handset].CallReference;
		((ApiFpCcInfoReqType *) clipMailPtr)->ProgressInd = API_PROGRESS_INVALID;
		((ApiFpCcInfoReqType *) clipMailPtr)->Signal = API_CC_SIGNAL_CUSTOM_NONE;

		/* Copy over infoElements */
		memcpy( &(((ApiFpCcInfoReqType *) clipMailPtr)->InfoElement[0]), clipIeBlockPtr, clipIeBlockLength );

		ApiFreeInfoElement( &clipIeBlockPtr );


		/* Size must be in little endian  */
		((ApiFpCcInfoReqType *) clipMailPtr)->InfoElementLength = clipIeBlockLength;

		/* Send mail */
		ast_verbose("OUTPUT: API_FP_CC_INFO_REQ");

		dectDrvWrite(clipMailPtr, clipMailLength);
		
		ast_free(queuePtr);
	}
}


void dect_ring_handset(int handset) {

        ApiFpCcSetupReqType* m;

	if (bad_handsetnr(handset))
		return;


	ast_verbose("dect_ring_handset: %d\n", handset);

        m = (ApiFpCcSetupReqType*) malloc(sizeof(ApiFpCcSetupReqType));

	OutCallReference.Value = 0;
        OutCallReference.Instance.Host = 0;
	OutCallReference.Instance.Fp = handset;



        OutAudio.IntExtAudio = API_IEA_EXT;
	OutAudio.AudioEndPointId = handset - 1;

        m->Primitive = API_FP_CC_SETUP_REQ;
	m->CallReference = OutCallReference;
	m->TerminalId = handset;
        m->AudioId = OutAudio;
	m->BasicService = API_BASIC_SPEECH;
        m->CallClass = API_CC_NORMAL;
        m->Signal = API_CC_SIGNAL_ALERT_ON_PATTERN_2;
	m->InfoElementLength = 0;

	dectDrvWrite(m, sizeof(ApiFpCcSetupReqType));
	free(m);

}





void dectDrvWrite(void *data, int size)
{   
	int i;
	unsigned char* cdata = (unsigned char*)data;

	ast_verbose("[WDECT][%04d] - ",size);
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
	ast_verbose("ApiGetInfoElement\n");
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


void dect_conf_init(void)
{
	ast_verbose("\n\n\nDECT conf init\n\n\n");
	NarrowBandCodecIe->Ie = API_IE_CODEC_LIST;
	NarrowBandCodecIe->IeLength = 6;
	NarrowBandCodecIe->IeData[0] = 0x01; // NegotiationIndicator , Negotiation possible                              
	NarrowBandCodecIe->IeData[1] = 0x01; // NoOfCodecs                                                               
	NarrowBandCodecIe->IeData[2] = 0x02; // API_CT_G726 API_MDS_1_MD                                                 
	NarrowBandCodecIe->IeData[3] = 0x00;  // MacDlcService                                                           
	NarrowBandCodecIe->IeData[4] = 0x00;  // CplaneRouting  API_CPR_CS                                               
	NarrowBandCodecIe->IeData[5] = 0x04;  // SlotSize API_SS_FS fullslot                                             

	WideBandCodecIe->Ie = API_IE_CODEC_LIST;
	WideBandCodecIe->IeLength  = 6;
	WideBandCodecIe->IeData[0] = 0x01;  // NegotiationIndicator , Negotiation possible                               
	WideBandCodecIe->IeData[1] = 0x01;  // NoOfCodecs                                                                
	WideBandCodecIe->IeData[2] = 0x03;  //                                                                           
	WideBandCodecIe->IeData[3] = 0x00;
	WideBandCodecIe->IeData[4] = 0x00;
	WideBandCodecIe->IeData[5] = 0x01; //                                                                            

	//PcmBufCtrlStarted=FALSE;

}



static void dect_setup_ind(ApiFpCcSetupIndType * m) {

	ApiInfoElementType *IePtr;
	ApiInfoElementType *IeBlockPtr;
	unsigned short IeBlockLength;
	unsigned char o_buf[5];
	ApiCodecListType codecList;
	unsigned char *newMailPtr;
	int newMailSize;
	ApiCalledNumberType * calledNumber;
	ApiSystemCallIdType *callIdPtr;
	int handset;
	int endpt_id;
	ApiCallReferenceType CallReferenceInitiating;
	ApiTerminalIdType TerminalIdInitiating;
	ApiFpCcAudioIdType Audio;
	ApiFpCcConnectReqType* req;	
	
	CallReferenceInitiating = m->CallReference;
	TerminalIdInitiating = m->TerminalId;

	handset = m->TerminalId;

	if (bad_handsetnr(handset))
		return;


	ast_verbose("handset: %d\n", (int) handset);

	CallReferenceInitiating.Instance.Fp = handset;
	
	handsets[handset].CallReference = CallReferenceInitiating;

	endpt_id = handset - 1;
        Audio.IntExtAudio = API_IEA_EXT;
	Audio.AudioEndPointId = endpt_id;


	/* Signal offhook to endpoint */
	vrgEndptSendCasEvtToEndpt( (ENDPT_STATE *)&(endptObjState[endpt_id]), CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_OFFHOOK );

	ApiFpCcSetupResType* r = (ApiFpCcSetupResType*) malloc(sizeof(ApiFpCcSetupResType));

	r->Primitive = API_FP_CC_SETUP_RES;
	r->CallReference = CallReferenceInitiating;
	r->Status = RSS_SUCCESS;
	r->AudioId = Audio;
	
	ast_verbose("API_FP_CC_SETUP_RES\n");
	dectDrvWrite(r, sizeof(ApiFpCcSetupResType));
	free(r);


	req = (ApiFpCcConnectReqType*) malloc((sizeof(ApiFpCcConnectReqType) - 1 + NarrowBandCodecIeLen));

	req->Primitive = API_FP_CC_CONNECT_REQ;
	req->CallReference = CallReferenceInitiating;
	req->InfoElementLength = NarrowBandCodecIeLen;
	memcpy(req->InfoElement,(rsuint8*)NarrowBandCodecIe,NarrowBandCodecIeLen);

	ast_verbose("API_FP_CC_CONNECT_REQ\n");
	dectDrvWrite(req, sizeof(ApiFpCcConnectReqType) - 1 + NarrowBandCodecIeLen);
	free(req);

	return;
}



static void audio_format_cfm(ApiFpSetAudioFormatCfmType * m) {

	ast_verbose("audio_format_cfm\n");

}


static void dect_release_ind(ApiFpCcReleaseIndType *m) {

	int handset = m->CallReference.Instance.Fp;
	ApiFpCcReleaseResType* r = (ApiFpCcReleaseResType*) malloc(sizeof(ApiFpCcReleaseResType));

	if (bad_handsetnr(handset))
		return;


	ast_verbose("handset: %d\n", handset);

	r->Primitive = API_FP_CC_RELEASE_RES;
	r->CallReference = m->CallReference;
	r->Status = RSS_SUCCESS;
	r->InfoElementLength = 0;
	r->InfoElement[1] = NULL;

	handsets[handset].CallReference.Instance.Fp = 0;

	/* Signal onhook to endpoint */
	vrgEndptSendCasEvtToEndpt((ENDPT_STATE *)&endptObjState[handset - 1], CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_ONHOOK );

	ast_verbose("API_FP_CC_RELEASE_RES\n");
	dectDrvWrite(r, sizeof(ApiFpCcReleaseResType));

}



static void dect_release_cfm(ApiFpCcReleaseCfmType *m) {

	int handset = m->CallReference.Instance.Fp;

	ast_verbose("dect_release_cfm: %d\n", handset);

	if (bad_handsetnr(handset))
		return;

	/* Signal onhook to endpoint */
	vrgEndptSendCasEvtToEndpt((ENDPT_STATE *)&endptObjState[handset - 1], CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_ONHOOK );
}





void dect_hangup(int handset) {

	ApiFpCcReleaseReqType *m = malloc(sizeof(ApiFpCcReleaseReqType));

	ast_verbose("dect_hangup: %d\n", handset);

	if (bad_handsetnr(handset))
		return;
	
	if (handsets[handset].CallReference.Instance.Fp == 0)
		return;

	m->Primitive = API_FP_CC_RELEASE_REQ;
	m->CallReference = handsets[handset].CallReference;
	m->Reason = API_RR_UNEXPECTED_MESSAGE;
	m->InfoElementLength = 0;

	printf("API_FP_CC_RELEASE_REQ\n");
	dectDrvWrite(m, sizeof(ApiFpCcReleaseReqType));
	free(m);

}


static void 
process_keypad_info(unsigned char handset,
			ApiInfoElementType* IeBlockPtr,
			unsigned short IeBlockLength )
{
	ApiMultikeyPadType * keyPadEntry = NULL;
	unsigned char keyPadLen;
	ApiInfoElementType* IePtr = NULL;
	int i, j;
	struct brcm_pvt *p;
	struct brcm_subchannel *sub;
   
	if (bad_handsetnr(handset))
		return;


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

		/* Get locks in correct order */
		ast_mutex_lock(&p->lock);

		struct brcm_subchannel *sub = brcm_get_active_subchannel(p);
		struct brcm_subchannel *sub_peer = brcm_subchannel_get_peer(sub);
		struct ast_channel *owner = sub->owner;
		struct ast_channel *peer_owner = sub_peer->owner;

		if (sub->owner) {
			ast_channel_ref(owner);
		}
		if (sub_peer->owner) {
			ast_channel_ref(peer_owner);
		}
		ast_mutex_unlock(&p->lock);

		if (owner && peer_owner) {
			if (owner < peer_owner) {
				ast_channel_lock(owner);
				ast_channel_lock(peer_owner);
			}
			else {
				ast_channel_lock(peer_owner);
				ast_channel_lock(owner);
			}
		}
		else if (owner) {
			ast_channel_lock(owner);
		}
		else if (peer_owner) {
			ast_channel_lock(peer_owner);
		}
		ast_mutex_lock(&p->lock);

		if (sub) {
			for (j = 0; j < 2; j++) { // we need to send two events: press and depress

				unsigned int old_state = sub->channel_state;
				handle_dtmf(dtmfMap->event, sub, sub_peer, owner, peer_owner);
				if (sub->channel_state == DIALING && old_state != sub->channel_state) {

					/* DTMF event took channel state to DIALING. Stop dial tone. */
					ast_log(LOG_DEBUG, "Dialing. Stop dialtone.\n");
					brcm_stop_dialtone(p);
				}
			}
		}
		ast_mutex_unlock(&p->lock);

		if (owner) {
			ast_channel_unlock(owner);
			ast_channel_unref(owner);
		}
		if (peer_owner) {
			ast_channel_unlock(peer_owner);
			ast_channel_unref(peer_owner);
		}
	}
}

static void dect_info_ind(ApiFpCcInfoIndType *m) {
	

	ApiInfoElementType* info;
	int handset = m->CallReference.Instance.Fp;
	ApiInfoElementType *ie_blk  = (ApiInfoElementType *)m->InfoElement;
	unsigned short ie_blk_len    = m->InfoElementLength;

	ast_verbose("INPUT: API_FP_CC_INFO_IND\n");

	if (bad_handsetnr(handset))
		return;



	if( (ie_blk_len > 0) ) {
		info = ApiGetInfoElement(ie_blk, ie_blk_len, API_IE_MULTIKEYPAD);
		
		/* Process API_IE_MULTIKEYPAD if present */
		if(info && info->IeLength != 0)
			process_keypad_info(handset, ie_blk, ie_blk_len);
	}
}



static void setup_cfm(ApiFpCcSetupCfmType *m) {
	
	int handset = m->CallReference.Instance.Fp;
	
	ast_verbose("setup_cfm: %d\n", handset);

	if (bad_handsetnr(handset))
		return;

	handsets[handset].CallReference = m->CallReference;
}



static void connect_cfm(ApiFpCcConnectCfmType *m) {  

	int endpt_id, handset;

	handset = m->CallReference.Instance.Fp;

	if (bad_handsetnr(handset))
		return;


	ast_verbose("Connected to handset %d\n", handset);

	endpt_id = handset - 1;

	ApiFpSetAudioFormatReqType  *aud_req = (ApiFpSetAudioFormatReqType *)malloc(sizeof(ApiFpSetAudioFormatReqType));
	aud_req->Primitive = API_FP_SET_AUDIO_FORMAT_REQ;
	aud_req->DestinationId = endpt_id;
	aud_req->AudioDataFormat = AP_DATA_FORMAT_LINEAR_8kHz;

	ast_verbose("API_FP_SET_AUDIO_FORMAT_REQ\n");
	dectDrvWrite(aud_req, sizeof(ApiFpSetAudioFormatReqType));
	free(aud_req);

}


static void alert_ind(ApiFpCcAlertIndType *m) {

	int handset = m->CallReference.Instance.Fp;

	if (bad_handsetnr(handset))
		return;


	ast_verbose("handset %d ringing\n", handset );
	
	/* No CLIP, just send API_FP_CC_INFO_REQ with ring signal  */
	ApiFpCcInfoReqType * ringCcInfoReq =  malloc( sizeof(ApiFpCcInfoReqType) );
	ringCcInfoReq->Primitive                 = API_FP_CC_INFO_REQ;
	ringCcInfoReq->ProgressInd               = API_IN_BAND_AVAILABLE;
	ringCcInfoReq->Signal                    = API_CC_SIGNAL_ALERT_ON_PATTERN_1;
	ringCcInfoReq->InfoElementLength         = 0;
	dectDrvWrite((unsigned char *)ringCcInfoReq, sizeof(ApiFpCcInfoReqType));
	ast_verbose("OUTPUT: API_FP_CC_INFO_REQ Ring on\n");

	if (handsets[handset].cid[0] != '\0')  {
		ast_verbose("Signal cid: %s\n", handsets[handset].cid);
		dectSendClip(handsets[handset].cid, handset);
		handsets[handset].cid[0] = '\0';
	} else {

		/* No CLIP, just send API_FP_CC_INFO_REQ with ring signal  */
		ApiFpCcInfoReqType * ringCcInfoReq =  malloc( sizeof(ApiFpCcInfoReqType) );
		ringCcInfoReq->Primitive                 = API_FP_CC_INFO_REQ;
		ringCcInfoReq->ProgressInd               = API_IN_BAND_AVAILABLE;
		ringCcInfoReq->Signal                    = API_CC_SIGNAL_ALERT_ON_PATTERN_1;
		ringCcInfoReq->InfoElementLength         = 0;
		dectDrvWrite((unsigned char *)ringCcInfoReq, sizeof(ApiFpCcInfoReqType));
		ast_verbose("OUTPUT: API_FP_CC_INFO_REQ Ring on\n");
	}
}

static init_cfm(unsigned char *buf) {

	ENDPT_STATE    endptState;
	EPCMD_PARMS    consoleCmdParams;
	int i;
	unsigned char o_buf[3];
	
	ApiFpCcFeaturesReqType *t = NULL;

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


	t = (ApiFpCcFeaturesReqType*) malloc(sizeof(ApiFpCcFeaturesReqType));

	t->Primitive = API_FP_CC_FEATURES_REQ;
	t->ApiFpCcFeature = API_FP_CC_EXTENDED_TERMINAL_ID_SUPPORT;

	dectDrvWrite(t, sizeof(ApiFpCcFeaturesReqType));
	free(t);

}


static void connect_ind(ApiFpCcConnectIndType *m) {

	int handset = m->CallReference.Instance.Fp;
  	struct brcm_pvt *p;
	struct brcm_subchannel *sub;
	unsigned char o_buf[5];
	ApiCallReferenceType CallReference = m->CallReference;
	ApiFpCcConnectResType *r;
	struct ast_channel *owner;

	if (bad_handsetnr(handset))
		return;


	/* Signal offhook to endpoint */
	vrgEndptSendCasEvtToEndpt( (ENDPT_STATE *)&endptObjState[handset - 1], CAS_CTL_DETECT_EVENT, CAS_CTL_EVENT_OFFHOOK );
	ast_verbose("handset %d answered\n", handset);


	r = (ApiFpCcConnectResType *) malloc(sizeof(ApiFpCcConnectResType));
	r->Primitive = API_FP_CC_CONNECT_RES;
	r->CallReference = CallReference;
	r->Status = RSS_SUCCESS;
	r->InfoElementLength = 0;
	r->InfoElement[1] = NULL;

					     
	ast_verbose("API_FP_CC_CONNECT_RES\n");
	dectDrvWrite(r, sizeof(ApiFpCcConnectResType));


	ApiFpSetAudioFormatReqType  *aud_req = (ApiFpSetAudioFormatReqType *)malloc(sizeof(ApiFpSetAudioFormatReqType));
	aud_req->Primitive = API_FP_SET_AUDIO_FORMAT_REQ;
	aud_req->DestinationId = handset - 1;
	aud_req->AudioDataFormat = AP_DATA_FORMAT_LINEAR_8kHz;

	ast_verbose("API_FP_SET_AUDIO_FORMAT_REQ\n");
	dectDrvWrite(aud_req, sizeof(ApiFpSetAudioFormatReqType));
	free(aud_req);


	p = brcm_get_pvt_from_lineid(iflist, handset - 1);
	if (!p)
		return;


	ast_mutex_lock(&p->lock);
	sub = brcm_get_active_subchannel(p);

	if (!sub) {
		ast_mutex_unlock(&p->lock);
		ast_verbose("Failed to get active subchannel\n");
		return;
	}

	/* Pick up call waiting */
	if (!sub->connection_init) {
		ast_verbose("create_connection()\n");
		brcm_create_connection(sub);
	}

	owner = sub->owner;
	if (owner) {
		sub->channel_state = INCALL;
		ast_channel_ref(owner);
	}
	ast_mutex_unlock(&p->lock);

	if (owner) {
		ast_queue_control(owner, AST_CONTROL_ANSWER);
		ast_channel_unref(owner);
 	}

}

static void features_cfm(void)
{
	unsigned char o_buf[3];


	*(o_buf + 0) = ((API_FP_MM_START_PROTOCOL_REQ & 0xff00) >> 8);
	*(o_buf + 1) = ((API_FP_MM_START_PROTOCOL_REQ & 0x00ff) >> 0);
	*(o_buf + 2) = 0;

	ast_verbose("API_FP_MM_START_PROTOCOL_REQ\n");
	dectDrvWrite(o_buf, 3);

}


static void handset_present_ind(ApiFpMmHandsetPresentIndType *m)
{
	ApiFpMmHandsetPresentIndType *t = NULL;
	int handset = m->TerminalId;

	if (bad_handsetnr(handset))
		return;


	ast_verbose("INPUT: API_FP_MM_HANDSET_PRESENT_IND from handset (%d)\n", handset);
	
	/* Retrieve MANIC and MODIC from Info elements */
	ApiInfoElementType *IeBlockPtr = (ApiInfoElementType *)m->InfoElement;
	unsigned short IeBlockLength = m->InfoElementLength;
	ApiInfoElementType* IePtr = NULL;

	/* Process API_IE_CODEC_LIST if present */
	if( (IePtr =  ApiGetInfoElement(IeBlockPtr, IeBlockLength, API_IE_CODEC_LIST)) ) {
		dectDumpHsetCodecList( IePtr );
	}

}



static void handle_data(unsigned char *buf) {

	RosPrimitiveType primitive;
	
	primitive = ((ApifpccEmptySignalType *) buf)->Primitive;

	switch (primitive) {

	case API_FP_CC_RELEASE_IND:
		ast_verbose("API_FP_CC_RELEASE_IND\n");
		dect_release_ind((ApiFpCcReleaseIndType *)buf);
		break;

	case API_FP_CC_RELEASE_CFM:
		ast_verbose("API_FP_CC_RELEASE_CFM\n");
		dect_release_cfm((ApiFpCcReleaseCfmType *)buf);
		break;

	case API_FP_CC_SETUP_IND:
		ast_verbose("API_FP_CC_SETUP_IND\n");
		dect_setup_ind((ApiFpCcSetupIndType *)buf);
		break;

	case API_FP_CC_INFO_IND:
		ast_verbose("API_FP_CC_INFO_IND\n");
		dect_info_ind((ApiFpCcInfoIndType *)buf);
		break;
      
	case API_FP_CC_REJECT_IND:
		ast_verbose("API_FP_CC_REJECT_IND\n");
		break;

	case API_FP_CC_CONNECT_CFM:
		ast_verbose("API_FP_CC_CONNECT_CFM\n");
		connect_cfm((ApiFpCcConnectCfmType *)buf);
		break;

	case API_FP_CC_CONNECT_IND:
		ast_verbose("API_FP_CC_CONNECT_IND\n");
		connect_ind((ApiFpCcConnectIndType *)buf);
		break;

	case API_FP_MM_HANDSET_PRESENT_IND:
		ast_verbose("API_FP_MM_HANDSET_PRESENT_IND\n");
		handset_present_ind((ApiFpMmHandsetPresentIndType *)buf);
		break;

	case API_FP_MM_SET_REGISTRATION_MODE_CFM:
		ast_verbose("API_FP_MM_SET_REGISTRATION_MODE_CFM\n");
		break;

	case API_FP_MM_REGISTRATION_COMPLETE_IND:
		ast_verbose("API_FP_MM_REGISTRATION_COMPLETE_IND\n");
		break;

	case API_FP_CC_SETUP_CFM:
		ast_verbose("API_FP_CC_SETUP_CFM\n");
		setup_cfm((ApiFpCcSetupCfmType *)buf);
		break;

	case API_LINUX_INIT_CFM:
		ast_verbose("API_LINUX_INIT_CFM\n");
		init_cfm(buf);
		break;

	case API_FP_CC_ALERT_IND:
		ast_verbose("API_FP_CC_ALERT_IND\n");
		alert_ind((ApiFpCcAlertIndType *)buf);
		break;

	case API_LINUX_NVS_UPDATE_IND:
		ast_verbose("API_FP_LINUX_NVS_UPDATE_IND\n");
		nvs_update_ind(buf);
		break;

	case API_FP_MM_GET_REGISTRATION_COUNT_CFM:
		ast_verbose("API_FP_MM_GET_REGISTRATION_COUNT_CFM\n");
		break;

	case API_FP_MM_GET_HANDSET_IPUI_CFM:
		ast_verbose("API_FP_MM_GET_HANDSET_IPUI_CFM\n");
		break;

	case API_FP_CC_FEATURES_CFM:
		ast_verbose("API_FP_CC_FEATURES_CFM\n");
		features_cfm();
		break;

	case API_FP_SET_AUDIO_FORMAT_CFM:
		ast_verbose("API_FP_SET_AUDIO_FORMAT_CFM\n");
		audio_format_cfm((ApiFpSetAudioFormatCfmType *) buf);
		break;






	default:
		ast_verbose("dect event unknown\n");
	}


}






static void nvs_update_ind(unsigned char *mail)
{
	int fd, ret;
	unsigned char buf[DECT_NVS_SIZE];
	DECT_NVS_DATA nvs;

	nvs.offset = ((ApiLinuxNvsUpdateIndType *) mail)->NvsOffset;
	nvs.nvsDataLength = ((ApiLinuxNvsUpdateIndType *) mail)->NvsDataLength;
	nvs.nvsDataPtr = (unsigned char *)&((ApiLinuxNvsUpdateIndType *) mail)->NvsData;

	fd = open("/etc/dect/nvs", O_RDWR);
	if (fd == -1) {
		ast_verbose("Error: open\n");
		exit(EXIT_FAILURE);
	}

	if (nvs.offset + nvs.nvsDataLength > DECT_NVS_SIZE) {
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

	ret = read(fd, pNvsData, DECT_NVS_SIZE);
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
	ApiLinuxInitReqType *t = NULL;
	DECTSHIMDRV_INIT_PARAM parm;
	
	dect_conf_init();
	
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
  
	ast_verbose("sizeof(ApiLinuxInitReqType): %d\n", sizeof(ApiLinuxInitReqType));

	/* download the eeprom values to the DECT driver*/
	t = (ApiLinuxInitReqType*) malloc(RSOFFSETOF(ApiLinuxInitReqType, Data) + DECT_NVS_SIZE);
	t->Primitive = API_LINUX_INIT_REQ;
	t->LengthOfData = DECT_NVS_SIZE;
	nvs_get_data(t->Data);

	dectDrvWrite(t, RSOFFSETOF(ApiLinuxInitReqType, Data) + DECT_NVS_SIZE);
	

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
	unsigned char buf[API_LINUX_MAX_MAIL_SIZE];
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



