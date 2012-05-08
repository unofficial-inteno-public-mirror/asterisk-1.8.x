/****************************************************************************
*
* Copyright © 2001-2009 Broadcom Corporation
*
* This program is the proprietary software of Broadcom Corporation and/or its
* licensors, and may only be used, duplicated, modified or distributed
* pursuant to the terms and conditions of a separate, written license
* agreement executed between you and Broadcom (an "Authorized License").
* Except as set forth in an Authorized License, Broadcom grants no license
* (express or implied), right to use, or waiver of any kind with respect to
* the Software, and Broadcom expressly reserves all rights in and to the
* Software and all intellectual property rights therein.  IF YOU HAVE NO
* AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE IN ANY WAY,
* AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE ALL USE OF THE
* SOFTWARE.
*
* Except as expressly set forth in the Authorized License,
*
* 1.     This program, including its structure, sequence and organization,
*        constitutes the valuable trade secrets of Broadcom, and you shall
*        use all reasonable efforts to protect the confidentiality thereof,
*        and to use this information only in connection with your use of
*        Broadcom integrated circuit products.
*
* 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED
*        "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
*        REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
*        OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
*        DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
*        NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
*        ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
*        CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
*        OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
*
* 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM
*        OR ITS LICENSORS BE LIABLE FOR
*        (i)  CONSEQUENTIAL, INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY
*             DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY WAY RELATING TO
*             YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN IF BROADCOM
*             HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES; OR
*        (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
*             SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE
*             LIMITATIONS SHALL APPLY NOTWITHSTANDING ANY FAILURE OF
*             ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.
*
 ***************************************************************************
 * File Name  : EndpointDrv.h
 *
 * Description: This file contains the definitions and structures for the
 *              Linux IOCTL interface that used between the user mode Endpoint
 *              API library and the kernel Endpoint API driver.
 *
 * Updates    : 04/04/2002  YD.  Created.
 ***************************************************************************/

#if !defined(_ENDPOINTDRV_H_)
#define _ENDPOINTDRV_H_



/* Change this value when needed */
#define CHANNEL_VERSION "1.2"

#define DEFAULT_CALLER_ID "Unknown"
#define PHONE_MAX_BUF 480
#define DEFAULT_GAIN 0x100

#define TIMEMSEC 1000

#define PCMU 0
#define G726 2
#define G723 4
#define PCMA 8
#define G729 18
#define DTMF 128
#define RTCP 200

#define NOT_INITIALIZED -1
#define EPSTATUS_DRIVER_ERROR -1
#define MAX_NUM_LINEID 2
#define PACKET_BUFFER_SIZE 1024

#define NOT_INITIALIZED -1
#define EPSTATUS_DRIVER_ERROR -1
#define MAX_NUM_LINEID 2


enum channel_state {
    ONHOOK,
    OFFHOOK,
    DIALING,
    INCALL,
    ANSWER,
	CALLENDED,
	RINGING,
};

enum endpoint_type {
	FXS,
	FXO,
	DECT,
};


static struct brcm_pvt {
	ast_mutex_t lock;
	int fd;							/* Raw file descriptor for this device */
	struct ast_channel *owner;		/* Channel we belong to, possibly NULL */
	int connection_id;				/* Id of the connection, used to map the correct port, lineid matching parameter */
	char dtmfbuf[AST_MAX_EXTENSION];/* DTMF buffer per channel */
	int dtmf_len;					/* Length of DTMF buffer */
	int dtmf_first;					/* DTMF control state, button pushes generate 2 events, one on button down and one on button up */
	format_t lastformat;            /* Last output format */
	format_t lastinput;             /* Last input format */
	struct brcm_pvt *next;			/* Next channel in list */
	struct ast_frame fr;			/* Frame */
	char offset[AST_FRIENDLY_OFFSET];
	char buf[PHONE_MAX_BUF];					/* Static buffer for reading frames */
	int txgain, rxgain;             /* gain control for playing, recording  */
									/* 0x100 - 1.0, 0x200 - 2.0, 0x80 - 0.5 */
	int silencesupression;
	char context[AST_MAX_EXTENSION];
	char obuf[PHONE_MAX_BUF * 2];
	char ext[AST_MAX_EXTENSION];
	char language[MAX_LANGUAGE];
	char cid_num[AST_MAX_EXTENSION];
	char cid_name[AST_MAX_EXTENSION];
	unsigned int last_dtmf_ts;		/* Timer for initiating dialplan extention lookup */
	unsigned int channel_state;		/* Channel states */
	unsigned int connection_init;	/* State for endpoint id connection initialization */
	unsigned int last_dialtone_ts;	/* Timestamp to send a continious dialtone */
	int	endpoint_type;				/* Type of the endpoint fxs, fxo, dect */
	unsigned int sequence_number;	/* Endpoint RTP sequence number state */
	unsigned int time_stamp;		/* Endpoint RTP time stamp state */
	unsigned int ssrc;				/* Endpoint RTP synchronization source */
	int codec;						/* Used codec */
	unsigned int dt_counter;		/* dialtone counter */
	char autodial[AST_MAX_EXTENSION];	/* Extension to automatically dial when the phone is of hook */
} *iflist = NULL;



/* Includes. */
/* #include <bosTypes.h> JH: I added BOS_CFG_BIG_ENDIAN to make it compile */ 

#ifndef _TYPEDEFS_H_

typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef unsigned long   uint32;
typedef unsigned long long  uint64;
typedef signed char     int8;
typedef signed short    int16;
typedef signed long     int32;
typedef signed long long    int64;

#if !defined(__cplusplus) && !defined(__KERNEL__) && !defined(_LINUX_TYPES_H) && !defined(_LINUX_IF_H)
typedef int bool;
#endif

#endif

typedef unsigned char   byte;
// typedef unsigned long   sem_t;

typedef unsigned long   HANDLE,*PULONG,DWORD,*PDWORD;
#ifndef LONG
typedef signed long     LONG,*PLONG;
#endif

typedef unsigned int    *PUINT;
typedef signed int      INT;

typedef unsigned short  *PUSHORT;
typedef signed short    SHORT,*PSHORT;
typedef unsigned short  WORD,*PWORD;

typedef unsigned char   *PUCHAR;
typedef signed char     *PCHAR;

typedef void            *PVOID;

typedef unsigned char   BOOLEAN, *PBOOL, *PBOOLEAN;

typedef unsigned char   BYTE,*PBYTE;

typedef signed int      *PINT;

typedef signed char     INT8;
typedef signed short    INT16;
typedef signed long     INT32;

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned long   UINT32;

typedef unsigned char   UBOOL8;
typedef unsigned char   UCHAR;
typedef unsigned short  USHORT;
typedef unsigned int    UINT;
typedef unsigned long   ULONG;

typedef void            VOID;
typedef unsigned char   BOOL;

// These are also defined in typedefs.h in the application area, so I need to
// protect against re-definition.
#ifndef TYPEDEFS_H

// Maximum and minimum values for a signed 16 bit integer.
#define MAX_INT16 32767
#define MIN_INT16 -32768

// Useful for true/false return values.  This uses the
// Taligent notation (k for constant).
typedef enum
{
    kFalse = 0,
    kTrue = 1
} Bool;

#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE  0
#endif

#define READ32(addr)        (*(volatile UINT32 *)((ULONG)&addr))
#define READ16(addr)        (*(volatile UINT16 *)((ULONG)&addr))
#define READ8(addr)         (*(volatile UINT8  *)((ULONG)&addr))

#define VIRT_TO_PHY(a)  (((unsigned long)(a)) & 0x1fffffff)



/* Simple types */
typedef unsigned char   VRG_UINT8;
typedef signed char     VRG_SINT8;
typedef unsigned short  VRG_UINT16;
typedef signed short    VRG_SINT16;
typedef unsigned long   VRG_UINT32;
typedef long            VRG_SINT32;


/* Boolean */
typedef  int   VRG_BOOL;               /** VRG_TRUE or VRG_FALSE */
#define VRG_TRUE  1
#define VRG_FALSE 0               
#define VRG_MAX(x,y)              ( ( (x) > (y) ) ? (x) : (y) )

/*-------------------------------------------------------------------------
* OFFSETOF returns the offset (in units of sizeof) of a structure member
* from the beginning of a structure
*/

#define VRG_OFFSETOF( structName, memberName )  ( (size_t)&((structName *)0)->memberName )

/* ---- Variable Externs ------------------------------------------------- */
/* ---- Function Prototypes ---------------------------------------------- */





#ifndef BRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE
   /* Explicitly define VRG_COUNTRY_CFG_STATIC_PROFILE = 1*/
   #ifdef VRG_COUNTRY_CFG_STATIC_PROFILE
      #undef VRG_COUNTRY_CFG_STATIC_PROFILE 
   #endif /* VRG_COUNTRY_CFG_STATIC_PROFILE */

   #define VRG_COUNTRY_CFG_STATIC_PROFILE 1
#else
   /* Explicitly define VRG_COUNTRY_CFG_STATIC_PROFILE = 0*/
   #ifdef VRG_COUNTRY_CFG_STATIC_PROFILE
      #undef VRG_COUNTRY_CFG_STATIC_PROFILE 
   #endif /* VRG_COUNTRY_CFG_STATIC_PROFILE */

   #define VRG_COUNTRY_CFG_STATIC_PROFILE 0
#endif /* BRCM_VRG_COUNTRY_CFG_NON_STATIC_PROFILE */


#ifndef BRCM_VRG_COUNTRY_CFG_CUSTOM_PROFILES
   /* Explicitly define VRG_COUNTRY_CFG_ALL_PROFILES = 1*/
   #undef VRG_COUNTRY_CFG_ALL_PROFILES 
   #define VRG_COUNTRY_CFG_ALL_PROFILES 1
#else
   /* Explicitly define VRG_COUNTRY_CFG_ALL_PROFILES = 0*/
   #undef VRG_COUNTRY_CFG_ALL_PROFILES
   #define VRG_COUNTRY_CFG_ALL_PROFILES 0
#endif /* BRCM_VRG_COUNTRY_CFG_CUSTOM_PROFILES */

#if !VRG_COUNTRY_CFG_ALL_PROFILES
/* ------------ Includes -------------------------------------------------- */

#ifdef BRCM_VRG_COUNTRY_CFG_AUSTRALIA
   #define VRG_COUNTRY_CFG_AUSTRALIA      1
#else
   #define VRG_COUNTRY_CFG_AUSTRALIA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_AUSTRIA
   #define VRG_COUNTRY_CFG_AUSTRIA      1
#else
   #define VRG_COUNTRY_CFG_AUSTRIA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_BELGIUM
   #define VRG_COUNTRY_CFG_BELGIUM      1
#else
   #define VRG_COUNTRY_CFG_BELGIUM      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_BRAZIL
   #define VRG_COUNTRY_CFG_BRAZIL      1
#else
   #define VRG_COUNTRY_CFG_BRAZIL      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_CHILE
   #define VRG_COUNTRY_CFG_CHILE      1
#else
   #define VRG_COUNTRY_CFG_CHILE      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_CHINA
   #define VRG_COUNTRY_CFG_CHINA      1
#else
   #define VRG_COUNTRY_CFG_CHINA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_CZECH
   #define VRG_COUNTRY_CFG_CZECH      1
#else
   #define VRG_COUNTRY_CFG_CZECH      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_DENMARK
   #define VRG_COUNTRY_CFG_DENMARK      1
#else
   #define VRG_COUNTRY_CFG_DENMARK      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_ETSI
   #define VRG_COUNTRY_CFG_ETSI      1
#else
   #define VRG_COUNTRY_CFG_ETSI      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_FINLAND
   #define VRG_COUNTRY_CFG_FINLAND      1
#else
   #define VRG_COUNTRY_CFG_FINLAND      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_FRANCE
   #define VRG_COUNTRY_CFG_FRANCE      1
#else
   #define VRG_COUNTRY_CFG_FRANCE      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_GERMANY
   #define VRG_COUNTRY_CFG_GERMANY      1
#else
   #define VRG_COUNTRY_CFG_GERMANY      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_HUNGARY
   #define VRG_COUNTRY_CFG_HUNGARY      1
#else
   #define VRG_COUNTRY_CFG_HUNGARY      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_INDIA
   #define VRG_COUNTRY_CFG_INDIA      1
#else
   #define VRG_COUNTRY_CFG_INDIA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_IRELAND
   #define VRG_COUNTRY_CFG_IRELAND      1
#else
   #define VRG_COUNTRY_CFG_IRELAND      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_ITALY
   #define VRG_COUNTRY_CFG_ITALY      1
#else
   #define VRG_COUNTRY_CFG_ITALY      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_JAPAN
   #define VRG_COUNTRY_CFG_JAPAN      1
#else
   #define VRG_COUNTRY_CFG_JAPAN      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_NETHERLANDS
   #define VRG_COUNTRY_CFG_NETHERLANDS      1
#else
   #define VRG_COUNTRY_CFG_NETHERLANDS      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_NEW_ZEALAND
   #define VRG_COUNTRY_CFG_NEW_ZEALAND      1
#else
   #define VRG_COUNTRY_CFG_NEW_ZEALAND      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_NORTH_AMERICA
   #define VRG_COUNTRY_CFG_NORTH_AMERICA      1
#else
   #define VRG_COUNTRY_CFG_NORTH_AMERICA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_POLAND
   #define VRG_COUNTRY_CFG_POLAND      1
#else
   #define VRG_COUNTRY_CFG_POLAND      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_ROMANIA
   #define VRG_COUNTRY_CFG_ROMANIA      1
#else
   #define VRG_COUNTRY_CFG_ROMANIA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_SLOVAKIA
   #define VRG_COUNTRY_CFG_SLOVAKIA      1
#else
   #define VRG_COUNTRY_CFG_SLOVAKIA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_SLOVENIA
   #define VRG_COUNTRY_CFG_SLOVENIA      1
#else
   #define VRG_COUNTRY_CFG_SLOVENIA      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_SPAIN
   #define VRG_COUNTRY_CFG_SPAIN      1
#else
   #define VRG_COUNTRY_CFG_SPAIN      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_SWEDEN
   #define VRG_COUNTRY_CFG_SWEDEN      1
#else
   #define VRG_COUNTRY_CFG_SWEDEN      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_NORWAY
   #define VRG_COUNTRY_CFG_NORWAY      1
#else
   #define VRG_COUNTRY_CFG_NORWAY      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_TAIWAN
   #define VRG_COUNTRY_CFG_TAIWAN      1
#else
   #define VRG_COUNTRY_CFG_TAIWAN      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_SWITZERLAND
   #define VRG_COUNTRY_CFG_SWITZERLAND      1
#else
   #define VRG_COUNTRY_CFG_SWITZERLAND      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_TR57
   #define VRG_COUNTRY_CFG_TR57      1
#else
   #define VRG_COUNTRY_CFG_TR57      0
#endif

#ifdef BRCM_VRG_COUNTRY_CFG_UK
   #define VRG_COUNTRY_CFG_UK      1
#else
   #define VRG_COUNTRY_CFG_UK      0
#endif

/* ---- Constants and Types ---------------------------------------------- */

#else
/* The following define controls which countries are supported */

#ifndef VRG_COUNTRY_CFG_AUSTRALIA
#define VRG_COUNTRY_CFG_AUSTRALIA      1
#endif

#ifndef VRG_COUNTRY_CFG_AUSTRIA
#define VRG_COUNTRY_CFG_AUSTRIA        0
#endif

#ifndef VRG_COUNTRY_CFG_BELGIUM
#define VRG_COUNTRY_CFG_BELGIUM        1
#endif

#ifndef VRG_COUNTRY_CFG_BRAZIL
#define VRG_COUNTRY_CFG_BRAZIL         1
#endif

#ifndef VRG_COUNTRY_CFG_CHILE
#define VRG_COUNTRY_CFG_CHILE          1
#endif

#ifndef VRG_COUNTRY_CFG_CHINA
#define VRG_COUNTRY_CFG_CHINA          1
#endif

#ifndef VRG_COUNTRY_CFG_CZECH 
#define VRG_COUNTRY_CFG_CZECH          1
#endif

#ifndef VRG_COUNTRY_CFG_DENMARK
#define VRG_COUNTRY_CFG_DENMARK        1
#endif

#ifndef VRG_COUNTRY_CFG_ETSI
#define VRG_COUNTRY_CFG_ETSI           1
#endif

#ifndef VRG_COUNTRY_CFG_FINLAND
#define VRG_COUNTRY_CFG_FINLAND        1
#endif

#ifndef VRG_COUNTRY_CFG_FRANCE
#define VRG_COUNTRY_CFG_FRANCE         1
#endif

#ifndef VRG_COUNTRY_CFG_GERMANY
#define VRG_COUNTRY_CFG_GERMANY        1
#endif

#ifndef VRG_COUNTRY_CFG_HUNGARY
#define VRG_COUNTRY_CFG_HUNGARY        1
#endif

#ifndef VRG_COUNTRY_CFG_INDIA
#define VRG_COUNTRY_CFG_INDIA          1
#endif

#ifndef VRG_COUNTRY_CFG_IRELAND
#define VRG_COUNTRY_CFG_IRELAND        0
#endif

#ifndef VRG_COUNTRY_CFG_ITALY
#define VRG_COUNTRY_CFG_ITALY          1
#endif

#ifndef VRG_COUNTRY_CFG_JAPAN
#define VRG_COUNTRY_CFG_JAPAN          1
#endif

#ifndef VRG_COUNTRY_CFG_NETHERLANDS
#define VRG_COUNTRY_CFG_NETHERLANDS    1
#endif

#ifndef VRG_COUNTRY_CFG_NEW_ZEALAND
#define VRG_COUNTRY_CFG_NEW_ZEALAND    1
#endif

#ifndef VRG_COUNTRY_CFG_NORTH_AMERICA
#define VRG_COUNTRY_CFG_NORTH_AMERICA  1
#endif

#ifndef VRG_COUNTRY_CFG_POLAND
#define VRG_COUNTRY_CFG_POLAND         0
#endif

#ifndef VRG_COUNTRY_CFG_ROMANIA
#define VRG_COUNTRY_CFG_ROMANIA        0
#endif

#ifndef VRG_COUNTRY_CFG_SLOVAKIA
#define VRG_COUNTRY_CFG_SLOVAKIA       0
#endif

#ifndef VRG_COUNTRY_CFG_SLOVENIA
#define VRG_COUNTRY_CFG_SLOVENIA       0
#endif

#ifndef VRG_COUNTRY_CFG_SPAIN
#define VRG_COUNTRY_CFG_SPAIN          1
#endif

#ifndef VRG_COUNTRY_CFG_SWEDEN
#define VRG_COUNTRY_CFG_SWEDEN         1
#endif

#ifndef VRG_COUNTRY_CFG_NORWAY
#define VRG_COUNTRY_CFG_NORWAY         1
#endif

#ifndef VRG_COUNTRY_CFG_SWITZERLAND
#define VRG_COUNTRY_CFG_SWITZERLAND    1
#endif

#ifndef VRG_COUNTRY_CFG_TR57
#define VRG_COUNTRY_CFG_TR57           1
#endif

#ifndef VRG_COUNTRY_CFG_UK
#define VRG_COUNTRY_CFG_UK             1
#endif

#ifndef VRG_COUNTRY_CFG_TAIWAN
#define VRG_COUNTRY_CFG_TAIWAN             1
#endif

#endif  /* if !VRG_COUNTRY_CFG_ALL_PROFILES */


/* ---- Constants and Types ---------------------------------------------- */

/*
** The following will generate a list of countries as follows:
**
**        enum
**        {
**           VRG_COUNTRY_JAPAN,
**           VRG_COUNTRY_GERMANY,
**           VRG_COUNTRY_SWEDEN,
**           ...
**        } VRG_COUNTRY;
*/
#define COUNTRY_ARCHIVE_MAKE_NAME( country )    VRG_COUNTRY_##country,

typedef enum VRG_COUNTRY
{

#ifndef COUNTRY_ARCHIVE_MAKE_NAME
   #error "COUNTRY_ARCHIVE_MAKE_NAME must be defined!"
#endif

#if VRG_COUNTRY_CFG_AUSTRALIA
COUNTRY_ARCHIVE_MAKE_NAME( AUSTRALIA     )
#endif
#if VRG_COUNTRY_CFG_BELGIUM
COUNTRY_ARCHIVE_MAKE_NAME( BELGIUM       )
#endif
#if VRG_COUNTRY_CFG_BRAZIL
COUNTRY_ARCHIVE_MAKE_NAME( BRAZIL        )
#endif
#if VRG_COUNTRY_CFG_CHILE
COUNTRY_ARCHIVE_MAKE_NAME( CHILE         )
#endif
#if VRG_COUNTRY_CFG_CHINA
COUNTRY_ARCHIVE_MAKE_NAME( CHINA         )
#endif
#if VRG_COUNTRY_CFG_CZECH
COUNTRY_ARCHIVE_MAKE_NAME( CZECH         )
#endif
#if VRG_COUNTRY_CFG_DENMARK
COUNTRY_ARCHIVE_MAKE_NAME( DENMARK       )
#endif
#if VRG_COUNTRY_CFG_ETSI
COUNTRY_ARCHIVE_MAKE_NAME( ETSI          )
#endif
#if VRG_COUNTRY_CFG_FINLAND
COUNTRY_ARCHIVE_MAKE_NAME( FINLAND       )
#endif
#if VRG_COUNTRY_CFG_FRANCE
COUNTRY_ARCHIVE_MAKE_NAME( FRANCE        )
#endif
#if VRG_COUNTRY_CFG_GERMANY
COUNTRY_ARCHIVE_MAKE_NAME( GERMANY       )
#endif
#if VRG_COUNTRY_CFG_HUNGARY
COUNTRY_ARCHIVE_MAKE_NAME( HUNGARY       )
#endif
#if VRG_COUNTRY_CFG_INDIA
COUNTRY_ARCHIVE_MAKE_NAME( INDIA         )
#endif
#if VRG_COUNTRY_CFG_ITALY
COUNTRY_ARCHIVE_MAKE_NAME( ITALY         )
#endif
#if VRG_COUNTRY_CFG_JAPAN
COUNTRY_ARCHIVE_MAKE_NAME( JAPAN         )
#endif
#if VRG_COUNTRY_CFG_NETHERLANDS
COUNTRY_ARCHIVE_MAKE_NAME( NETHERLANDS   )
#endif
#if VRG_COUNTRY_CFG_NEW_ZEALAND
COUNTRY_ARCHIVE_MAKE_NAME( NEW_ZEALAND   )
#endif
#if VRG_COUNTRY_CFG_NORTH_AMERICA
COUNTRY_ARCHIVE_MAKE_NAME( NORTH_AMERICA )
#endif
#if VRG_COUNTRY_CFG_SPAIN
COUNTRY_ARCHIVE_MAKE_NAME( SPAIN         )
#endif
#if VRG_COUNTRY_CFG_SWEDEN
COUNTRY_ARCHIVE_MAKE_NAME( SWEDEN        )
#endif
#if VRG_COUNTRY_CFG_NORWAY
COUNTRY_ARCHIVE_MAKE_NAME( NORWAY        )
#endif
#if VRG_COUNTRY_CFG_SWITZERLAND
COUNTRY_ARCHIVE_MAKE_NAME( SWITZERLAND   )
#endif
#if VRG_COUNTRY_CFG_TR57
COUNTRY_ARCHIVE_MAKE_NAME( TR57          )
#endif
#if VRG_COUNTRY_CFG_UK
COUNTRY_ARCHIVE_MAKE_NAME( UK            )
#endif
#if VRG_COUNTRY_CFG_TAIWAN
COUNTRY_ARCHIVE_MAKE_NAME( TAIWAN        )
#endif
#if 0
#if VRG_COUNTRY_CFG_POLAND
COUNTRY_ARCHIVE_MAKE_NAME( POLAND        )
#endif
#if VRG_COUNTRY_CFG_AUSTRIA
COUNTRY_ARCHIVE_MAKE_NAME( AUSTRIA       )
#endif
#if VRG_COUNTRY_CFG_IRELAND
COUNTRY_ARCHIVE_MAKE_NAME( IRELAND       )
#endif
#if VRG_COUNTRY_CFG_SLOVAKIA
COUNTRY_ARCHIVE_MAKE_NAME( SLOVAKIA      )
#endif
#if VRG_COUNTRY_CFG_ROMANIA
COUNTRY_ARCHIVE_MAKE_NAME( ROMANIA       )
#endif
#if VRG_COUNTRY_CFG_SLOVENIA
COUNTRY_ARCHIVE_MAKE_NAME( SLOVENIA      )
#endif
#endif /* if 0 */

#undef COUNTRY_ARCHIVE_MAKE_NAME


   VRG_COUNTRY_MAX

} VRG_COUNTRY;





/* Voice codec types */
typedef enum
{
   CODEC_NULL,           /* NULL */
   CODEC_PCMU,           /* G.711 ulaw */
   CODEC_PCMA,           /* G.711 alaw */
   CODEC_G726_16,        /* G.726 - 16 kbps */
   CODEC_G726_24,        /* G.726 - 24 kbps */
   CODEC_G726_32,        /* G.726 - 32 kbps */
   CODEC_G726_40,        /* G.726 - 40 kbps */
   CODEC_G7231_53,       /* G.723.1 - 5.3 kbps */
   CODEC_G7231_63,       /* G.723.1 - 6.3 kbps */
   CODEC_G7231A_53,      /* G.723.1A - 5.3 kbps */
   CODEC_G7231A_63,      /* G.723.1A - 6.3 kbps */
   CODEC_G729A,          /* G.729A */
   CODEC_G729B,          /* G.729B */
   CODEC_G711_LINEAR,    /* Linear media queue data */
   CODEC_G728,           /* G.728 */
   CODEC_G729,           /* G.729 */
   CODEC_G729E,          /* G.729E */
   CODEC_BV16,           /* BRCM Broadvoice - 16 kbps */
   CODEC_BV32,           /* BRCM Broadvoice - 32 kbps */
   CODEC_NTE,            /* Named telephone events */
   CODEC_ILBC_20,        /* iLBC speech coder - 20 ms frame / 15.2 kbps */
   CODEC_ILBC_30,        /* iLBC speech coder - 30 ms frame / 13.3 kbps */
   CODEC_G7231_53_VAR,   /* G723.1 variable rates (preferred=5.3) */
   CODEC_G7231_63_VAR,   /* G723.1 variable rates (preferred=6.3) */
   CODEC_G7231_VAR,      /* G723.1 variable rates */
   CODEC_T38,            /* T.38 fax relay */
   CODEC_T38_MUTE,       /* Mute before switching to T.38 fax relay */
   CODEC_RED,            /* Redundancy - RFC 2198 */
   CODEC_G722_MODE_1,    /* G.722 Mode 1 64 kbps */
   CODEC_LINPCM128,      /* Narrowband linear PCM @ 128 Kbps */
   CODEC_LINPCM256,      /* Wideband linear PCM @ 256 Kbps */

   /* Maximum number of codec types.  Must be last defined codec, always. */
   CODEC_MAX_TYPES,

   /* Place-holder for dynamic codec types that haven't been mapped yet */
   CODEC_DYNAMIC = (0xffff),

   /* Place-holder for unknown codec types that should be ignored/removed from list */
   CODEC_UNKNOWN = (0xfffe)

} CODEC_TYPE;


/* Voice codec class for checking. */
typedef enum
{
   CODEC_G723x_53,
   CODEC_G723x_63,
   CODEC_G723x_VAR,
   CODEC_G723x,
   CODEC_G726x,
   CODEC_G729x,
   CODEC_ILBCx,
   CODEC_T38x,
   CODEC_PCMx,
   CODEC_VBDx,
   CODEC_NON_VOICE

} CODEC_CLASS;


enum
{
   CODEC_UNSUPPORTED = 0,
   CODEC_SUPPORTED   = 1
};


/* Bit-flags for named telephone event types (RFC 2833) */
enum
{
   /* NTE Events */
   CODEC_NTE_RING    =  (1 << 0),      /* Ringing event */
   CODEC_NTE_ONHOOK  =  (1 << 1),      /* Onhook event */
   CODEC_NTE_OSI     =  (1 << 2),      /* Open switch interval event */
   CODEC_NTE_DTMF0   =  (1 << 3),      /* DTMF Tone 0 */
   CODEC_NTE_DTMF1   =  (1 << 4),      /* DTMF Tone 1 */
   CODEC_NTE_DTMF2   =  (1 << 5),      /* DTMF Tone 2 */
   CODEC_NTE_DTMF3   =  (1 << 6),      /* DTMF Tone 3 */
   CODEC_NTE_DTMF4   =  (1 << 7),      /* DTMF Tone 4 */
   CODEC_NTE_DTMF5   =  (1 << 8),      /* DTMF Tone 5 */
   CODEC_NTE_DTMF6   =  (1 << 9),      /* DTMF Tone 6 */
   CODEC_NTE_DTMF7   =  (1 << 10),     /* DTMF Tone 7 */
   CODEC_NTE_DTMF8   =  (1 << 11),     /* DTMF Tone 8 */
   CODEC_NTE_DTMF9   =  (1 << 12),     /* DTMF Tone 9 */
   CODEC_NTE_DTMFS   =  (1 << 13),     /* DTMF Tone * */
   CODEC_NTE_DTMFH   =  (1 << 14),     /* DTMF Tone # */
   CODEC_NTE_DTMFA   =  (1 << 15),     /* DTMF Tone A */
   CODEC_NTE_DTMFB   =  (1 << 16),     /* DTMF Tone B */
   CODEC_NTE_DTMFC   =  (1 << 17),     /* DTMF Tone C */
   CODEC_NTE_DTMFD   =  (1 << 18)      /* DTMF Tone D */

};


enum
{
   /* Mask for inlcuding all DTMF events */
   CODEC_NTE_DTMF = CODEC_NTE_DTMF0    | \
                    CODEC_NTE_DTMF1    | \
                    CODEC_NTE_DTMF2    | \
                    CODEC_NTE_DTMF3    | \
                    CODEC_NTE_DTMF4    | \
                    CODEC_NTE_DTMF5    | \
                    CODEC_NTE_DTMF6    | \
                    CODEC_NTE_DTMF7    | \
                    CODEC_NTE_DTMF8    | \
                    CODEC_NTE_DTMF9    | \
                    CODEC_NTE_DTMFS    | \
                    CODEC_NTE_DTMFH    | \
                    CODEC_NTE_DTMFA    | \
                    CODEC_NTE_DTMFB    | \
                    CODEC_NTE_DTMFC    | \
                    CODEC_NTE_DTMFD,


   /* Mask for inlcuding all LCS events */
   CODEC_NTE_LCS  = CODEC_NTE_RING   | \
                    CODEC_NTE_ONHOOK | \
                    CODEC_NTE_OSI
};


/* Packetization periods */
typedef enum
{
   CODEC_PTIME_5     = 5,        /* 5 ms  */
   CODEC_PTIME_10    = 10,       /* 10 ms */
   CODEC_PTIME_20    = 20,       /* 20 ms */
   CODEC_PTIME_30    = 30,       /* 30 ms */
   CODEC_PTIME_40    = 40,       /* 40 ms */
   CODEC_PTIME_ANY   = 0xFFFF    /* ptime = '-' */
} CODEC_PKT_PERIOD;


enum
{
   /* Mask for codecs that support all packetization periods */
   CODEC_SUPPORT_ALL_PTIME =  CODEC_PCMU  | \
                              CODEC_PCMA  | \
                              CODEC_G726x | \
                              CODEC_G728  | \
                              CODEC_BV16  | \
                              CODEC_BV32  | \
                              CODEC_NTE   | \
                              CODEC_RED
};


/* RTP payload types */
typedef enum
{
   RTP_PAYLOAD_PCMU        = 0,               /* G.711 mu-law 64 kbps   */
   RTP_PAYLOAD_G726_32     = 2,               /* G.726-32               */
   RTP_PAYLOAD_G723        = 4,               /* G.723                  */
   RTP_PAYLOAD_PCMA        = 8,               /* G.711 A-law 64 kbps    */
   RTP_PAYLOAD_CNA         = 13,              /* Comfort noise          */
   RTP_PAYLOAD_G728        = 15,              /* G.728                  */
   RTP_PAYLOAD_G729        = 18,              /* G.729                  */
   RTP_PAYLOAD_CN          = 19,              /* Comfort noise          */
   RTP_PAYLOAD_INVALID     = 0xff
} RTP_PAYLOAD_TYPE;

/* RTP named telephone events, as defined in RFC 2833 */
typedef enum
{
   /* DTMF named events */
   RTP_NTE_DTMF0     = 0,           /* DTMF Tone 0 event */
   RTP_NTE_DTMF1     = 1,           /* DTMF Tone 1 event */
   RTP_NTE_DTMF2     = 2,           /* DTMF Tone 2 event */
   RTP_NTE_DTMF3     = 3,           /* DTMF Tone 3 event */
   RTP_NTE_DTMF4     = 4,           /* DTMF Tone 4 event */
   RTP_NTE_DTMF5     = 5,           /* DTMF Tone 5 event */
   RTP_NTE_DTMF6     = 6,           /* DTMF Tone 6 event */
   RTP_NTE_DTMF7     = 7,           /* DTMF Tone 7 event */
   RTP_NTE_DTMF8     = 8,           /* DTMF Tone 8 event */
   RTP_NTE_DTMF9     = 9,           /* DTMF Tone 9 event */
   RTP_NTE_DTMFS     = 10,          /* DTMF Tone * event */
   RTP_NTE_DTMFH     = 11,          /* DTMF Tone # event */
   RTP_NTE_DTMFA     = 12,          /* DTMF Tone A event */
   RTP_NTE_DTMFB     = 13,          /* DTMF Tone B event */
   RTP_NTE_DTMFC     = 14,          /* DTMF Tone C event */
   RTP_NTE_DTMFD     = 15,          /* DTMF Tone D event */

   /* LCS named events */
   RTP_NTE_RING      = 144,         /* Ringing event */
   RTP_NTE_ONHOOK    = 149,         /* Onhook event */
   RTP_NTE_OSI       = 159,         /* Open switch interval event */

   /* GR303 named events */
   RTP_NTE_RINGOFF   = 149,         /* Ringing off event */
   RTP_NTE_OFFHOOK   = 159          /* Offhook event */

} RTP_NTE;

/* Codec options descriptor */
typedef struct CODECOPT
{
   CODEC_TYPE  rfc2198Type;                  /* If codec type is CODEC_RED, then this is the
                                                redundant codec type. */
   BOS_UINT8   opt1;                         /* Optional data 1 for this codec
                                                   If codec type is CODEC_RED, this is the
                                                      redundancy level.
                                                   If codec type supports VBD (V.152), this is
                                                      the flag for its support. */
   BOS_UINT8   opt2;                         /* Optional data 2 for this codec
                                                   If codec type is CODEC_RED, this is the
                                                      payload type for the redundant codec. */
} CODECOPT;

/* Codec descriptor */
typedef struct CODECDESC
{
   CODEC_TYPE  type;                         /* codec type */
   BOS_UINT8   rtpPayloadType;               /* RTP payload type that corresponds to 'type' */
   CODECOPT    options;                      /* Supplementary codec options. */
} CODECDESC;

/* Codec list */
typedef struct CODECCNXLIST
{
   CODECDESC         codecs[CODEC_MAX_TYPES];   /* list of codecs */
   int               numCodecs;                 /* number of codecs/packetization period in list */
   CODEC_PKT_PERIOD  period[CODEC_MAX_TYPES];   /* list of packetization period associated with each codec */
   int               numPeriods;                /* # of ptime requested */
} CODECCNXLIST;

/* Codec list for a single connection
 *    - consists of 2 sub-lists:
 *       1. local codec list with locally-assigned RTP payload types
 *       2. remote codec list with remotely-assigned RTP payload types
 */
typedef struct CODECCNXPARMLIST
{
   CODECCNXLIST   send;             /* list of local codecs */
   CODECCNXLIST   recv;             /* list of remote codecs */
} CODECCNXPARMLIST;




/* ---- Variable Externs ------------------------------------------------- */
/* ---- Function Prototypes ---------------------------------------------- */

/*
*****************************************************************************
** FUNCTION:   codecGetBaseFrameRate
**
** PURPOSE:    To retrieve the base frame rate associated a codec type.
**
** PARAMETERS: codec (in)  codec type.
**
** RETURNS:    Native frame rate associated with codec. O if error.
**
** NOTE:
*****************************************************************************
*/
unsigned int codecGetBaseFrameRate( CODEC_TYPE codec );


/*
*****************************************************************************
** FUNCTION:   codecGetBasePayloadSize
**
** PURPOSE:    To retrieve the payload size associated a codec type, running
**             at the base frame rate.
**
** PARAMETERS: codec (in)  codec type.
**
** RETURNS:    Base payload packet size. 0 if error.
**
** NOTE:
*****************************************************************************
*/
unsigned int codecGetBasePayloadSize( CODEC_TYPE codec );


/*
*****************************************************************************
** FUNCTION:   codecGetPayloadSize
**
** PURPOSE:    To retrieve the payload size associated a codec type and a
**             packetization time
**
** PARAMETERS: codec (in)  codec type
**             ptime (in)  packetization time
**
** RETURNS:    Payload packet size. 0 if error.
**
** NOTE:
*****************************************************************************
*/
unsigned int codecGetPayloadSize( CODEC_TYPE codec, unsigned int ptime );


/*
*****************************************************************************
** FUNCTION:   codecCheckClass
**
** PURPOSE:    To check whether a codec belongs to a specific pre-defined
**             class
**
** PARAMETERS: codec (in)  codec type
**             class (in)  class type
**
** RETURNS:    1 if codec belongs to the class. 0 otherwise.
**
** NOTE:
*****************************************************************************
*/
unsigned int codecCheckClass( CODEC_TYPE codec, CODEC_CLASS cclass );


/* ---- Constants and Types ---------------------------------------------- */

/* MIB value for Tone Detection */
#define MIB_TONE_DET_ALL_ENABLED            1
#define MIB_TONE_DET_ALL_DISABLED           2
#define MIB_TONE_DET_V18ALARMPOS_DISABLED   3
#define MIB_TONE_DET_ALARMPOS_DISABLED      4
#define MIB_TONE_DET_V18_DISABLED           5

/* Only used by E-Package */
#define MAX_CADENCE_RING      128

#define VRG_ENDPT_NO_RING_INTERLEAVE   0xABBA

/*
 * The power (a priori) of a 1mW, 1.5kHz sine wave (assuming zero gain)
 * is represented by (<amplitude>^2)/2 where <amplitude> = 22656 (the digital
 * equivalent of peak amplitude).
 * Use this value in a decibel calculation
 * e.g. <measured dbm> = 10*log10(<measured power>/DIALTONE_ENERGYZERO)
 */
#define DIALTONE_ENERGYZERO 256647168L

/*
** Events detected
*/
typedef enum
{
   EPEVT_NULL,                    /* internal use: Null event */
   EPEVT_DTMF0,                   /* DTMF Tone 0 */
   EPEVT_DTMF1,                   /* DTMF Tone 1 */
   EPEVT_DTMF2,                   /* DTMF Tone 2 */
   EPEVT_DTMF3,                   /* DTMF Tone 3 */
   EPEVT_DTMF4,                   /* DTMF Tone 4 */
   EPEVT_DTMF5,                   /* DTMF Tone 5 */
   EPEVT_DTMF6,                   /* DTMF Tone 6 */
   EPEVT_DTMF7,                   /* DTMF Tone 7 */
   EPEVT_DTMF8,                   /* DTMF Tone 8 */
   EPEVT_DTMF9,                   /* DTMF Tone 9 */
   EPEVT_DTMFS,                   /* DTMF Tone * */
   EPEVT_DTMFH,                   /* DTMF Tone # */
   EPEVT_DTMFA,                   /* DTMF Tone A */
   EPEVT_DTMFB,                   /* DTMF Tone B */
   EPEVT_DTMFC,                   /* DTMF Tone C */
   EPEVT_DTMFD,                   /* DTMF Tone D */
   EPEVT_OFFHOOK,                 /* Off-hook event */
   EPEVT_ONHOOK,                  /* On-hook event */
   EPEVT_EARLY_OFFHOOK,           /* Early off-hook event */
   EPEVT_EARLY_ONHOOK,            /* Early on-hook event */
   EPEVT_FLASH,                   /* Hook-flash event */
   EPEVT_FAX,                     /* Fax tone detected */
   EPEVT_MODEM,                   /* Modem detect event */
   EPEVT_LOWENERGY,               /* Low energy detect event */
   EPEVT_DTMFL,                   /* DTMF long duration */
   EPEVT_MEDIA,                   /* Media start */
   EPEVT_TDD,                     /* Telecom Devices for the Deaf */
   EPEVT_T38_STOP,                /* T.38 completion */
   EPEVT_T38_FAILURE,             /* T.38 failure */
   EPEVT_RINGING_ON,              /* Phones are currently ringing */
   EPEVT_RINGING_OFF,             /* Phones are currently not ringing  */
   EPEVT_VBD_STOP,                /* VBD stop event */
   EPEVT_VBD_START,               /* VBD start event */
   EPEVT_FSK_CLIDRX,              /* FSK CLIDRX */
   EPEVT_DTMF_CLIDRX,             /* DTMF CLIDRX */
   EPEVT_OPCOMPLETE,              /* Operation complete */
   EPEVT_CPTONETIMEOUT,           /* Call progress tone detect timeout */
   EPEVT_RINGDET,                 /* Ring signal on detected */
   EPEVT_RINGOFF,                 /* Ring signal off detected */
   EPEVT_RINGEND,                 /* Ring signal end detected */
   EPEVT_ENCODER_SWITCH,          /* Encoder switch event */
   EPEVT_DECODER_SWITCH,          /* Decoder switch event */
   EPEVT_DIALTONE,                /* Dial Tone Detection event */
   EPEVT_DIALTONE_END,            /* Dial Tone End event */
   EPEVT_DTMF_LEVEL,              /* Dial Tone Level event */
   EPEVT_MLT_MEASUREMENT,         /* Event associated with requested measurement */
   EPEVT_INGRESS_DTMF,            /* Ingress DTMF generated */
   EPEVT_CUSTOMTONE,              /* Custom tone detect event */
   EPEVT_LAST

}EPEVT;

/*
** Signals generated
*/
typedef enum
{
   EPSIG_NULL,                    /* internal use: Null signal */
   EPSIG_BUSY,                    /* busy tone */
   EPSIG_CONF,                    /* confirmation tone */
   EPSIG_DIAL,                    /* dial tone */
   EPSIG_MSGW,                    /* message waiting indicator tone */
   EPSIG_OHWARN,                  /* off-hook warning tone */
   EPSIG_RINGING,                 /* enable ringer */
   EPSIG_RING0,                   /* distinctive ringing 0 */
   EPSIG_RING1,                   /* distinctive ringing 1 */
   EPSIG_RING2,                   /* distinctive ringing 2 */
   EPSIG_RING3,                   /* distinctive ringing 3 */
   EPSIG_RING4,                   /* distinctive ringing 4 */
   EPSIG_RING5,                   /* distinctive ringing 5 */
   EPSIG_RING6,                   /* distinctive ringing 6 */
   EPSIG_RING7,                   /* distinctive ringing 7 */
   EPSIG_CALLID_RINGING,          /* enable ringer, pending callid */
   EPSIG_CALLID_RING0,            /* distinctive ringing 0, pending callid */
   EPSIG_CALLID_RING1,            /* distinctive ringing 1, pending callid */
   EPSIG_CALLID_RING2,            /* distinctive ringing 2, pending callid */
   EPSIG_CALLID_RING3,            /* distinctive ringing 3, pending callid */
   EPSIG_CALLID_RING4,            /* distinctive ringing 4, pending callid */
   EPSIG_CALLID_RING5,            /* distinctive ringing 5, pending callid */
   EPSIG_CALLID_RING6,            /* distinctive ringing 6, pending callid */
   EPSIG_CALLID_RING7,            /* distinctive ringing 7, pending callid */
   EPSIG_REORDER,                 /* reorder tone */
   EPSIG_SPLASH,                  /* ring splash tone */
   EPSIG_RINGBACK,                /* ringback tone */
   EPSIG_STUTTER,                 /* stutter dial tone */
   EPSIG_INTRUSION,               /* intrusion tone (Norway) */
   EPSIG_WARNING,                 /* warning tone (Norway) */
   EPSIG_DIAL2,                   /* dial tone 2 (Norway's centrex dial tone) */
   EPSIG_CALLWT,                   /* call waiting tone */
   EPSIG_CALLW1,                  /* call waiting tone 1 */
   EPSIG_CALLW2,                  /* call waiting tone 2 */
   EPSIG_CALLW3,                  /* call waiting tone 3 */
   EPSIG_CALLW4,                  /* call waiting tone 4  */
   EPSIG_SAS_CAS,                 /* combined SAS and CAS tone for CLASS2 */
   EPSIG_SAS_CAS1,                /* combined SAS and CAS tone for CLASS2 */
   EPSIG_SAS_CAS2,                /* combined SAS and CAS tone for CLASS2 */
   EPSIG_SAS_CAS3,                /* combined SAS and CAS tone for CLASS2 */
   EPSIG_SAS_CAS4,                /* combined SAS and CAS tone for CLASS2 */
   EPSIG_VMWI,                    /* visual message waiting indicator */
   EPSIG_REV,                     /* phase reversal */
   EPSIG_DTMF0,                   /* DTMF Tone 0 */
   EPSIG_DTMF1,                   /* DTMF Tone 1 */
   EPSIG_DTMF2,                   /* DTMF Tone 2 */
   EPSIG_DTMF3,                   /* DTMF Tone 3 */
   EPSIG_DTMF4,                   /* DTMF Tone 4 */
   EPSIG_DTMF5,                   /* DTMF Tone 5 */
   EPSIG_DTMF6,                   /* DTMF Tone 6 */
   EPSIG_DTMF7,                   /* DTMF Tone 7 */
   EPSIG_DTMF8,                   /* DTMF Tone 8 */
   EPSIG_DTMF9,                   /* DTMF Tone 9 */
   EPSIG_DTMFS,                   /* DTMF Tone * */
   EPSIG_DTMFH,                   /* DTMF Tone # */
   EPSIG_DTMFA,                   /* DTMF Tone A */
   EPSIG_DTMFB,                   /* DTMF Tone B */
   EPSIG_DTMFC,                   /* DTMF Tone C */
   EPSIG_DTMFD,                   /* DTMF Tone D */
   EPSIG_CALLID,                  /* Caller ID message */
   EPSIG_CALLCARD,                /* Calling Card Service tone */
   EPSIG_NETBUSY,                 /* Network busy tone */
   EPSIG_NETBUSY1,                /* Network busy tone 1 */
   EPSIG_DISCONNECT,              /* Line Disconnect tone */
   EPSIG_PAYPHONE_REC,            /* Special Information tone */
   EPSIG_OSI,                     /* Open switch interval */
   EPSIG_PSTNCALLSETUP,           /* PSTN call setup */
   EPSIG_PSTNCALLSETUP_CONNECTONLY,/* PSTN call setup, where no dialtone detection and dialstring generation happens */
   EPSIG_OFFHOOK,                 /* Offhook - seize */
   EPSIG_ONHOOK,                  /* Onhook - release */
   EPSIG_ANSWER,                  /* Offhook - answer */
   EPSIG_ANALOG_LOOPBACK,         /* Enable analog loopback */
   EPSIG_LINE_RESET,              /* Line reset */
   EPSIG_DIAGTESTS_PROV_START,    /* Start diag tests with provisioning */
   EPSIG_DIAGTESTS_NOPROV_START,  /* Start diag tests without using provisioning */
   EPSIG_DIAGTESTS_PC15_START,    /* Start diag tests with PC15 provisioning */
   EPSIG_DIAGTESTS_CALIBRATE_START, /* Start calibartion process */
   EPSIG_UPDATE_DTMFPLAYOUT,      /* Update DTMF Playout duration */
   EPSIG_TXGAIN,                  /* Change Tx Gain setting */
   EPSIG_RXGAIN,                  /* Change Rx Gain setting */
   EPSIG_RING_WITH_DC_OFFSET,     /* Change Ring with DC Offset setting */
   EPSIG_BOOSTED_LOOP_CURRENT,    /* change Boosted Loop Current setting */
   EPSIG_ADMIN_STATUS,            /* line admin status change (enabled/disabled) */
   EPSIG_RING_WAVEFORM,           /* Change Ring Waveform settings */
   EPSIG_RINGBACK_CUST1,          /* Custom ringback tone 1 */
   EPSIG_SPECIAL_DIAL,            /* Special dial tone */
   EPSIG_SB_DISCONNECT,           /* Disconnect switchboard */
   EPSIG_INGRESS_DTMF,            /* Generate ingress DTMF tone */
   EPSIG_LINE_MODE_CONTROL,       /* Set to 1 so that subsequent mode controls apply to line VHD, 0 otherwise */
   EPSIG_FILL_INFO,               /* Filler Information tone for UAE */
/*
** E-line package-specific defines
*/

   /*
   ** Pulsed Signals encoding request
   */
   EPSIG_INIT_RING,
   EPSIG_LOOP_CLOSE,
   EPSIG_LOOP_OPEN,
   EPSIG_ENABLE_METERING,
   EPSIG_METERING_BURST,
   EPSIG_NO_BATTERY,
   EPSIG_NORMAL_POLARITY,
   EPSIG_REDUCED_BATTERY,
   EPSIG_REVERSE_POLARITY,

   /*
   ** Steady signals
   */
   EPSIG_STEADY_FULL_BATTERY,
   EPSIG_STEADY_LOOP_CLOSE,
   EPSIG_STEADY_LOOP_OPEN,
   EPSIG_STEADY_NO_BATTERY,
   EPSIG_STEADY_NORMAL_POLARITY,
   EPSIG_STEADY_REDUCED_BATTERY,
   EPSIG_STEADY_REVERSED_POLARITY,


   /*
   ** Cadence Ringing base enum (i.e. cr(0))
   */
   EPSIG_CADENCE_RING_BASE,

   /*** DO NOT insert anything here!! ***/

   /* Cadence Ringing max enum (i.e. cr(127)) */
   EPSIG_CADENCE_RING_MAX = ( EPSIG_CADENCE_RING_BASE + MAX_CADENCE_RING - 1),

/*
** end of E-line package-specific defines
*/

   /* DAA related signalling */
   EPSIG_DAA_DISABLE,
   EPSIG_DAA_ENABLE,

   EPSIG_LAST

}EPSIG;

/* Signal Direction */
typedef enum
{
   EPSIG_DIRECTION_EGRESS_OFF,
   EPSIG_DIRECTION_EGRESS_ON,
   EPSIG_DIRECTION_INGRESS_OFF,
   EPSIG_DIRECTION_INGRESS_ON,
   EPSIG_DIRECTION_BOTH_OFF,
   EPSIG_DIRECTION_BOTH_ON
} EPSIG_DIRECTION;

/*
** Provisioned values
*/
typedef enum
{
   EPPROV_R0Cadence           = 0,        /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_R1Cadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_R2Cadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_R3Cadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_R4Cadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_R5Cadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_R6Cadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_R7Cadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_RGCadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_RSCadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_RTCadence,                      /* Effective on next vrgEndptSignal (ring signal) */
   EPPROV_CallWtgDelay,                   /* Effective on next vrgEndptSignal (SAS_CAS or call waiting signal) */


   /* Tones - 22 total (6 unused, 15 used, 1 CAS tone) */
   EPPROV_ToneBusy            = 200,      /* EPSIG_BUSY                 Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneConfirmation,               /* EPSIG_CONF                 Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneDial,                       /* EPSIG_DIAL                 Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneMessageWaiting,             /* EPSIG_MSGW                 Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneOffHookWarning,             /* EPSIG_OHWARN               Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneRingBack,                   /* EPSIG_RINGBACK             Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneReOrder,                    /* EPSIG_REORDER              Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneStutterdial,                /* EPSIG_STUTTER              Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneCallWaiting,                /* EPSIG_CALLWT               Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneCallWaiting1,               /* EPSIG_CALLW1               Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneCallWaiting2,               /* EPSIG_CALLW2               Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneCallWaiting3,               /* EPSIG_CALLW3               Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneCallWaiting4,               /* EPSIG_CALLW4               Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneAlertingSignal,             /* CAS TONE                   Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneSpecialDial,                /* ???-03                     Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneSpecialInfo,                /* ???-04                     Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneRelease,                    /* ???-05                     Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneCongestion,                 /* EPSIG_NETBUSY              Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneCongestion1,                /* EPSIG_NETBUSY1             Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneUserDefined1,               /* EPSIG_RINGBACK_CUST1       Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneUserDefined2,               /* Intrusion tone (Norway)    Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneUserDefined3,               /* Warning tone (Norway)      Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneUserDefined4,               /* Centrex dial tone (Norway) Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneUserDefined5,               /* Disconnect tone            Effective on next vrgEndptSignal (tone signal)  */
   EPPROV_ToneUserDefined6,               /* EPSIG_PAYPHONE_REC         Effective on next vrgEndptSignal (tone signal)  */


   EPPROV_MinHookFlash        = 400,      /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_MaxHookFlash,                   /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_PlsDlInterdigitTime,            /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_PlsDlMinMakeTime,               /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_PlsDlMaxMakeTime,               /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_PlsDlMinBreakTime,              /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_PlsDlMaxBreakTime,              /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_CIDMode,                        /* Effective on next vrgEndptSignal (for ringing with caller id) */
   EPPROV_CIDFskAfterRing,                /* Effective on next vrgEndptSignal (for ringing with caller id) */
   EPPROV_CIDFskAfterDTAS,                /* Effective on next vrgEndptSignal (for ringing with caller id) */
   EPPROV_CIDFskAfterRPAS,                 /* Effective on next vrgEndptSignal (for ringing with caller id) */
   EPPROV_CIDRingAfterFSK,                /* Effective on next vrgEndptSignal (for ringing with caller id) */
   EPPROV_CIDDTASAfterLR,                 /* Effective on next vrgEndptSignal (for ringing with caller id) */
   EPPROV_CIDSigProtocol,                 /* Effective on next vrgEndptSignal (for ringing with caller id) */
   EPPROV_VMWIMode,                       /* Effective on next vrgEndptSignal (for EPSIG_VMWI) */
   EPPROV_VMWISigProtocol,                /* Currently not sourced from provisioning (only from vrgEndptGlobe static tables) */
   EPPROV_VMWIFskAfterDTAS,               /* Effective on next vrgEndptSignal (for EPSIG_VMWI) */
   EPPROV_VMWIFskAfterRPAS,               /* Effective on next vrgEndptSignal (for EPSIG_VMWI) */
   EPPROV_VMWIDTASAfterLR,                /* Effective on next vrgEndptSignal (for EPSIG_VMWI) */
   EPPROV_PulseSignalEntry,               /* Not used */
   EPPROV_RingCadenceEntry,               /* Not used */
   EPPROV_StandardRingCadence,            /* Not used */
   EPPROV_RingSplashCadence,              /* Not used */
   EPPROV_MinConnect,                     /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_MinDisconnect,                  /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_CIDFskParms,                    /* Fsk CID specific parameters*/
   EPPROV_CIDDtmfParms,                   /* Dtmf CID specific paramters*/
   EPPROV_VMWIMsgFormat,                  /* Visual Message waiting indicator formats TR-NWT-001401 */
   EPPROV_PteDetectAdmin,                 /* Dtmf CID specific paramters*/
   EPPROV_PteMinDetectPower,              /* minimum detection power level */
   EPPROV_PveEgressVolume,                /* Egress Volume */

/*
** EMTA management package-specific defines
*/

   EPPROV_AnalogLoopback      = 600,      /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_DiagTestsStart,                 /* Effective on next run of MLT tests */
   EPPROV_DiagTestsStop,                  /* Effective on next run of MLT tests */
   EPPROV_DiagTestsValid,                 /* Effective on next run of MLT tests */
   EPPROV_DiagTestsResult,                /* Effective on next run of MLT tests */
   EPPROV_DiagTestsValue,                 /* Effective on next run of MLT tests */
   EPPROV_DiagTestsFault,                 /* Effective on next run of MLT tests */
   EPPROV_RingWithDCOffset,               /* Not used */
   EPPROV_BoostedLoopCurrent,             /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_VoiceJitterBuffFixed,           /* Effective on next vrgEndptCreateConnection */
   EPPROV_VoiceJitterBuffMin,             /* Effective on next vrgEndptCreateConnection */
   EPPROV_VoiceJitterBuffMax,             /* Effective on next vrgEndptCreateConnection */
   EPPROV_VoiceJitterBuffTarget,          /* Effective on next vrgEndptCreateConnection */
   EPPROV_DataJitterBuffTarget,           /* Effective on next vrgEndptCreateConnection */
   EPPROV_DataJitterBuffMax,              /* Not used */
   EPPROV_DtmfToneRelay,                  /* Not used */
   EPPROV_DTMFSkew,                       /* Effective on next DTMF Generation request for the specific line*/
   EPPROV_TxGain,                         /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_RxGain,                         /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_ToneDetectionCtrl,              /* Effective on next vrgEndptCreateConnection */
   EPPROV_GR303Support,                   /* Effective on next vrgEndptCreate for the specific line*/
   EPPROV_ClidDateMissingAction,          /* Not used */

/*
** E-line package-specific defines
*/

   /*
   ** Pulsed signals
   */
   EPPROV_InitRing            = 800,      /* Not used */
   EPPROV_LoopClose,                      /* Not used */
   EPPROV_LoopOpen,                       /* Not used */
   EPPROV_EnableMetering,                 /* Not used */
   EPPROV_MeteringBurst,                  /* Not used */
   EPPROV_MeteringFrequency,              /* Effective on next vrgEndptSignal (EPSIG_METERING_BURST) */
   EPPROV_NoBattery,                      /* Not used */
   EPPROV_NormalPolarity,                 /* Not used */
   EPPROV_ReducedBattery,                 /* Not used */
   EPPROV_ReversePolarity,                /* Not used */


   /* Cadence Ringing base enum (i.e. cr(0)) */
   EPPROV_CadenceRingBase     = 1000,     /* Effective on next vrgEndptSignal (ring signal) */

   /*** DO NOT insert anything here!! ***/

   /* Cadence Ringing max enum (i.e. cr(127)) */
   EPPROV_CadenceRingMax = ( EPPROV_CadenceRingBase + MAX_CADENCE_RING - 1 ),    /* Not used */

/*
** End of E-line package-specific defines
*/

   EPPROV_Pulse2DtmfConvert   = 2000,     /* Effective on next vrgEndptCreate for the specific line*/

/*
** Enhanced NCS signalling specific defines
*/

   EPPROV_FaxDetection        = 2200,     /* Effective on next vrgEndptCreateConnection */
   EPPROV_DTMFPlayout,                    /* Effective on next vrgEndptCreate for the specific line 
                                          ** or on next vrgEndptSignal for EPSIG_UPDATE_DTMFPLAYOUT */
   EPPROV_DtmfDbLevel,                    /* Effective on next vrgEndptSignal (ingress DTMF) or pulse to DTMF conversion */
   EPPROV_DtmfPulseTime,                  /* Effective on next vrgEndptSignal (ingress DTMF) or pulse to DTMF conversion */

   EPPROV_Rfc2833ToneLevel,               /* Tone Power Level over-ride */

   EPPROV_PcDiagTestsStart    = 2400,     /* Not used */
   EPPROV_PcDiagTestsClear,               /* Not used */
   EPPROV_PcDiagTestsValid,               /* Not used */
   EPPROV_PcDiagTestsResult,              /* Not used */

   EPPROV_HighVring           = 2600,     /* Effective on next vrgEndptCreate for the specific line 
                                          ** or on next vrgEndptSignal (EPSIG_RING_WAVEFORM) */
   EPPROV_PowerRingFrequency,             /* Effective on next vrgEndptCreate for the specific line 
                                          ** or on next vrgEndptSignal (EPSIG_RING_WAVEFORM) */
   EPPROV_RingWaveform,                   /* Effective on next vrgEndptCreate for the specific line 
                                          ** or on next vrgEndptSignal (EPSIG_RING_WAVEFORM) */
   EPPROV_RingVoltage,                    /* Effective on next vrgEndptCreate for the specific line 
                                          ** or on next vrgEndptSignal (EPSIG_RING_WAVEFORM) */
   EPPROV_RingDCOffset,                   /* Effective on next vrgEndptCreate for the specific line 
                                          ** or on next vrgEndptSignal (EPSIG_RING_WAVEFORM) */
   EPPROV_RingOffsetCal,                  /* Effective on next vrgEndptCreate for the specific line 
                                          ** or on next vrgEndptSignal (EPSIG_RING_WAVEFORM) */
   EPPROV_LoadBalancing,                  /* Not used */

   /*Items for notifying when line tests is in progress or done*/
   EPPROV_LineTestInProgress = 2800,
   EPPROV_LineTestDone,

   EPPROV_Flexicalc,                      /* Effective on next vrgEndptInit */
   EPPROV_PreferredVBDCodec,              /* Effective on next vrgEndptCreateConnection or vrgEndptModifyConnection */

   /*Item to store the locale seen at the last voice start*/
   EPPROV_LastLocale,

   /* egress dtmf detection */
   EPPROV_EgressDtmfDetection,

   EPPROV_LastItem, /* Must be the last item */

} EPPROV;

/*
** Returned status
*/
typedef enum
{
   EPSTATUS_SUCCESS = 0,         /* success */
   EPSTATUS_ERROR,               /* generic endpoint driver error */
   EPSTATUS_ENDPT_UNKNOWN,       /* endpoint is unknown */
   EPSTATUS_NOTREADY,            /* endpoint is not ready */
   EPSTATUS_RESOURCES,           /* endpoint has insufficient resources */
   EPSTATUS_SIGNAL_UNKNOWN,      /* endpoint cant generate that signal */
   EPSTATUS_CNX_UNKNOWN,         /* incorrect connection ID */
   EPSTATUS_UNSUPPORTED_MODE,    /* unsupported connection mode */
   EPSTATUS_UNKNOWN_TYPE,        /* unknown endpoint type */
   EPSTATUS_BUSY,                /* endpoint is busy */
   EPSTATUS_ONHOOK,              /* endpoint is onhook, can't perform operation */
   EPSTATUS_BAD_MODE,            /* endpoint is in wrong mode, can't perform operation */
   EPSTATUS_SHUTDOWN_ERR,        /* unable to shutdown the endpoint */
   EPSTATUS_PROV_FAILURE,        /* endpoint provisioning failure */
   EPSTATUS_RESET_PENDING,       /* reset is pending */

} EPSTATUS;

/*
** Connection modes
*/
typedef enum
{
   EPCNXMODE_SNDO,                /* Send only */
   EPCNXMODE_RCVO,                /* Receive only */
   EPCNXMODE_SNDRX,               /* Send-Receive mode */
   EPCNXMODE_CONF,                /* Send-Receive Conference mode */
   EPCNXMODE_INACT,               /* Inactive */
   EPCNXMODE_LOOP,                /* Network Loopback test */
   EPCNXMODE_TEST,                /* Network Continuity test */
   EPCNXMODE_REPLCATE,            /* Replicate */
   EPCNXMODE_TRANSCODE,           /* Transcoding */
   EPCNXMODE_MAX
} EPCNXMODE;



/*
** Cas states
*/
typedef enum
{
   EPCAS_ONHOOK,                  /* on-hook */
   EPCAS_OFFHOOK,                 /* off-hook */
   EPCAS_FLASH,                   /* flash */
   EPCAS_RINGON,                  /* ring on */
   EPCAS_RINGOFF,                 /* ring off */
   EPCAS_RINGEND,                 /* ring end */
   EPCAS_FIRST_RINGOFF,           /* first ring off for on-hook caller id */
   EPCAS_VMWI_OSI_SENT,           /* Vmwi supervisory disconnect complete */
   EPCAS_EARLY_OFFHOOK,           /* Early off hook event */
   EPCAS_EARLY_ONHOOK,            /* Early on hook event */
   EPCAS_DELAY_OFFHOOK,           /* Delayed off hook event */
   EPCAS_DELAY_ONHOOK             /* Delayed on hook event */

} EPCASSTATE;


/** SLIC/SLAC Modes. */
typedef enum
{
   EPSLIC_MODE_LCF,               /**< Loop Current Forward. */
   EPSLIC_MODE_STANDBY,           /**< Stand-by. */
   EPSLIC_MODE_LCFO               /**< Loop Current Forward Off (Disconnect). */
} EPSLICMODE;


/*
** Endpoint console commands
*/
typedef enum
{
   EPCMD_DSP_MIPS=0xff,          /* Display DSP MIPS usage */
   EPCMD_PRINT_VHDS,             /* Display VHD list. */
   EPCMD_ENDPTVHD_STATS,         /* Display DSP EndptVHD stats */
   EPCMD_PVE_STATE_FROM_CNX,     /* Display DSP VHD PVE state based on cnx ID */
   EPCMD_VHD_STATS,              /* Display DSP VHD stats */
   EPCMD_VHD_STATS_FROM_CNX,     /* Display DSP VHD stats based on cnx ID */
   EPCMD_RTP_STATS,              /* Display DSP RTP stats */
   EPCMD_VHD_JBREGS,             /* Display current jitter buffer registers */
   EPCMD_FAXR_STATS,             /* Display DSP FAXR stats */
   EPCMD_FAXR_STATS_FROM_ENDPT,  /* Display DSP FAXR stats based on endpt number */
   EPCMD_IPC_STATS,              /* Display DSP IPC stats */
   EPCMD_IPC_STATS_FROM_ENDPT,   /* Display DSP IPC stats based on endpt number */
   EPCMD_DSP_BUFFERS,            /* Display DSP buffer pool stats */
   EPCMD_DSP_GETCNT,             /* Display DSP debug counters */
   EPCMD_DSP_FORCEASSERT,        /* Force DSP assert */
   EPCMD_DSP_CHECKASSERT,        /* Check DSP assert stack pointer */
   EPCMD_DSP_GETREGS,            /* Get a snapshot of DSP regs */
   EPCMD_DSP_READDMEM,           /* Read internal DSP data memory */
   EPCMD_APM_STATUS,             /* Display APM status info */
   EPCMD_PWRMGMT_VPM,            /* Set the VPM power mode */
   EPCMD_PWRMGMT_AFE,            /* Power up/down the Analog Front End */
   EPCMD_TR57_ENABLE,            /* Enable/Disable TR57 test mode */
   EPCMD_VHD_LOOPBACK_ENABLE,    /* Enable VHD loopback */
   EPCMD_READ_HOOK_STATE,        /* Read hook state on the channel */
   EPCMD_SET_SLIC_STATE,         /* Set slic state on the channel */
   EPCMD_MEDIA_Q_START,          /* Start DSP media Q relay */
   EPCMD_MEDIA_Q_DUMP,           /* Display media Q relay results to console */
   EPCMD_MEDIA_Q_SET_SKIP_NUM,   /* Num of buffers to skip before capture starts */
   EPCMD_PRINT_DSP_CAPABILITIES, /* Display DSP capabilities. */
   EPCMD_DSP_STACK_SHOW,         /* Display DSP stack usage statistics. */
   EPCMD_HAPINET_CONFIG_SETREG,  /* Set configuration registers of the NET Service */
   EPCMD_DSP_ICP_CALIBRATE,      /* Calibrate DSP idle profiler. */
   EPCMD_DSP_ICP_START,          /* Start DSP idle profiler. */
   EPCMD_DSP_DPR_START,          /* Start development DSP profiler. */
   EPCMD_DSP_ICP_STOP,           /* Stop DSP idle profiler. */
   EPCMD_CONFIGURE_NETWTEST,     /* Configure switchboard connections for network test. */
   EPCMD_SET_ECAN_STATE,         /* Force ECAN to a certain state (on, off, NLP off) */
   EPCMD_HEC_BURST_ENABLE,
   EPCMD_HEC_NOISE_ENABLE,
   EPCMD_HEC_DEFAULT,
   EPCMD_HEC_GET_STATE,
   EPCMD_CASEVT_GENERATE,
   EPCMD_TONEEVT_GENERATE,
   EPCMD_INDTMF_GENERATE,
   EPCMD_CONNECTSB,
   EPCMD_INGRESSGAIN_SET,
   EPCMD_EGRESSGAIN_SET,
   EPCMD_DECT_START_BUFF_PROC,
   EPCMD_DECT_STOP_BUFF_PROC,
   EPCMD_PBDT_START,
   EPCMD_PBDT_STOP,
   EPCMD_PBDT_POWER,
   EPCMD_TPD_START,
   EPCMD_RTCP_NTP_TS_UPDATE,     /* Update RTCP NTP timestamp */
   EPCMD_PROVTABLE_SHOW,         /* Print out dynamic provisioning table */
   EPCMD_RESET_PROVTABLE,        /* Reset the provision table to defaults */
   EPCMD_DECTTEST,
   EPCMD_HOSTASSERT,
   EPCMD_HALCAP_SETUP,
   EPCMD_HALCAP_START,
   EPCMD_HALCAP_STOP,
   EPCMD_HALCAP_DEINIT,
   EPCMD_MAX
} EPCONSOLECMD;

/*
** Console command parameters
*/
typedef struct
{
   unsigned int arg[8];
} EPCMD_PARMS;

#if defined( NTR_SUPPORT )
/*
** Network Timing Reference Synchronization parameters
*/
typedef enum
{
   GET_COUNTS,  /* Get the latest NTR and MIPS register values */
   SET_FEEDBACK,/* Set the PCM feedback register */
   GET_NDIV,    /* Get the latest NDIV_INT and NDIV_FRAC register values */
   PRINT_REGS   /* Debug command that prints out NTR and MIPS register values over a period of time */
} EPNTR_ACT;

typedef struct
{
   EPNTR_ACT                  ntrAction;
   VRG_UINT8                  isEnbl;
   VRG_SINT32                 pcmStepsAdjust;
   VRG_UINT32                 localCount;
   VRG_UINT32                 ntrCount;
   VRG_UINT32                 ndivInt;
   VRG_UINT32                 ndivFrac;
} EPNTR_PARMS;
#endif /* NTR_SUPPORT */

/* Data Mode Types */
typedef enum
{
   EPDATAMODE_NONE,          /* Disable CDIS */
   EPDATAMODE_VBD,           /* VBD (no FAXR or auto encoder switch) - default mode */
   EPDATAMODE_T38,           /* Use T38 fax relay (no auto encoder switch) */
   EPDATAMODE_T38_MUTE       /* Use T38 fax relay (but mute until instructed to switch to T.38) */
} EPDATAMODE;

/* Auto Encoder switch */
typedef enum
{
   EPAUTOENC_OFF = 0,   /* Auto encoder switch is turned off */
   EPAUTOENC_ON         /* Auto encoder switch is turned on */
} EPAUTOENC;

/*
** Endpoint types
*/
typedef enum
{
   EPTYPE_FXS,               /* Foreign Exchange Station, we talk to
                              * phone-like devices */
   EPTYPE_PSTN,              /* (FXO) Public switched telephone network,
                              * we talk to a phone switch */
   EPTYPE_DECT,              /* It is a DECT endpt which has no signaling
                                on its audio path */
   EPTYPE_NOSIG              /* No signalling, i.e. no CAS, tones, CLID.
                              * Used for paging/music-on-hold endpoints */

} EPTYPE;

/*
** CLID type supported by the endpoint.  The CLID type is dependent of the actual
** locale (aka country) settings for the endpoint.
**
** This enum matches the content of the CLASS_SIG_TYPE enum in hdspClass.h for ease
** of usage.
*/
typedef enum
{
   EPCLIDTYPE_FSK = 1,       /* CLID for this endpoint is FSK */
   EPCLIDTYPE_DTMF,          /* CLID for this endpoint is DTMF */

} EPCLIDTYPE;

/* T.38 Error Correction Scheme */
typedef enum
{
   EPT38EC_NONE,             /* No error correction */
   EPT38EC_UDPREDUNDANCY,    /* UDP Redundancy */
   /* EPT38EC_UDPFEC, ******* UDP Forward Error Correction - NOT SUPPORTED *****/

} EPT38ECMODE;

/* T.38 Connection Parameters */
typedef struct
{
   EPT38ECMODE     ecMode;              /* Error correction mode associated with the connection */
   VRG_UINT32      maxRemDgrm;          /* Maximum datagram size the remote end can handle      */
   VRG_UINT32      maxBitRate;          /* Maximum bit rate for the fax call                    */
   VRG_UINT32      numFaxPagesTx;       /* Number of transmitted pages for the life of the cnx */
   VRG_UINT32      numFaxPagesRx;       /* Number of received pages for the life of the cnx */
   VRG_UINT16      keepAliveInterval;   /* Interval at which keepAlive T.30 no signal indicator is sent during T.38 mode*/

} EPZT38PARAM;


/* XR Reporting Mode Types - only for VoIP Metrics*/
typedef enum
{
   EPRTCPXRMODE_UNSET,
   EPRTCPXRMODE_ON,          /* Enable XR Collecting & Reporting */
   EPRTCPXRMODE_OFF,         /* Disable XR Collecting & Reporting */
   EPRTCPXRMODE_NEGOTIATE,   /* Enable XR Collecting & Disable XR Reporting */
} EPRTCPXRMODE;


/* VBD (V.152) Redundancy support */
typedef enum
{
   EPVBDRED_OFF,             /* Enable redundancy for VBD */
   EPVBDRED_ON,              /* Disable redundancy for VBD */
} EPVBDREDMODE;


/* VBD mode */
typedef enum
{
   EPVBDMODE_NONE   = (0),
   EPVBDMODE_LEGACY = (1 << 0),         /* Legacy VBD mode */
   EPVBDMODE_V152   = (1 << 1),         /* V.152 VBD mode */
   EPVBDMODE_MAX    = 2

} EPVBDMODE;

/* DTMF tone on/off */
typedef enum
{
   EPDTMFACT_TONEON = 0,
   EPDTMFACT_TONEOFF,
   EPDTMFACT_EGRESS_TONEON,
   EPDTMFACT_EGRESS_TONEOFF,
} EPDTMFACT;

typedef enum
{
   EPDTMFINJECT_INGOFF = 0,
   EPDTMFINJECT_INGON,        /* Inject DTMF to the ingress direction */
} EPDTMFINJECT;

/* VBD parameters */
typedef struct
{
   EPVBDMODE    vbdMode;
   EPVBDREDMODE vbdRedMode;
} EPZVBDPARAM;

/* Tone relay parameters */
typedef enum DTMF_RELAY_TYPE
{
   DTMF_RELAY_RFC2833_DISABLED,
   DTMF_RELAY_RFC2833_ENABLED,
   DTMF_RELAY_RFC2833_SUBTRACT
} DTMF_RELAY_TYPE;

/* DTMF RFC 2833 mode */
typedef enum
{
   EPDTMFRFC2833_ENABLED,
   EPDTMFRFC2833_DISABLED,
   EPDTMFRFC2833_SUBTRACT,
} EPDTMFRFC2833CONFIG;

/* Preferred VBD codec */
typedef enum
{
   EPVBDCODEC_NONE, 
   EPVBDCODEC_PCMU,
   EPVBDCODEC_PCMA

} EPPREFERREDVBDCODEC;

/* Tone Detection mode */
typedef enum
{
   EPTONEDET_ALL_ENABLED,
   EPTONEDET_ALL_DISABLED,
   EPTONEDET_V18ALARMPOS_DISABLED,
   EPTONEDET_ALARMPOS_DISABLED,
} EPTONEDETMODE;

/* Metering burst frequency */
typedef enum
{
   PULSE_SIGNAL_FREQ_12KHZ = 12000, 
   PULSE_SIGNAL_FREQ_16KHZ = 16000, 

} EPPULSESIGFREQUENCY;

/*
** Connection parameters
*/
typedef struct
{
   EPCNXMODE         mode;             /* connection mode */
   CODECCNXPARMLIST  cnxParmList;      /* list (in ordered preference) of negotiated
                                        * codecs/packetization period between the local
                                        * and remote endpoint */
   VRG_UINT32        namedPhoneEvts;   /* bit-field of negotiated named telephone events */
   VRG_UINT16        echocancel;       /* echo cancellation */
   VRG_UINT16        silence;          /* silence suppression */
   VRG_UINT16        comfortNoise;     /* comfort noise */
   VRG_UINT16        preserveFaxMode;  /* preserve a fax mode (if we are in already) */
   VRG_UINT16        secHdrSize;       /* Authentication mode -- security header size */
   EPDATAMODE        dataMode;         /* fax relay, vbd, or none */
   EPAUTOENC         autoEncoder;      /* Auto Encoder Switch */
   EPZT38PARAM       t38param;         /* T.38 fax parameters */
   EPRTCPXRMODE      rtcpXRMode;       /* rtcp XR mode -- on, off or negotiate */
   EPZVBDPARAM       vbdparam;         /* VBD parameters */
   EPDTMFRFC2833CONFIG digitRelayType; /* DTMF tone relay type */
   VRG_UINT32        localSsrc;        /* Local SSRC for the ingress RTP packets */

} EPZCNXPARAM;

/*
** Connection statistics
*/
typedef struct
{
   VRG_UINT32     txpkts;           /* packets sent */
   VRG_UINT32     txbytes;          /* octets sent */
   VRG_UINT32     rxpkts;           /* packets received */
   VRG_UINT32     rxbytes;          /* octets received */
   VRG_SINT32     lost;             /* packets lost */
   VRG_UINT32     discarded;        /* discarded packets */
   VRG_UINT32     txRtcpPkts;       /* Number of ingress RTCP packets */
   VRG_UINT32     rxRtcpPkts;       /* Number of egress RTCP packets */
   VRG_UINT16     txRtcpXrPkts;     /* Number of egress RTCP XR packets */
   VRG_UINT16     rxRtcpXrPkts;     /* Number of egress RTCP XR packets */
   VRG_UINT16     overRuns;         /* Number of jitter buffer overruns */
   VRG_UINT16     underRuns;        /* Number of jitter buffer underruns */
   VRG_UINT32     jitter;           /* Interarrival jitter estimate from RTP service (in ms) */
   VRG_UINT16     peakJitter;       /* Peak jitter / holding time from voice PVE service (in ms)*/
   VRG_UINT16     jbMin;            /* Jitter buffer nominal delay */
   VRG_UINT16     jbAvg;            /* Jitter buffer average delay */
   VRG_UINT16     jbMax;            /* Jitter buffer absolute maximum delay */
   VRG_UINT32     latency;          /* Avg tx delay (in ms) */
   VRG_UINT16     peakLatency;      /* Peak tx delay (in ms) */
   VRG_UINT16     MOSLQ;            /* MOS-listening quality (value*10) */
   VRG_UINT16     MOSCQ;            /* MOS-conversational quality (value*10) */
} EPZCNXSTATS;

/*
** Connection T.38 specific statistics
*/
typedef struct
{
   VRG_UINT32     txpg;             /* pages sent */
   VRG_UINT32     rxpg;             /* pages received */

} EPZT38CNXSTATS;

/*
** Endpoint capabilities
*/
typedef struct EPZCAP   /* Endpoint Capabilities */
{
   VRG_UINT16  pCap[2];      /* Packetazation period data (msec). MS-Bit contains "1" if a range is defined */
   VRG_UINT8   codecCap[CODEC_MAX_TYPES];   /* Codec caps for the given endpoint */
   VRG_UINT32  nteCap;       /* Bit encoded value representing supported named telephone events */
   VRG_UINT16  eCap;         /* Echo cancelation (0 if NOT supported) */
   VRG_UINT16  sCap;         /* Silence Suppression parameter (0 if NOT supported) */
   int         mCap[16];     /* Connection Modes. Each char codes the connection mode coded as MGECMODE enum type */
   EPTYPE      endptType;    /* Endpoint type */
   EPCLIDTYPE  clidType;     /* CLID type */
   VRG_UINT8   clidData[2];  /* Extra data.  Used for EPCLIDTYPE_DTMF to carry head/tail information */
   VRG_UINT8   vbdCap;     /* Bit encoded value representing supported voice band data capabilities. */
   VRG_UINT8   redLvl;     /* Maximum number of redundancy level(s) supported per RFC 2198. */
} EPZCAP;

/*
** RTP header format
** NOTE: The first six fields are bit-length specific.
**       The RTP payload directly follows the RTP header.
*/
typedef struct {

#if BOS_CFG_BIG_ENDIAN
    VRG_UINT8  version:2;   /* protocol version */
    VRG_UINT8  p:1;         /* padding flag */
    VRG_UINT8  x:1;         /* header extension flag */
    VRG_UINT8  cc:4;        /* CSRC count */
    VRG_UINT8  m:1;         /* marker bit */
    VRG_UINT8  pt:7;        /* payload type */
#elif BOS_CFG_LITTLE_ENDIAN
    VRG_UINT8  cc:4;        /* CSRC count */
    VRG_UINT8  x:1;         /* header extension flag */
    VRG_UINT8  p:1;         /* padding flag */
    VRG_UINT8  version:2;   /* protocol version */
    VRG_UINT8  pt:7;        /* payload type */
    VRG_UINT8  m:1;         /* marker bit */
#else
   #error "BOS_CFG_xxx_ENDIAN not defined!"
#endif
    VRG_UINT8  seq[2];      /* 16-bit sequence number */
    VRG_UINT8  ts[4];       /* 32-bit timestamp */
    VRG_UINT8  ssrc[4];     /* synchronization source */
} RTPPACKET;

/*
** Reason code associated with events reported from the endpoint module
** to the upper layer application.  It is up to the application receiving
** the event to use the reason code for event processing.
*/
typedef enum
{
   EPEVTREASON_PTSW,         /* Payload type switch. */
   EPEVTREASON_CNG,          /* CNG signal. */
   EPEVTREASON_EGRESS_CNG,   /* Egress CNG signal. */
   EPEVTREASON_V21flag,      /* V.21 flag. */
   EPEVTREASON_V21tone,      /* V.21 tone. */
   EPEVTREASON_BAUDOT,       /* V.18 Baudot tone and character. */
   EPEVTREASON_BAUDOT_SHORT, /* V.18 Baudot tone and character. Shorter duration (100ms instead of 110ms). */
   EPEVTREASON_EGRESS_BAUDOT_SHORT, /* V.18 Baudot tone and character. Shorter duration (100ms instead of 110ms). */
   EPEVTREASON_BELLTONE,     /* Bell 103 carrier. */
   EPEVTREASON_ANS,          /* V.25 ANS. */
   EPEVTREASON_EGRESS_ANS,   /* Egress V.25 ANS. */
   EPEVTREASON_prANS,        /* V.25 ANS with phase reversal. */
   EPEVTREASON_EGRESS_prANS, /* Egress V.25 ANS with phase reversal. */
   EPEVTREASON_CUSTTONE_INGRESS, /* Ingress custom tone detected */
   EPEVTREASON_CUSTTONE_EGRESS, /* Ingress custom tone detected */
} EPEVTREASON;

/*
** Reason code associated with a VBD_STOP event. For now, enxtended low
** energy is the only event of interest. More values may be introduced
** in the future.
*/
typedef enum
{
   EVEVTVDBSTOP_EXTLOWENERGY /* Extended low energy */
} EPEVTVBDSTOPREASON;

/*
** Maximum number of entries in the codec table array.  This
** number should really be tied to the number of supported cnxs. */
#define VRG_CODEC_TABLE_MAX_ROW_ENTRY      4


/*
** Definition of a single codec entry in the codec table array
*/
typedef struct VRG_CODEC_TABLE_ROW_ENTRY
{
   CODEC_TYPE  codec;      /* codec type */
   VRG_UINT16  maxCodec;   /* maximum number of simultaneous operation
                           ** of the assiocated codec type */

} VRG_CODEC_TABLE_ROW_ENTRY;


/*
** Definition of a single row of the codec table
**
** Each row is composed of 2 components:
**    1. an array of codec entries
**    2. number of elements in the array that is being used
*/
typedef struct VRG_CODEC_TABLE_ROW
{
   /* Array of codec entries */
   VRG_CODEC_TABLE_ROW_ENTRY  codecTableEntry[VRG_CODEC_TABLE_MAX_ROW_ENTRY];

   /* Number of entries used in the array */
   int                        codecTableNumEntry;


} VRG_CODEC_TABLE_ROW;

/* Maximum size of the output buffer for the EPCMD_VHD_STATS_FROM_CNX endpt
 * command. */
#define MAX_EPCMD_VHD_STATS_FROM_CNX_BUFFER_SIZE 750

/* Get/set macros for RTPPACKET structure  - access to (non-bit field) RTPPACKET member
 * variables should be made through these macros. The macros resolve alignment issues
 * that may occur if the endpoint produces or consumes an RTP packet that isn't 32-bit aligned. */
#define RTPPACKET_GET_SEQNUM( rtp ) ( (rtp)->seq[0] << 8 | (rtp)->seq[1] )

#define RTPPACKET_SET_SEQNUM( rtp, val ) ((rtp)->seq[0] = (VRG_UINT8)((( val ) & 0xff00 ) >> 8), \
                                          (rtp)->seq[1] = (VRG_UINT8)(( val ) & 0x00ff ))

#define RTPPACKET_GET_TIMESTAMP( rtp ) ((rtp)->ts[0] << 24 | (rtp)->ts[1] << 16 | \
                                          (rtp)->ts[2] << 8 | (rtp)->ts[3] )

#define RTPPACKET_SET_TIMESTAMP( rtp, val ) ((rtp)->ts[0] = (VRG_UINT8)((( val ) & 0xff000000 ) >> 24),  \
                                            (rtp)->ts[1] = (VRG_UINT8)((( val ) & 0x00ff0000 ) >> 16),  \
                                            (rtp)->ts[2] = (VRG_UINT8)((( val ) & 0x0000ff00 ) >> 8),   \
                                            (rtp)->ts[3] = (VRG_UINT8)(( val ) & 0x000000ff ))

#define RTPPACKET_IS_VALID_VERSION( rtp ) ( (rtp)->version == 0x2 )


#if BOS_CFG_BIG_ENDIAN

#define RTPPACKET_GET_SSRC( rtp ) ((rtp)->ssrc[0] << 24 | (rtp)->ssrc[1] << 16 | \
                                          (rtp)->ssrc[2] << 8 | (rtp)->ssrc[3] )

#define RTPPACKET_SET_SSRC( rtp, val ) ((rtp)->ssrc[0] = (VRG_UINT8)((( val ) & 0xff000000 ) >> 24), \
                                         (rtp)->ssrc[1] = (VRG_UINT8)((( val ) & 0x00ff0000 ) >> 16), \
                                         (rtp)->ssrc[2] = (VRG_UINT8)((( val ) & 0x0000ff00 ) >> 8),  \
                                         (rtp)->ssrc[3] = (VRG_UINT8)(( val ) & 0x000000ff ))
#else
#define RTPPACKET_GET_SSRC( rtp ) ((rtp)->ssrc[3] << 24 | (rtp)->ssrc[2] << 16 | \
                                          (rtp)->ssrc[1] << 8 | (rtp)->ssrc[0] )

#define RTPPACKET_SET_SSRC( rtp, val ) ((rtp)->ssrc[3] = (VRG_UINT8)((( val ) & 0xff000000 ) >> 24), \
                                         (rtp)->ssrc[2] = (VRG_UINT8)((( val ) & 0x00ff0000 ) >> 16), \
                                         (rtp)->ssrc[1] = (VRG_UINT8)((( val ) & 0x0000ff00 ) >> 8),  \
                                         (rtp)->ssrc[0] = (VRG_UINT8)(( val ) & 0x000000ff ))
#endif


/* Media Types */
typedef enum
{
   EPMEDIATYPE_RTP,          /* rtp packet */
   EPMEDIATYPE_RTCP,         /* rtcp packet */
   EPMEDIATYPE_T38           /* t38 packet */
} EPMEDIATYPE;

/* Endpt Packet Type */
typedef struct
{
   EPMEDIATYPE mediaType;    /* Type of packet (fax/non-fax) */
   void* packetp;            /* Pointer to the packet */
} EPPACKET;


/* --------------------------------------------------------------------------
** 'ENDPT_STATE' is the base, generic endpt structure; it specifies a set of
** function pointers that define the generic endpt API that must be provided by
** all derived endpt types.
**
** All members of the 'ENDPT_STATE' structure must be present in all derived
** endpt structures, in the same order.
**
** Derived endpoint types should provide a "derived" version of ENDPT_STATE, e.g.:
**
**    typedef struct MY_ENDPT_STATE
**    {
**       const struct ENDPT_FUNCS  *endptFuncs;
**       int                        lineId;
**
**       int                        myEndptSpecificData1;
**       int                        myEndptSpecificData2;
**       ...
**
**    } MY_ENDPT_STATE;
**
** Clients, which have access to ENDPT_STATE structs, can use the generic
** macros provided below to transparently invoke derived endpt specific
** functions. The derived endpt functions will receive a pointer to the
** ENDPT_STATE struct as the first parameter. This struct can be cast to the
** derived endpt structure to gain access to endpt specific instance memory.
*/
typedef struct
{
   /* All derived structure must contain all members below. */
   const struct ENDPT_FUNCS  *endptFuncs;
   int                        lineId;

} ENDPT_STATE;


/* ---- Variable Externs ------------------------------------------------- */
/* ---- Function Prototypes ---------------------------------------------- */

/* --------------------------------------------------------------------------
** Callback functions that should be registered with the endpoint.
*/

/*
*****************************************************************************
** FUNCTION:   endptEventCallback
**
** PURPOSE:    Endpoint event callback function prototype
**
** PARAMETERS: endptState  - endpt object.
**             cnxId       - the connection identifier (-1 if not applicable)
**             event       - the event
**             data        - additional data for the event
**             datap       - pointer to received data
**             length      - length of the received data
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef void (*endptEventCallback)( ENDPT_STATE *endptState, int cnxId,
                                    EPEVT event, void *datap, int length, int data );

/*
*****************************************************************************
** FUNCTION:   endptRtpPacketCallback
**
** PURPOSE:    Endpoint connection packet callback
**
** PARAMETERS: endptState  - endpt object.
**             cnxId       - the connection id.
**             packet      - the endpt packet
**             length      - the endpt packet length including header
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef void (*endptPacketCallback)
(
   ENDPT_STATE   *endptState,
   int            cnxId,
   EPPACKET      *packet,
   int            length
);

/*
*****************************************************************************
** FUNCTION:   endptGetProvCallback
**
** PURPOSE:    Endpoint provisioned value callback
**
** PARAMETERS: lineId         - endpt indentifier
**             provItemId     - the enumerated id of the provisionable item
**             provItemValue  - pointer to the provisioned data value
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef EPSTATUS (*endptGetProvCallback)
(
   int            lineId,
   EPPROV         provItemId,
   void          *provItemValue
);


/*
*****************************************************************************
** FUNCTION:   endptSetProvCallback
**
** PURPOSE:    Endpoint provisioned value callback
**
** PARAMETERS: lineId         - endpt indentifier
**             provItemId     - the enumerated id of the provisionable item
**             provItemValue  - pointer to the provisioned data value
**             length         - pointer to the length to set
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef EPSTATUS (*endptSetProvCallback)
(
   int            lineId,
   EPPROV         provItemId,
   void          *provItemValue,
   int            length
);


/*
*****************************************************************************
** FUNCTION:   endptPacketReleaseCallback
**
** PURPOSE:    Callback handler invoked when the packet passed to endptRtpPacket
**             is released by the endpoint back to the caller.
**
** PARAMETERS: endptState  - endpt object.
**             cxid        - connection identifier
**             bufDesc     - buffer descriptor value passed to endptRtpPacket
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef void ( *endptPacketReleaseCallback )
(
   ENDPT_STATE   *endpt,
   int            cxid,
   unsigned int   bufDesc
);


/*
*****************************************************************************
** FUNCTION:   endptTaskShutdownCallback
**
** PURPOSE:    Callback handler invoked just prior to the shutdown of
**             endpoint tasks.
**
** PARAMETERS: none
**
** RETURNS:    nothing
**
** NOTE:       This callback will be triggered in response to a call to
**             vrgEndptDeinit. Currently, it MUST be invoked within the
**             context of the task that invokes the endptRtpPacketCallback
**             (i.e. RTP procuder task). It may be invoked within
**             the context of other tasks in the future (depending on system
**             requirements).
**
**             This callback has been provided to support lame OSs (e.g. pSOS)
**             that only allow the creator of some resources (e.g. sockets) to
**             use those resources. If another task (e.g. RTP packet producer)
**             needs to use that resource, it needs to be shared. Subsequently,
**             the shared resource needs to be freed from *within the context
**             of the task that it was shared with*. i.e. shared resources
**             should be freed within the context of this callback.
**
*****************************************************************************
*/
typedef void ( *endptTaskShutdownCallback ) ( void );



/* --------------------------------------------------------------------------
** Endpoint API function pointers.
*/

/*
*****************************************************************************
** FUNCTION:   endptCapabilities
**
** PURPOSE:    Retrieve the capabilities for an endpoint
**
** PARAMETERS: endptState     - endpt object.
**             capabilities   - a pointer to the capabilities struct to populate
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
typedef EPSTATUS (*endptCapabilities)
(
   ENDPT_STATE   *endptState,
   EPZCAP        *capabilities
);

/*
*****************************************************************************
** FUNCTION:   endptSignal
**
** PURPOSE:    Generate a signal on the endpoint (or connection)
**
** PARAMETERS: endptState  - endpt object.
**             cnxId       - connection identifier (-1 if not applicable)
**             signal      - signal type code (see EPSIG)
**             value       - signal value
**                            BR signal types - 1
**                            OO signal types - 0 == off, 1 == on
**                            TO signal types - 0 = stop/off, 1= start/on
**                            String types - (char *) cast to NULL-term string value
**              duration   - pulse duration (-1 if not used)
**              period     - pulse period (-1 if not used)
**              repetition - depending on the pulsed signal, this parameter
**                           has different meaning:
**                             - 'em': defines the report pulse count (rpc)
**                             - other pulsed signals: defines the repetition (rep)
**                           (-1 if not used)
**
** RETURNS:    EPSTATUS
**
*****************************************************************************
*/
typedef EPSTATUS (*endptSignal)
(
   ENDPT_STATE   *endptState,
   int            cnxId,
   EPSIG          signal,
   unsigned int   value,
   int            duration,
   int            period,
   int            repetition
);

/*
*****************************************************************************
** FUNCTION:   endptCreateConnection
**
** PURPOSE:    Function to create a connection
**
** PARAMETERS: endptState  - endpt object.
**             cnxId       - connection identifier
**             cnxParam    - ptr to connection parameter block
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
typedef EPSTATUS (*endptCreateConnection)
(
   ENDPT_STATE   *endptState,
   int            cnxId,
   EPZCNXPARAM   *cnxParam
);

/*
*****************************************************************************
** FUNCTION:   endptModifyConnection
**
** PURPOSE:    Function to modify a connection
**
** PARAMETERS: endptState  - endpt object.
**             cnxId       - connection identifier
**             cnxParam    - ptr to connection parameter block
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
typedef EPSTATUS (*endptModifyConnection)
(
   ENDPT_STATE   *endptState,
   int            cnxId,
   EPZCNXPARAM   *cnxParam
);

/*
*****************************************************************************
** FUNCTION:   endptDeleteConnection
**
** PURPOSE:    Function to delete a connection
**
** PARAMETERS: endptState  - endpt object.
**             cnxId       - connection identifier
**
** RETURNS:    EPSTATUS - if success, fills in statistics block
**
** NOTE:
*****************************************************************************
*/
typedef EPSTATUS (*endptDeleteConnection)( ENDPT_STATE *endptState, int cnxId );


/*****************************************************************************
** FUNCTION:   endptLinkInternal
**
** PURPOSE:    Function to internally link two endpoints
**
** PARAMETERS:  endptState       - first endpt object.
**              otherEndptState  - second endpt object.
**              link             - whether or not to link or unlink.
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
typedef EPSTATUS (*endptLinkInternal)
(
   ENDPT_STATE *endptState,
   ENDPT_STATE *otherEndptState,
   VRG_BOOL link
);

/*
*****************************************************************************
** FUNCTION:   endptPacket
**
** PURPOSE:    Transmit a endpt packet to the endpoint. This function is asynchronous,
**             it does not wait for the data to be transmitted  before returning.
**             In addition, the buffer release mechanism is asynchronous.
**             The endpoint owns the packet passed to this function until a callback
**             is invoked releasing the packet back to the caller (endptPacketReleaseCallback).
**             The value of 'bufDesc' will be passed to the callback function so that
**             the caller can identify which packet is being released by the endpoint.
**
** PARAMETERS: endptState - endpt object.
**             epPacket   - pointer to the EPPACKET packet.
**             length     - the length of the endpt packet including header
**             bufDesc    - buffer descriptor value that uniquely identifies
**                          the packet. This value is returned in the
**                          callback invoked once the buffer has been completely
**                          transmitted. This value is only meaningful to the
**                          caller and is opaque to the endpoint.
**
** RETURNS:    EPSTATUS
**
** NOTE:       If this function does not return EPSTATUS_SUCCESS, it is the caller's
**             responsibility to free the RTP packet.
**
*****************************************************************************
*/
typedef EPSTATUS (*endptPacket)
(
   ENDPT_STATE   *endptState,
   int            cnxId,
   EPPACKET      *epPacket,
   int            length,
   unsigned int   bufDesc
);


/*
*****************************************************************************
** FUNCTION:   endptConsoleCmd
**
** PURPOSE:    Display endpoint info to the console
**
** PARAMETERS: endptState  - endpt object.
**             cnxId       - the connection index
**             cmd         - endpoint console command type
**
** RETURNS:    nothing
**
** NOTE:
*****************************************************************************
*/
typedef EPSTATUS (*endptConsoleCmd)
(
   ENDPT_STATE       *endptState,
   EPCONSOLECMD      cmd,
   EPCMD_PARMS       *pConsoleCmdParams
);


/*
*****************************************************************************
** FUNCTION:   endptPowerSourceChanged
**
** PURPOSE:    Notify endpoint of power source changed
**
** PARAMETERS: newPowerSource - 0: operating on AC
**                              1: operating on battery power
**
** RETURNS:    nothing
**
** NOTE:
*****************************************************************************
*/
typedef void (*endptPowerSourceChanged)
(
   int   newPowerSource
);


/*
*****************************************************************************
** FUNCTION:   endptRtpStatistics
**
** PURPOSE:    get RTP statistics
**
** PARAMETERS: endptState  - endpt object
**             cnxId       - connection identifier
**             epRtpStats  - RTP stats
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
typedef EPSTATUS (*endptRtpStatistics)
(
   ENDPT_STATE    *endptState,
   int            cnxId,
   EPZCNXSTATS    *epRtpStats
);


/*
*****************************************************************************
** FUNCTION:   endptIsEnabled
**
** PURPOSE:    Determine if the endpoint is enabled.
**
** PARAMETERS: int lineId;
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef void ( *endptIsEnabled )
(
   int               lineId,
   int 				 *enabled
);


#if defined( NTR_SUPPORT )
/*
*****************************************************************************
** FUNCTION:   endptNtrCmd
**
** PURPOSE:    Either update PCM feedback registers in kernel space, or obtain latest counts
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef void ( *endptNtrCmd )
(
   ENDPT_STATE             *endpt,
   VRG_UINT8               ntrAction,
   VRG_UINT8               isEnbl,
   VRG_SINT32              pcmStepsAdjust,
   VRG_UINT32              *localCount,
   VRG_UINT32              *ntrCount,
   VRG_UINT32              *ndivInt,
   VRG_UINT32              *ndivFrac 
); 
#endif /* NTR_SUPPORT */

/*
*****************************************************************************
** FUNCTION:   endptT38Statistics
**
** PURPOSE:    Get T.38 stats from the endpoint.
**
** PARAMETERS: endptState  - endpt object.
**             cnxId        - connection identifier
**             epT38Stats  - T.38 stats
**
** RETURNS:    nothing
**
*****************************************************************************
*/
typedef void ( *endptT38Statistics )
(
   ENDPT_STATE       *endpt,
   int               cnxId,
   EPZT38CNXSTATS    *epT38Stats
);


/*
*****************************************************************************
** FUNCTION:   endptMuteConnection
**
** PURPOSE:    Toggle the mute status of a connection on the endpoint.
**
** PARAMETERS: endptState  - endpt object.
**             cnxId        - connection identifier
**             mute        - mute status for the connection
**
** RETURNS:    EPSTATUS
**
*****************************************************************************
*/
typedef EPSTATUS ( *endptMuteConnection )
(
   ENDPT_STATE       *endpt,
   int               cnxId,
   VRG_BOOL          mute
);

/*
*****************************************************************************
** FUNCTION:   endptSetCasState
**
** PURPOSE:    To set the CAS state of a given endpoint. Used by external CAS.
**
** PARAMETERS: endptState  - endpt object.
**             lineId      - line number
**             casState    - New CAS state to set to the given endpoint
**
** RETURNS:    EPSTATUS
**
*****************************************************************************
*/
typedef EPSTATUS ( *endptSendCasEvt )
(
   int                 lineId,
   CAS_CTL_EVENT_TYPE  casEvtType,
   CAS_CTL_EVENT       casCtlEvt 
);

/*
** Structure that contains all function pointers that define the endpt API.
*/
typedef struct ENDPT_FUNCS
{
   endptCapabilities       getCapabilities;     /* Retrieve endpoint capabilities */
   endptSignal             generateSignal;      /* Generate signal on endpoint */
   endptCreateConnection   createConnection;    /* Create connection to endpoint */
   endptModifyConnection   modifyConnection;    /* Modify existing connection */
   endptDeleteConnection   deleteConnection;    /* Delete connection */
   endptLinkInternal       linkInternal;        /* Link or unlink two internal endpts */
   endptPacket             sendPacket;          /* Send endpt packet to connection */
   endptConsoleCmd         consoleCmd;          /* Display endpoint info to console */
   endptPowerSourceChanged powerSourceChanged;  /* Notify power source changed */
   endptRtpStatistics      rtpStatistics;       /* RTP statistics for the connection. */
   endptT38Statistics      t38Statistics;       /* T.38 statistics for the connection. */
   endptIsEnabled		   isEnabled;           /* Is the endpoint enabled*/
   endptMuteConnection     muteConnection;      /* Toggle mute status on a connection */
   endptSendCasEvt         sendCasEvt;          /* Function used by external CAS to send CAS events to endpt */
#if defined( NTR_SUPPORT )
   endptNtrCmd             ntrCmd;
#endif /* NTR_SUPPORT */
} ENDPT_FUNCS;


/* --------------------------------------------------------------------------
** This is the generic API that should be used by clients to access the endpt.
*/

#define endptCapabilities( state, cap ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->getCapabilities( (state), (cap) ) : EPSTATUS_ERROR )

#define endptSignal( state, cxid, signal, value, duration, period, repetition ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->generateSignal( (state), (cxid), (signal), (value), \
           (duration), (period), (repetition) ) : EPSTATUS_ERROR )

#define endptCreateConnection( state, cxid, parm ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->createConnection( (state), (cxid), (parm) ) : EPSTATUS_ERROR )

#define endptModifyConnection( state, cxid, parm ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->modifyConnection( (state), (cxid), (parm) ) : EPSTATUS_ERROR )

#define endptDeleteConnection( state, cxid ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->deleteConnection( (state), (cxid) ) : EPSTATUS_ERROR )

#define endptPacket( state, cxid, pkt, len, desc ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->sendPacket( (state), (cxid), (pkt), (len), (desc) ) : EPSTATUS_ERROR )

#define endptConsoleCmd( state, cmd, params ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->consoleCmd( (state), (cmd), (params) ) : EPSTATUS_ERROR )

#define endptPowerSourceChanged( state, newPowerSource ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->powerSourceChanged( (newPowerSource) ) : EPSTATUS_ERROR )

#define endptRtpStatistics( state, cxid, epRtpStats ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->rtpStatistics( (state), (cxid), (epRtpStats) ) : EPSTATUS_ERROR )

#define endptT38Statistics( state, cxid, t38Stats ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->t38Statistics( (state), (cxid), (t38Stats) ) : EPSTATUS_ERROR )

#define endptIsEnabled( state, lineId, enabled ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->isEnabled( (lineId), (enabled) ) : EPSTATUS_ERROR )

#define endptMuteConnection( state, cxid, mute ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->muteConnection( (state), (cxid), (mute) ) : EPSTATUS_ERROR )

#define endptLinkInternal( state, otherState, link ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->linkInternal( (state), (otherState), (link) ) : EPSTATUS_ERROR )

#define endptSendCasEvt( state, lineId, casEvtType, casCtlEvt ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->sendCasEvt( (lineId), (casEvtType), (casCtlEvt) ) : EPSTATUS_ERROR )

#if defined( NTR_SUPPORT )
#define endptNtrCmd( state, action, isEnbl, pcmStepsAdjust, localCount, ntrCount, ndivInt, ndivFrac ) \
         ( (state)->endptFuncs ? (state)->endptFuncs->ntrCmd( (state), (action), (isEnbl), (pcmStepsAdjust), (localCount), (ntrCount), (ndivInt), (ndivFrac)) : EPSTATUS_ERROR )
#endif /* NTR_SUPPORT */


#define  VRG_CLASS_DATE_SIZE         8
#define  VRG_CLASS_MAX_NUMBER_SIZE   20
#define  VRG_CLASS_MAX_NAME_SIZE     16


typedef struct
{
   char  date[VRG_CLASS_DATE_SIZE + 1];          /* date string */
   char  number[VRG_CLASS_MAX_NUMBER_SIZE + 1];  /* phone number string */
   char  name[VRG_CLASS_MAX_NAME_SIZE + 1];      /* name string */
   char  reasonNoNumber;                         /* reason no number (ex. "P") */
   char  reasonNoName;                           /* reason no name (ex. "P") */
} VRG_CLIDRX_DATA;

/*
** VRG endpoint structure. Conceptually, this structure is similar to
** a C++ sub-class that is derived from the 'ENDPT_STATE' base-class(structure).
** The base endpt structure specifies a set of function pointers that defines
** the generic endpt API that must be provided by all derived endpt types.
**
** When the VRG endpt initialization function is invoked, the base endpt
** structure function pointers will be intialized to a set of VRG specific
** endpt functions. Therefore, given a pointer to the base endpt struct,
** clients can interface to a generic endpt API that will vector to the
** derived endpt function.
*/
typedef struct
{
   /* Must be first elements of this struct. */
   const ENDPT_FUNCS   *endptFuncs;
   int                  lineId;
   EPTYPE               endptType;

   /* VRG specific endpt state below. */

} VRG_ENDPT_STATE;


/*
** Endpt initialization structure
*/
typedef struct VRG_ENDPT_INIT_CFG
{
   /* current country code based on nvol settings */
   VRG_COUNTRY    country;

   /* current power source - 0 = utility power
   **                        1 = battery power */
   int            currentPowerSource;

} VRG_ENDPT_INIT_CFG;


/*
*****************************************************************************
** EXTERNAL FUNCTION PROTOTYPES
*****************************************************************************
*/

/*
*****************************************************************************
** FUNCTION:   vrgEndptInit
**
** PURPOSE:    Module initialization for the VRG endpoint. The endpoint
**             module is responsible for controlling a set of endpoints.
**             Individual endpoints are initialized using the vrgEndptInit() API.
**
** PARAMETERS: endptInitCfg             - pointer to endpt configuration block
**             notifyCallback           - Callback to use for event notification
**             packetCallback           - Callback to use for endpt packets
**             getProvisionCallback     - Callback to get provisioned values.
**                                        May be set to NULL.
**             setProvisionCallback     - Callback to get provisioned values.
**                                        May be set to NULL.
**             packetReleaseCallback    - Callback to release ownership of
**                                        endpt packet back to caller
**             taskShutdownCallback     - Callback invoked to indicate endpt
**                                        task shutdown
**             rtpStatsCallback         - Callback invoked to record rtp stats
**
** RETURNS:    EPSTATUS
**
*****************************************************************************
*/
EPSTATUS vrgEndptInit
(
   VRG_ENDPT_INIT_CFG        *endptInitCfg,
   endptEventCallback         notifyCallback,
   endptPacketCallback        packetCallback,
   endptGetProvCallback       getProvisionCallback,
   endptSetProvCallback       setProvisionCallback,
   endptPacketReleaseCallback packetReleaseCallback,
   endptTaskShutdownCallback  taskShutdownCallback
);


/*
*****************************************************************************
** FUNCTION:   vrgEndptDeinit
**
** PURPOSE:    VRG endpoint module shutdown - call once during system shutdown.
**             This will shutdown all endpoints and free all resources used by
**             the VRG endpt manager. (i.e. this function should free all resources
**             allocated in vrgEndptInit() and vrgEndptCreate()).
**
** PARAMETERS: none
**
** RETURNS:    EPSTATUS
**             This function should only return an error under catastrophic
**             circumstances. i.e. Something that cannot be fixed by re-invoking
**             the module initialization function.
**
** NOTE:       It is assumed that this function is only called after all endpoint
**             tasks have been notified of a pending application reset, and each
**             one has acknowledged the notification. This implies that each endpoint
**             task is currently blocked, waiting to be resumed so that they may
**             complete the shutdown procedure.
**
**             It is also assumed that no task is currently blocked on any OS
**             resource that was created in the module initialization functions.
**
*****************************************************************************
*/
EPSTATUS vrgEndptDeinit( void );


/*
*****************************************************************************
** FUNCTION:   vrgEndptCreate
**
** PURPOSE:    This function is used to create a VRG endpoint object.
**
** PARAMETERS: physId      (in)  Physical interface.
**             lineId      (in)  Endpoint line identifier.
**             endptState  (out) Created endpt object.
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgEndptCreate( int physId, int lineId, VRG_ENDPT_STATE *endptState );


/*
*****************************************************************************
** FUNCTION:   vrgEndptDestroy
**
** PURPOSE:    This function is used to de-allocate a VRG endpoint object.
**
** PARAMETERS: endptState  (mod) Created endpt object.
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgEndptDestroy( VRG_ENDPT_STATE *endptState );


/*
*****************************************************************************
** FUNCTION:   vrgEndptGetNumEndPoints
**
** PURPOSE:    Retrieve the number of endpoints in a collection
**
** PARAMETERS: None
**
** RETURNS:    Number of endpoints
**
*****************************************************************************
*/
int vrgEndptGetNumEndpoints( void );


/*
*****************************************************************************
** FUNCTION:   vrgEndptGetNumFxsEndpoints
**
** PURPOSE:    Retrieve the number of FXS endpoints in a collection
**
** PARAMETERS: None
**
** RETURNS:    Number of FXO endpoints
**
*****************************************************************************
*/
int vrgEndptGetNumFxsEndpoints( void );


/*
*****************************************************************************
** FUNCTION:   vrgEndptGetNumFxoEndpoints
**
** PURPOSE:    Retrieve the number of FXO endpoints in a collection
**
** PARAMETERS: None
**
** RETURNS:    Number of FXO endpoints
**
*****************************************************************************
*/
int vrgEndptGetNumFxoEndpoints( void );


/*
*****************************************************************************
** FUNCTION:   vrgEndptGetNumDectEndpoints
**
** PURPOSE:    Retrieve the number of DECT endpoints in a collection
**
** PARAMETERS: None
**
** RETURNS:    Number of DECT endpoints
**
*****************************************************************************
*/
int vrgEndptGetNumDectEndpoints( void );

#ifdef PSTN_LIFE_LINE_SUPPORT
/*
*****************************************************************************
** FUNCTION:   vrgEndptIsPstnLifeLineSupported
**
** PURPOSE:    Determines whether pstn life line is supported
**
** PARAMETERS: None
**
** RETURNS:    true if supported; false otherwise
**
*****************************************************************************
*/
VRG_BOOL vrgEndptIsPstnLifeLineSupported( void );
#endif 

/*****************************************************************************
*  FUNCTION:   vrgEndptVerifyCountry
*
*  PURPOSE:    Look up the country code and verify it is legal
*
*  PARAMETERS: country    - country code
*
*  RETURNS:    EPSTATUS
*
*  NOTES:      SUCCESS or FAILURE
*
*****************************************************************************/
EPSTATUS vrgEndptVerifyCountry( VRG_COUNTRY country );


/*
*****************************************************************************
** FUNCTION:   vrgCodecTableInit
**
** PURPOSE:    Initialize codec table to reflect the simultaneous support
**
** PARAMETERS: none
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgCodecTableInit( void );


/*
*****************************************************************************
** FUNCTION:   vrgCodecTableRetrieveRow
**
** PURPOSE:    Return a single row from the codec table
**
** PARAMETERS: index        - row index to return (0-indexed)
**             pNumOfCodecs - pointer to the location for storing the
**                            retrieved row
**
** RETURNS:    none
**
** NOTE:
*****************************************************************************
*/
void vrgCodecTableRetrieveRow( int index, VRG_CODEC_TABLE_ROW *pNumOfCodecs );

/*
*****************************************************************************
** FUNCTION:   vrgEndptGetEndptOperStatus
**
** PURPOSE:    Get endpt operation status.  An endpt becomes un-operational
**             if any of the vhds associated with the endpt is pending a reset
**
** PARAMETERS: lineId - line Id
**
** RETURNS:    EPSTATUS
**
** NOTE:
*****************************************************************************
*/
EPSTATUS vrgEndptGetEndptOperStatus( int lineId );






typedef struct
{
#ifdef ENDPT_6345
   UINT16    peakHoldingTime;    /* Peak Holding Time since last statistic */

   /* Total number of superpackets arriving on the egress path */
   UINT16    packetCount;        /* # of packets received */

   /* addTail and reorder are successful additions to the JB */
   /* addTail is typically 1..N times the packetCount if superpackets are enabled */
   UINT16    addTailCount;       /* # of frames added to tail of JB - normal case */
   UINT16    reorderCount;       /* # of frames reordered */

   /* overrun, duplicate, outOfRange, tooLate, jitterMax excess are packets that have been discarded */
   UINT16    overrunCount;       /* Decoder overrun count */
   UINT16    duplicateCount;     /* # of duplicate frames deleted */
   UINT16    outOfRangeCount;    /* # of frames with timestamps too far from current TS to be handled */
   UINT16    tooLateCount;       /* Packet arrived too late (it's redundant mate already played) */

   /* cantDecode are packets that can't be played out due to algorithm not available */
   UINT16    cantDecodeCount;    /* Can't decode packet - decoder not in load or pkt hdr bad */

   /* The following are internal to the AJC module - they do not represent physical packets */
   UINT16    ajcUnderrunCount;   /* Adaptive Jitter Control: jitter buffer underruns */
   UINT16    ajcDeleteCount;     /* Adaptive Jitter Control: # of packet deletes done to reduce holding time */
   UINT16    ajcRepeatCount;     /* Adaptive Jitter Control: # of packet repeats done to either increase holding time
                                    or due to late frame or lost frames. */
   UINT16    ajcResyncCount;     /* Number of times ajb resynced (went through buildout state) */
   UINT16    ajcPhaseJitterCount;     /* Number of times ajb inserted a phase discontinuity
                                    (possibly in silence or during CNG or due to a repeat/delete). */
   /* 14 entries.  Make sure this is even (!) */
#else
  UINT16    peakHoldingTime;         /* Peak Holding Time since last statistic */
  UINT16    minimumHoldingTime;      /* Long-term tracker of min. Hold Time */
  UINT16    targetHoldingTime;       /* Target holding Time */
  UINT16    inactiveFrameCount;      /* Inactive Frame Count */
  UINT16    activeFrameCount;        /* Active Frame Count */
  UINT16    hsxDecoderOverrunCount;  /* Decoder overrun count */
  UINT16    hsxDecoderUnderrunCount; /* Decoder underrun count */
  UINT16    lostFrameCount;          /* Lost frames resulting in frame repeat */
#endif
} ENDPT_VOICE_DECODERSTATS;

/* Encoder Statistics */
typedef struct
{
#ifdef ENDPT_6345
   UINT16   inactiveFrameCount;     /* Inactive Frame Count of Suppressed Frames*/
   UINT16   activeFrameCount;       /* Active Frame Count - actually sent ingress */
   UINT16   sidFrameCount;          /* SID Frame Count */
   UINT16   toneRelayCount;         /* # of tone packets from PTE relayed ingress */
#else
  UINT16    hsxEncoderOverrunCount;  /* Encoder overrun count */
#endif
} ENDPT_VOICE_ENCODERSTATS;


typedef struct
{
   ENDPT_VOICE_DECODERSTATS   decoder;
   ENDPT_VOICE_ENCODERSTATS   encoder;
} ENDPT_VOICE_PVE_STATS;

typedef struct
{
   ENDPT_VOICE_PVE_STATS hsxPVEstats;         /* statistics for PVE encoder and decoder */

} ENDPT_VOICE_STATS;

/* Maximum size for the event data passed with the event callback */
#define MAX_EVENTDATA_SIZE    256

/* Maximum size of the string that can be printed from user-space (including NULL character) */
#define MAX_PRINTF_SIZE       4050


typedef enum
{
   IOCTL_STATUS_FAILURE = -1,
   IOCTL_STATUS_SUCCESS =  0,
   IOCTL_STATUS_SHUTDOWN,
   IOCTL_STATUS_DEBUG   
} IOCTL_STATUS;


typedef enum ENDPOINTIOCTL_INDEX
{
   ENDPTIO_INIT_INDEX = 0,
   ENDPTIO_DEINIT_INDEX,
   ENDPTIO_CREATE_INDEX,
   ENDPTIO_DESTROY_INDEX,
   ENDPTIO_CAPABILITIES_INDEX,
   ENDPTIO_SIGNAL_INDEX,
   ENDPTIO_CREATE_CONNECTION_INDEX,
   ENDPTIO_MODIFY_CONNECTION_INDEX,
   ENDPTIO_DELETE_CONNECTION_INDEX,
   ENDPTIO_MUTE_CONNECTION_INDEX,
   ENDPTIO_LINK_INTERNAL_INDEX,
   ENDPTIO_PACKET_INDEX,
   ENDPTIO_GET_PACKET_INDEX,
   ENDPTIO_GET_EVENT_INDEX,
   ENDPTIO_GET_CODECMAP_INDEX,
   ENDPTIO_VOICESTAT_INDEX,
   ENDPTIO_ISINITIALIZED_INDEX,
   ENDPTIO_CONSOLE_CMD_INDEX,
   ENDPTIO_TEST_INDEX,
   ENDPTIO_ENDPOINTCOUNT_INDEX,
   ENDPTIO_FXSENDPOINTCOUNT_INDEX,
   ENDPTIO_FXOENDPOINTCOUNT_INDEX,
   ENDPTIO_DECTENDPOINTCOUNT_INDEX,
#ifdef PSTN_LIFE_LINE_SUPPORT
   ENDPTIO_ISPSTNLIFELINESUPPORTED_INDEX,
#endif
#ifdef NTR_SUPPORT
   ENDPTIO_NTR_CMD_INDEX,
#endif /* NTR_SUPPORT */
   ENDPTIO_HOOKSTAT_INDEX,
   ENDPTIO_SEND_CAS_EVT_INDEX,
   ENDPTIO_SET_RELAY_INDEX,
   ENDPTIO_PRINTF_INDEX,
   ENDPTIO_PROV_SET_INDEX,
   ENDPTIO_PROV_GET_INDEX,
   ENDPTIO_PROBE_SET_INDEX,
   ENDPTIO_PROBE_GET_INDEX,
   ENDPTIO_GET_RTP_STATS_INDEX,
#if defined(BRCM_IDECT_CALLMGR) || defined(BRCM_EDECT_CALLMGR)
   ENDPTIO_DECT_INFO_INDEX,
   ENDPTIO_DECT_HS_INFO_INDEX,
   ENDPTIO_DECT_GET_NVS_INDEX,
   ENDPTIO_DECT_SET_NVS_INDEX,
#endif /* BRCM_IDECT_CALLMGR || BRCM_EDECT_CALLMGR */

   ENDPTIO_MAX_INDEX
} ENDPOINTIOCTL_INDEX;


/* Defines. */
#define ENDPOINTDRV_MAJOR            209 /* arbitrary unused value */

#define ENDPOINTIOCTL_ENDPT_INIT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_INIT_INDEX, ENDPOINTDRV_INIT_PARAM)

#define ENDPOINTIOCTL_ENDPT_DEINIT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DEINIT_INDEX, ENDPOINTDRV_INIT_PARAM)

#define ENDPOINTIOCTL_ENDPT_CREATE \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_CREATE_INDEX, ENDPOINTDRV_CREATE_PARM)

#define ENDPOINTIOCTL_ENDPT_DESTROY \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DESTROY_INDEX, ENDPOINTDRV_DESTROY_PARM)

#define ENDPOINTIOCTL_ENDPT_CAPABILITIES \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_CAPABILITIES_INDEX, ENDPOINTDRV_CAP_PARM)

#define ENDPOINTIOCTL_ENDPT_SIGNAL \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_SIGNAL_INDEX, ENDPOINTDRV_SIGNAL_PARM)

#define ENDPOINTIOCTL_ENDPT_CREATE_CONNECTION \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_CREATE_CONNECTION_INDEX, ENDPOINTDRV_CONNECTION_PARM)

#define ENDPOINTIOCTL_ENDPT_MODIFY_CONNECTION \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_MODIFY_CONNECTION_INDEX, ENDPOINTDRV_CONNECTION_PARM)

#define ENDPOINTIOCTL_ENDPT_DELETE_CONNECTION \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DELETE_CONNECTION_INDEX, ENDPOINTDRV_DELCONNECTION_PARM)

#define ENDPOINTIOCTL_ENDPT_MUTE_CONNECTION \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_MUTE_CONNECTION_INDEX, ENDPOINTDRV_MUTECONNECTION_PARM)

#define ENDPOINTIOCTL_ENDPT_LINK_INTERNAL \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_LINK_INTERNAL_INDEX, ENDPOINTDRV_LINKINTERNAL_PARM)

#define ENDPOINTIOCTL_ENDPT_PACKET \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_PACKET_INDEX, ENDPOINTDRV_PACKET_PARM)

#define ENDPOINTIOCTL_ENDPT_GET_PACKET \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_GET_PACKET_INDEX, ENDPOINTDRV_PACKET_PARM)

#define ENDPOINTIOCTL_ENDPT_GET_EVENT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_GET_EVENT_INDEX, ENDPOINTDRV_EVENT_PARM)

#define ENDPOINTIOCTL_ENDPT_GET_CODECMAP \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_GET_CODECMAP_INDEX, ENDPOINTDRV_CODECMAP_PARM)

#define ENDPOINTIOCTL_ENDPT_VOICESTAT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_VOICESTAT_INDEX, ENDPOINTDRV_VOICESTAT_PARM)

#define ENDPOINTIOCTL_ISINITIALIZED \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_ISINITIALIZED_INDEX, ENDPOINTDRV_ISINITIALIZED_PARM)

#define ENDPOINTIOCTL_ENDPT_CONSOLE_CMD \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_CONSOLE_CMD_INDEX, ENDPOINTDRV_CONSOLE_CMD_PARM)

#define ENDPOINTIOCTL_TEST \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_TEST_INDEX, ENDPOINTDRV_TESTPARM)

#define ENDPOINTIOCTL_ENDPOINTCOUNT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_ENDPOINTCOUNT_INDEX, ENDPOINTDRV_ENDPOINTCOUNT_PARM)

#define ENDPOINTIOCTL_FXSENDPOINTCOUNT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_FXSENDPOINTCOUNT_INDEX, ENDPOINTDRV_ENDPOINTCOUNT_PARM)

#define ENDPOINTIOCTL_FXOENDPOINTCOUNT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_FXOENDPOINTCOUNT_INDEX, ENDPOINTDRV_ENDPOINTCOUNT_PARM)

#define ENDPOINTIOCTL_DECTENDPOINTCOUNT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DECTENDPOINTCOUNT_INDEX, ENDPOINTDRV_ENDPOINTCOUNT_PARM)

#ifdef PSTN_LIFE_LINE_SUPPORT
#define ENDPOINTIOCTL_ISPSTNLIFELINESUPPORTED \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_ISPSTNLIFELINESUPPORTED_INDEX, ENDPOINTDRV_ISSUPPORTED_PARM)
#endif

#ifdef NTR_SUPPORT
#define ENDPTIO_NTR_CMD \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_NTR_CMD_INDEX, ENDPOINTDRV_NTR_PARM)
#endif /* NTR_SUPPORT */

#define ENDPOINTIOCTL_HOOKSTAT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_HOOKSTAT_INDEX, ENDPOINTDRV_HOOKSTAT_CMD_PARM)

#define ENDPOINTIOCTL_SEND_CAS_EVT \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_SEND_CAS_EVT_INDEX, ENDPOINTDRV_SENDCASEVT_CMD_PARM)

#define ENDPOINTIOCTL_SET_RELAY \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_SET_RELAY_INDEX, ENDPOINTDRV_RELAY_CMD_PARM)

#define ENDPOINTIOCTL_PRINTF \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_PRINTF_INDEX, ENDPOINTDRV_PRINTF_PARM)

#define ENDPOINTIOCTL_PROV_SET \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_PROV_SET_INDEX, ENDPOINTDRV_PROV_PARM)

#define ENDPOINTIOCTL_PROV_GET \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_PROV_GET_INDEX, ENDPOINTDRV_PROV_PARM)

#define ENDPOINTIOCTL_PROBE_SET \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_PROBE_SET_INDEX, ENDPOINTDRV_PROBE_PARM)

#define ENDPOINTIOCTL_PROBE_GET \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_PROBE_GET_INDEX, ENDPOINTDRV_PROBE_PARM)

#define ENDPOINTIOCTL_GET_RTP_STATS \
    _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_GET_RTP_STATS_INDEX, ENDPOINTDRV_RTP_STATS_PARM)

#if defined(BRCM_IDECT_CALLMGR) || defined(BRCM_EDECT_CALLMGR)
#   define ENDPOINTIOCTL_DECT_INFO \
       _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DECT_INFO_INDEX, ENDPOINTDRV_DECT_INFO_CMD_PARM)

#   define ENDPOINTIOCTL_DECT_HS_INFO \
       _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DECT_HS_INFO_INDEX, ENDPOINTDRV_DECT_HS_INFO_CMD_PARM)
       
#   define ENDPOINTIOCTL_DECT_GET_NVS \
       _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DECT_GET_NVS_INDEX, ENDPOINTDRV_DECT_NVS_CMD_PARM)       

#   define ENDPOINTIOCTL_DECT_SET_NVS \
       _IOWR(ENDPOINTDRV_MAJOR, ENDPTIO_DECT_SET_NVS_INDEX, ENDPOINTDRV_DECT_NVS_CMD_PARM)       
       
#endif /* BRCM_IDECT_CALLMGR || BRCM_EDECT_CALLMGR */


#define MAX_ENDPOINTDRV_IOCTL_COMMANDS   ENDPTIO_MAX_INDEX


typedef struct
{
   UINT32      size;    /* Size of the structure (including the size field) */
   VRG_ENDPT_INIT_CFG *endptInitCfg;
   EPSTATUS    epStatus;
} ENDPOINTDRV_INIT_PARAM, *PENDPOINTDRV_INIT_PARAM;

typedef struct
{
   UINT32   size;       /* Size of the structure (including the size field) */
   UINT32   physId;
   UINT32   lineId;
   VRG_ENDPT_STATE* endptState;
   EPSTATUS epStatus;
} ENDPOINTDRV_CREATE_PARM, *PENDPOINTDRV_CREATE_PARM;

typedef struct
{
   UINT32   size;       /* Size of the structure (including the size field) */
   VRG_ENDPT_STATE* endptState;
   EPSTATUS epStatus;
} ENDPOINTDRV_DESTROY_PARM, *PENDPOINTDRV_DESTROY_PARM;

typedef struct
{
   UINT32   size;       /* Size of the structure (including the size field) */
   EPZCAP*  capabilities;
   ENDPT_STATE* state;
   EPSTATUS epStatus;
} ENDPOINTDRV_CAP_PARM, *PENDPOINTDRV_CAP_PARM;

typedef struct
{
   UINT32      size;    /* Size of the structure (including the size field) */
   ENDPT_STATE* state;
   UINT32      cnxId;
   EPSIG       signal;
   UINT32      value;      // Reserve an array, can be a pointer
   EPSTATUS    epStatus;
   int         duration;
   int         period;
   int         repetition;
} ENDPOINTDRV_SIGNAL_PARM, *PENDPOINTDRV_SIGNAL_PARM;

typedef struct
{
   UINT32      size;    /* Size of the structure (including the size field) */
   ENDPT_STATE* state;
   int         cnxId;
   EPZCNXPARAM*   cnxParam;
   EPSTATUS    epStatus;
} ENDPOINTDRV_CONNECTION_PARM, *PENDPOINTDRV_CONNECTION_PARM;

typedef struct
{
   UINT32         size; /* Size of the structure (including the size field) */
   ENDPT_STATE*   state;
   int            cnxId;
   EPSTATUS       epStatus;
} ENDPOINTDRV_DELCONNECTION_PARM, *PENDPOINTDRV_DELCONNECTION_PARM;

typedef struct
{
   UINT32         size; /* Size of the structure (including the size field) */
   ENDPT_STATE*   state;
   int            cnxId;
   VRG_BOOL       mute;
   EPSTATUS       epStatus;
} ENDPOINTDRV_MUTECONNECTION_PARM, *PENDPOINTDRV_MUTECONNECTION_PARM;

typedef struct
{
   UINT32         size; /* Size of the structure (including the size field) */
   ENDPT_STATE*   state1;
   ENDPT_STATE*   state2;
   VRG_BOOL       link;
   EPSTATUS       epStatus;
} ENDPOINTDRV_LINKINTERNAL_PARM, *PENDPOINTDRV_LINKINTERNAL_PARM;

typedef struct
{
   UINT32   size;       /* Size of the structure (including the size field) */
   ENDPT_STATE*   state;
   int      cnxId;
   EPPACKET*      epPacket;
   int      length;
   UINT32   bufDesc;
   EPSTATUS epStatus;
} ENDPOINTDRV_PACKET_PARM, *PENDPOINTDRV_PACKET_PARM;

typedef struct
{
   UINT32   size;       /* Size of the structure (including the size field) */
   int      lineId;
   int      cnxId;
   int      length;
   EPEVT    event;
   UINT8    eventData[MAX_EVENTDATA_SIZE];
   UINT16   intData;
} ENDPOINTDRV_EVENT_PARM, *PENDPOINTDRV_EVENT_PARM;

typedef struct
{
   UINT32         size; /* Size of the structure (including the size field) */
   int            isInitialized;
} ENDPOINTDRV_ISINITIALIZED_PARM, *PENDPOINTDRV_ISINITIALIZED_PARM;

typedef struct
{
   UINT32         size; /* Size of the structure (including the size field) */
   UINT32         testParm1;
   UINT32         testParm2;
   EPZCNXPARAM*   testParm3;
   EPSTATUS       epStatus;
} ENDPOINTDRV_TESTPARM, *PENDPOINTDRV_TESTPARM;

typedef struct ENDPOINTDRV_PACKET
{
   UINT32   size;       /* Size of the structure (including the size field) */
   int      cnxId;
   int      length;
   EPMEDIATYPE mediaType;
   UINT8    data[1024];
} ENDPOINTDRV_PACKET;

typedef struct ENDPOINTDRV_CONSOLE_CMD_PARM
{
   UINT32         size;       /* Size of the structure (including the size field) */
   ENDPT_STATE*   state;
   int            cmd;
   int            lineId;
   EPCMD_PARMS*   consoleCmdParams;
   EPSTATUS       epStatus;
} ENDPOINTDRV_CONSOLE_CMD_PARM, *PENDPOINTDRV_CONSOLE_CMD_PARM;


typedef struct
{
   UINT32         size; /* Size of the structure (including the size field) */
   int            endpointNum;
} ENDPOINTDRV_ENDPOINTCOUNT_PARM, *PENDPOINTDRV_ENDPOINTCOUNT_PARM;

#ifdef PSTN_LIFE_LINE_SUPPORT
typedef struct
{
   UINT32         size; /* Size of the structure (including the size field) */
   VRG_BOOL       isSupported;
} ENDPOINTDRV_ISSUPPORTED_PARM, *PENDPOINTDRV_ISSUPPORTED_PARM;
#endif

#ifdef NTR_SUPPORT
typedef struct
{
   UINT32      size;   /* Size of the structure (including the size field) */
   UINT8       bNtrEnbl;       /* enable / disable feedback state in pcm block */
   INT32       pcmStepsAdjust; /* Number of fine-grain PCM register steps to make (dependent on PCM chip) */
   UINT32      localCount;     /* MIPS counter register reading */
   UINT32      ntrCount;       /* NTR counter register reading */
   UINT32      ndivInt;        /* NDIV_INT register reading */
   UINT32      ndivFrac;       /* NDIV_FRAC register reading */
   EPSTATUS    epStatus;       /* return value */
   UINT8       ntrAction;      /* enum of possible commands (get?/set?/debug_print?)*/
} ENDPOINTDRV_NTR_PARM, *PENDPOINTDRV_NTR_PARM;
#endif /* NTR_SUPPORT */

typedef struct ENDPOINTDRV_HOOKSTAT_CMD_PARM
{
   UINT32         size;       /* Size of the structure (including the size field) */
   int            lineId;
   EPCASSTATE     hookstat;
   EPSTATUS       epStatus;
} ENDPOINTDRV_HOOKSTAT_CMD_PARM, *PENDPOINTDRV_HOOKSTAT_CMD_PARM;

typedef struct ENDPOINTDRV_SENDCASEVT_CMD_PARM
{
   UINT32                 size;       /* Size of the structure (including the size field) */
   int                    lineId;
   CAS_CTL_EVENT_TYPE     casCtlEvtType;
   CAS_CTL_EVENT          casCtlEvt;
   EPSTATUS               epStatus;
} ENDPOINTDRV_SENDCASEVT_CMD_PARM, *PENDPOINTDRV_SENDCASEVT_CMD_PARM;

typedef struct ENDPOINTDRV_RELAY_CMD_PARM
{
   UINT32         size;       /* Size of the structure (including the size field) */
   int            lineId;
   BOOL           cmd;
   EPSTATUS       epStatus;
} ENDPOINTDRV_RELAY_CMD_PARM, *PENDPOINTDRV_RELAY_CMD_PARM;

typedef struct ENDPOINTDRV_PRINTF_PARM
{
   UINT32         size;
   char           str[MAX_PRINTF_SIZE];
} ENDPOINTDRV_PRINTF_PARM, *PENDPOINTDRV_PRINTF_PARM;

typedef struct ENDPOINTDRV_PROV_PARM
{
   UINT32         size;       /* Size of this structure (including the size field) */
   int            line;
   EPPROV         provItemId;
   void*          provItemValue;
   int            provItemLength;
   EPSTATUS       epStatus;
} ENDPOINTDRV_PROV_PARM, *PENDPOINTDRV_PROV_PARM;

typedef struct ENDPOINTDRV_PROBE_PARM
{
   UINT32         size;       /* Size of this structure (including the size field) */
   int            deviceId;
   int            chan;
   int            reg;
   int            regSize;
   void           *probeValue;
   int            probeValueLength;
   int            indirectness;
   EPSTATUS       epStatus;
} ENDPOINTDRV_PROBE_PARM, *PENDPOINTDRV_PROBE_PARM;

typedef struct
{
   UINT32       size;    /* Size of the structure (including the size field) */
   ENDPT_STATE* state;
   int          cnxId;
   EPZCNXSTATS* stats;
   EPSTATUS     epStatus;
} ENDPOINTDRV_RTP_STATS_PARM, *PENDPOINTDRV_RTP_STATS_PARM;

#if defined(BRCM_IDECT_CALLMGR) || defined(BRCM_EDECT_CALLMGR)
typedef struct ENDPOINTDRV_DECT_INFO_CMD_PARM
{
   UINT32           size;

   int              dectStatus;
   int              regWnd;
   char             accessCode[ VRG_DECT__ACCESS_CODE + 1 ];
   unsigned int     version;
   char             linkDate[ VRG_DECT__FW_LINK_DATE + 1 ];
   unsigned char    type;
   char             id[ VRG_DECT__BASE_ID + 1 ];
   unsigned int     manic;
   unsigned int     modic;
   unsigned int     maxHset;
   unsigned int     curHset;

   EPSTATUS         epStatus;

} ENDPOINTDRV_DECT_INFO_CMD_PARM, *PENDPOINTDRV_DECT_INFO_CMD_PARM;


typedef struct ENDPOINTDRV_DECT_HS_INFO_CMD_PARM
{
   UINT32           size;

   int              handsetId;
   int              status;
   unsigned int     timestamp;
   unsigned char    ipui[ VRG_DECT__IPUI ];
   unsigned int     manic;
   unsigned int     modic;

   EPSTATUS         epStatus;

} ENDPOINTDRV_DECT_HS_INFO_CMD_PARM, *PENDPOINTDRV_DECT_HS_INFO_CMD_PARM;


typedef struct ENDPOINTDRV_DECT_NVS_CMD_PARM
{
   UINT32           size;

   unsigned short   offset;
   unsigned short   nvsDataLength;
   unsigned char*   nvsDataPtr;

   EPSTATUS         epStatus;

} ENDPOINTDRV_DECT_NVS_CMD_PARM, *PENDPOINTDRV_DECT_NVS_CMD_PARM;

#endif /* BRCM_IDECT_CALLMGR || BRCM_EDECT_CALLMGR */



typedef void (*rtpDropPacketResetCallback)(void);

typedef struct
{
   endptEventCallback         pEventCallBack;
   endptPacketCallback        pPacketCallBack;
   rtpDropPacketResetCallback pRtpDropPacketResetCallBack;
   int                        fileHandle;
   int                        logFileHandle;

} ENDPTUSER_CTRLBLOCK;

EPSTATUS vrgEndptSignal
(
   ENDPT_STATE   *endptState,
   int            cnxId,
   EPSIG          signal,
   unsigned int   value,
   int            duration,
   int            period,
   int            repetition
 );



enum rtp_type {
	BRCM_UNKNOWN,
	BRCM_AUDIO,
	BRCM_DTMFBE,
	BRCM_DTMF,
	BRCM_RTCP,
};


/* function declaration */

EPSTATUS vrgEndptDriverOpen(void);
EPSTATUS vrgEndptDriverClose(void);
static void brcm_generate_rtp_packet(struct brcm_pvt *p, UINT8 *packet_buf, int type);
static int brcm_create_connection(struct brcm_pvt *p);
static int brcm_close_connection(struct brcm_pvt *p);
int endpt_init(void);
int endpt_deinit(void);
void event_loop(void);
static int restart_monitor(void);
static struct ast_channel *brcm_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);
static int brcm_call(struct ast_channel *ast, char *dest, int timeout);
static int brcm_hangup(struct ast_channel *ast);
static int brcm_answer(struct ast_channel *ast);
static struct ast_frame *brcm_read(struct ast_channel *ast);
static int brcm_write(struct ast_channel *ast, struct ast_frame *frame);
static int brcm_send_text(struct ast_channel *ast, const char *text);
static int brcm_get_endpoints_count(void);
static void brcm_create_fxs_endpoints(void);
int brcm_signal_ringing(struct brcm_pvt *p);
int brcm_stop_ringing(struct brcm_pvt *p);


#endif // _ENDPOINTDRV_H_
