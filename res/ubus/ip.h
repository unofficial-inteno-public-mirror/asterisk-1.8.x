/*
 * ip.h
 *
 *  SIP IP struct
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#ifndef IP_H_
#define IP_H_

#ifdef NI_MAXHOST
#undef NI_MAXHOST
#endif

#define NI_MAXHOST 65

typedef struct IP
{
	int family;
	char addr[NI_MAXHOST];
} IP;

#endif /* IP_H_ */
