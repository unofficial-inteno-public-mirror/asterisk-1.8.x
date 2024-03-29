/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
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

/*! \file
 * \brief Access Control of various sorts
 */

#ifndef _ASTERISK_ACL_H
#define _ASTERISK_ACL_H


#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#include "asterisk/network.h"
#include "asterisk/netsock2.h"
#include "asterisk/io.h"

#define AST_SENSE_DENY                  0
#define AST_SENSE_ALLOW                 1

/* Host based access control */

/*! \brief internal representation of acl entries
 * In principle user applications would have no need for this,
 * but there is sometimes a need to extract individual items,
 * e.g. to print them, and rather than defining iterators to
 * navigate the list, and an externally visible 'struct ast_ha_entry',
 * at least in the short term it is more convenient to make the whole
 * thing public and let users play with them.
 */
struct ast_ha {
	/* Host access rule */
	struct ast_sockaddr addr;
	struct ast_sockaddr netmask;
	int sense;
	struct ast_ha *next;
};

int ast_get_ips_or_srvs(struct ast_sockaddr **addr_list, const char *hostname, const char *service, unsigned int family);

/*!
 * \brief Free a list of HAs
 *
 * \details
 * Given the head of a list of HAs, it and all appended
 * HAs are freed
 *
 * \param ha The head of the list of HAs to free
 * \retval void
 */
void ast_free_ha(struct ast_ha *ha);

/*!
 * \brief Copy the contents of one HA to another
 *
 * \details
 * This copies the internals of the 'from' HA to the 'to'
 * HA. It is important that the 'to' HA has been allocated
 * prior to calling this function
 *
 * \param from Source HA to copy
 * \param to Destination HA to copy to
 * \retval void
 */
void ast_copy_ha(const struct ast_ha *from, struct ast_ha *to);

/*!
 * \brief Add a new rule to a list of HAs
 *
 * \details
 * This adds the new host access rule to the end of the list
 * whose head is specified by the path parameter. Rules are
 * evaluated in a way such that if multiple rules apply to
 * a single IP address/subnet mask, then the rule latest
 * in the list will be used.
 *
 * \param sense Either "permit" or "deny" (Actually any 'p' word will result
 * in permission, and any other word will result in denial)
 * \param stuff The IP address and subnet mask, separated with a '/'. The subnet
 * mask can either be in dotted-decimal format or in CIDR notation (i.e. 0-32).
 * \param path The head of the HA list to which we wish to append our new rule. If
 * NULL is passed, then the new rule will become the head of the list
 * \param[out] error The integer error points to will be set non-zero if an error occurs
 * \return The head of the HA list
 */
struct ast_ha *ast_append_ha(const char *sense, const char *stuff, struct ast_ha *path, int *error);

/*!
 * \brief Apply a set of rules to a given IP address
 *
 * \details
 * The list of host access rules is traversed, beginning with the
 * input rule. If the IP address given matches a rule, the "sense"
 * of that rule is used as the return value. Note that if an IP
 * address matches multiple rules that the last one matched will be
 * the one whose sense will be returned.
 *
 * \param ha The head of the list of host access rules to follow
 * \param addr An ast_sockaddr whose address is considered when matching rules
 * \retval AST_SENSE_ALLOW The IP address passes our ACL
 * \retval AST_SENSE_DENY The IP address fails our ACL
 */
int ast_apply_ha(const struct ast_ha *ha, const struct ast_sockaddr *addr);

/*!
 * \brief Get the IP address given a hostname
 *
 * \details
 * Similar in nature to ast_gethostbyname, except that instead
 * of getting an entire hostent structure, you instead are given
 * only the IP address inserted into a ast_sockaddr structure.
 *
 * \param addr The IP address found.  The address family is used
 * as an input parameter to filter the returned addresses.  If
 * it is 0, both IPv4 and IPv6 addresses can be returned.
 * \param hostname The hostname to look up
 *
 * \retval 0 Success
 * \retval -1 Failure
 */
int ast_get_ip(struct ast_sockaddr *addr, const char *hostname);

/*!
 * \brief Get the IP address given a hostname and optional service
 *
 * \details
 * If the service parameter is non-NULL, then an SRV lookup will be made by
 * prepending the service to the hostname parameter, separated by a '.'
 * For example, if hostname is "example.com" and service is "_sip._udp" then
 * an SRV lookup will be done for "_sip._udp.example.com". If service is NULL,
 * then this function acts exactly like a call to ast_get_ip.
 *
 * \param addr The IP address found.  The address family is used
 * as an input parameter to filter the returned addresses.  If
 * it is 0, both IPv4 and IPv6 addresses can be returned.
 *
 * \param hostname The hostname to look up
 * \param service A specific service provided by the host. A NULL service results
 * in an A-record lookup instead of an SRV lookup
 * \retval 0 Success
 * \retval -1 Failure
 */
int ast_get_ip_or_srv(struct ast_sockaddr *addr, const char *hostname, const char *service);

/*!
 * \brief Get our local IP address when contacting a remote host
 *
 * \details
 * This function will attempt to connect(2) to them over UDP using a source
 * port of 5060. If the connect(2) call is successful, then we inspect the
 * sockaddr_in output parameter of connect(2) to determine the IP address
 * used to connect to them. This IP address is then copied into us.
 *
 * \param them The IP address to which we wish to attempt to connect
 * \param[out] us The source IP address used to connect to them
 * \retval -1 Failure
 * \retval 0 Success
 */
int ast_ouraddrfor(const struct ast_sockaddr *them, struct ast_sockaddr *us);

/*!
 * \brief Find an IP address associated with a specific interface
 *
 * \details
 * Given an interface such as "eth0" we find the primary IP address
 * associated with it using the SIOCGIFADDR ioctl. If the ioctl call
 * should fail, we populate address with 0s.
 *
 * \note
 * This function is not actually used anywhere
 *
 * \param iface The interface name whose IP address we wish to find
 * \param[out] address The interface's IP address is placed into this param
 * \retval -1 Failure. address is filled with 0s
 * \retval 0 Success
 */
int ast_lookup_iface(char *iface, struct ast_sockaddr *address);

/*!
 * \brief Duplicate the contents of a list of host access rules
 *
 * \details
 * A deep copy of all ast_has in the list is made. The returned
 * value is allocated on the heap and must be freed independently
 * of the input parameter when finished.
 *
 * \note
 * This function is not actually used anywhere.
 *
 * \param original The ast_ha to copy
 * \retval The head of the list of duplicated ast_has
 */
struct ast_ha *ast_duplicate_ha_list(struct ast_ha *original);

/*!
 * \brief Find our IP address
 *
 * \details
 * This function goes through many iterations in an attempt to find
 * our IP address. If any step along the way should fail, we move to the
 * next item in the list. Here are the steps taken:
 * - If bindaddr has a non-zero IP address, that is copied into ourip
 * - We use a combination of gethostname and ast_gethostbyname to find our
 *   IP address.
 * - We use ast_ouraddrfor with 198.41.0.4 as the destination IP address
 * - We try some platform-specific socket operations to find the IP address
 *
 * \param[out] ourip Our IP address is written here when it is found
 * \param bindaddr A hint used for finding our IP. See the steps above for
 * more details
 * \param family Only addresses of the given family will be returned. Use 0
 * or AST_SOCKADDR_UNSPEC to get addresses of all families.
 * \retval 0 Success
 * \retval -1 Failure
 */
int ast_find_ourip(struct ast_sockaddr *ourip, const struct ast_sockaddr *bindaddr, int family);

/*!
 * \brief Convert a string to the appropriate COS value
 *
 * \param value The COS string to convert
 * \param[out] cos The integer representation of that COS value
 * \retval -1 Failure
 * \retval 0 Success
 */
int ast_str2cos(const char *value, unsigned int *cos);

/*!
 * \brief Convert a string to the appropriate TOS value
 *
 * \param value The TOS string to convert
 * \param[out] tos The integer representation of that TOS value
 * \retval -1 Failure
 * \retval 0 Success
 */
int ast_str2tos(const char *value, unsigned int *tos);

/*!
 * \brief Convert a TOS value into its string representation
 *
 * \param tos The TOS value to look up
 * \return The string equivalent of the TOS value
 */
const char *ast_tos2str(unsigned int tos);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _ASTERISK_ACL_H */
