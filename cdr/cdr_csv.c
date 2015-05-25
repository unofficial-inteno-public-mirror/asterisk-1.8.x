/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * Includes code and algorithms from the Zapata library.
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

/*!
 * \file
 * \brief Comma Separated Value CDR records.
 *
 * \author Mark Spencer <markster@digium.com>
 *
 * \arg See also \ref AstCDR
 * \ingroup cdr_drivers
 */

/*** MODULEINFO
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include "asterisk/paths.h"	/* use ast_config_AST_LOG_DIR */
#include "asterisk/config.h"
#include "asterisk/channel.h"
#include "asterisk/cdr.h"
#include "asterisk/module.h"
#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/cli.h"

#define CSV_LOG_DIR "/cdr-csv"
#define CSV_MASTER  "/Master.csv"

#define DATE_FORMAT "%Y-%m-%d %T"

static int usegmtime = 0;
static int accountlogs;
static int loguniqueid = 0;
static int loguserfield = 0;

/* Max number of rows to keep in CSV. 0 means unlimited */
static int maxrows = 0;

static int loaded = 0;
static const char config[] = "cdr.conf";

/* #define CSV_LOGUNIQUEID 1 */
/* #define CSV_LOGUSERFIELD 1 */

/*----------------------------------------------------
  The values are as follows:


  "accountcode", 	accountcode is the account name of detail records, Master.csv contains all records *
  			Detail records are configured on a channel basis, IAX and SIP are determined by user *
			DAHDI is determined by channel in dahdi.conf
  "source",
  "destination",
  "destination context",
  "callerid",
  "channel",
  "destination channel",	(if applicable)
  "last application",	Last application run on the channel
  "last app argument",	argument to the last channel
  "start time",
  "answer time",
  "end time",
  duration,   		Duration is the whole length that the entire call lasted. ie. call rx'd to hangup
  			"end time" minus "start time"
  billable seconds, 	the duration that a call was up after other end answered which will be <= to duration
  			"end time" minus "answer time"
  "disposition",    	ANSWERED, NO ANSWER, BUSY
  "amaflags",       	DOCUMENTATION, BILL, IGNORE etc, specified on a per channel basis like accountcode.
  "uniqueid",           unique call identifier
  "userfield"		user field set via SetCDRUserField
----------------------------------------------------------*/

static char *name = "csv";

AST_MUTEX_DEFINE_STATIC(mf_lock);
AST_MUTEX_DEFINE_STATIC(acf_lock);

static int remove_cdr(const char *uniqueid);
static int resize_log(int maxrows);

static int load_config(int reload)
{
	struct ast_config *cfg;
	struct ast_variable *var;
	const char *tmp;
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

	if (!(cfg = ast_config_load(config, config_flags)) || cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_WARNING, "unable to load config: %s\n", config);
		return 0;
	} else if (cfg == CONFIG_STATUS_FILEUNCHANGED)
		return 1;

	accountlogs = 1;
	usegmtime = 0;
	loguniqueid = 0;
	loguserfield = 0;

	if (!(var = ast_variable_browse(cfg, "csv"))) {
		ast_config_destroy(cfg);
		return 0;
	}

	if ((tmp = ast_variable_retrieve(cfg, "csv", "usegmtime"))) {
		usegmtime = ast_true(tmp);
		if (usegmtime)
			ast_debug(1, "logging time in GMT\n");
	}

	/* Turn on/off separate files per accountcode. Default is on (as before) */
	if ((tmp = ast_variable_retrieve(cfg, "csv", "accountlogs"))) {
 		accountlogs = ast_true(tmp);
 		if (accountlogs) {
			ast_debug(1, "logging in separate files per accountcode\n");
 		}
 	}

	if ((tmp = ast_variable_retrieve(cfg, "csv", "loguniqueid"))) {
		loguniqueid = ast_true(tmp);
		if (loguniqueid)
			ast_debug(1, "logging CDR field UNIQUEID\n");
	}

	if ((tmp = ast_variable_retrieve(cfg, "csv", "loguserfield"))) {
		loguserfield = ast_true(tmp);
		if (loguserfield)
			ast_debug(1, "logging CDR user-defined field\n");
	}

	if ((tmp = ast_variable_retrieve(cfg, "csv", "maxrows"))) {
		int value = atoi(tmp);
		if (value <= 0) {
			maxrows = 0;
		}
		else {
			maxrows = value;
			ast_debug(1, "limiting max number rows to %d\n", maxrows);
		}
	}

	ast_config_destroy(cfg);
	return 1;
}

static int append_string(char *buf, const char *s, size_t bufsize)
{
	int pos = strlen(buf), spos = 0, error = -1;

	if (pos >= bufsize - 4)
		return -1;

	buf[pos++] = '\"';

	while(pos < bufsize - 3) {
		if (!s[spos]) {
			error = 0;
			break;
		}
		if (s[spos] == '\"')
			buf[pos++] = '\"';
		buf[pos++] = s[spos];
		spos++;
	}

	buf[pos++] = '\"';
	buf[pos++] = ',';
	buf[pos++] = '\0';

	return error;
}

static int append_int(char *buf, int s, size_t bufsize)
{
	char tmp[32];
	int pos = strlen(buf);

	snprintf(tmp, sizeof(tmp), "%d", s);

	if (pos + strlen(tmp) > bufsize - 3)
		return -1;

	strncat(buf, tmp, bufsize - strlen(buf) - 1);
	pos = strlen(buf);
	buf[pos++] = ',';
	buf[pos++] = '\0';

	return 0;
}

static int append_date(char *buf, struct timeval when, size_t bufsize)
{
	char tmp[80] = "";
	struct ast_tm tm;

	if (strlen(buf) > bufsize - 3)
		return -1;

	if (ast_tvzero(when)) {
		strncat(buf, ",", bufsize - strlen(buf) - 1);
		return 0;
	}

	ast_localtime(&when, &tm, usegmtime ? "GMT" : NULL);
	ast_strftime(tmp, sizeof(tmp), DATE_FORMAT, &tm);

	return append_string(buf, tmp, bufsize);
}

static int build_csv_record(char *buf, size_t bufsize, struct ast_cdr *cdr)
{

	buf[0] = '\0';
	/* Account code */
	append_string(buf, cdr->accountcode, bufsize);
	/* Source */
	append_string(buf, cdr->src, bufsize);
	/* Destination */
	append_string(buf, cdr->dst, bufsize);
	/* Destination context */
	append_string(buf, cdr->dcontext, bufsize);
	/* Caller*ID */
	append_string(buf, cdr->clid, bufsize);
	/* Channel */
	append_string(buf, cdr->channel, bufsize);
	/* Destination Channel */
	append_string(buf, cdr->dstchannel, bufsize);
	/* Last Application */
	append_string(buf, cdr->lastapp, bufsize);
	/* Last Data */
	append_string(buf, cdr->lastdata, bufsize);
	/* Start Time */
	append_date(buf, cdr->start, bufsize);
	/* Answer Time */
	append_date(buf, cdr->answer, bufsize);
	/* End Time */
	append_date(buf, cdr->end, bufsize);
	/* Duration */
	append_int(buf, cdr->duration, bufsize);
	/* Billable seconds */
	append_int(buf, cdr->billsec, bufsize);
	/* Disposition */
	append_string(buf, ast_cdr_disp2str(cdr->disposition), bufsize);
	/* AMA Flags */
	append_string(buf, ast_cdr_flags2str(cdr->amaflags), bufsize);
	/* Unique ID */
	if (loguniqueid)
		append_string(buf, cdr->uniqueid, bufsize);
	/* append the user field */
	if(loguserfield)
		append_string(buf, cdr->userfield,bufsize);
	/* If we hit the end of our buffer, log an error */
	if (strlen(buf) < bufsize - 5) {
		/* Trim off trailing comma */
		buf[strlen(buf) - 1] = '\0';
		strncat(buf, "\n", bufsize - strlen(buf) - 1);
		return 0;
	}
	return -1;
}

static int writefile(char *s, char *acc)
{
	char tmp[PATH_MAX];
	FILE *f;

	if (strchr(acc, '/') || (acc[0] == '.')) {
		ast_log(LOG_WARNING, "Account code '%s' insecure for writing file\n", acc);
		return -1;
	}

	snprintf(tmp, sizeof(tmp), "%s/%s/%s.csv", ast_config_AST_LOG_DIR,CSV_LOG_DIR, acc);

	ast_mutex_lock(&acf_lock);
	if (!(f = fopen(tmp, "a"))) {
		ast_mutex_unlock(&acf_lock);
		ast_log(LOG_ERROR, "Unable to open file %s : %s\n", tmp, strerror(errno));
		return -1;
	}
	fputs(s, f);
	fflush(f);
	fclose(f);
	ast_mutex_unlock(&acf_lock);

	return 0;
}

static int resize_log(int maxrows)
{
	FILE *mf = NULL;
	FILE *tmpf = NULL;
	int rowcount = 0;
	char buf[1024];
	char csvmaster[PATH_MAX];
	char csvtmp[PATH_MAX];

	if (maxrows <= 0) {
		/* nothing to to */
		return 0;
	}

	snprintf(csvmaster, sizeof(csvmaster),"%s/%s/%s", ast_config_AST_LOG_DIR, CSV_LOG_DIR, CSV_MASTER);
	snprintf(csvtmp, sizeof(csvtmp),"%s/%s/%s.tmp", ast_config_AST_LOG_DIR, CSV_LOG_DIR, CSV_MASTER);

	if ((mf = fopen(csvmaster, "r")) == NULL) {
		ast_log(LOG_ERROR, "Unable to open master file %s : %s\n", csvmaster, strerror(errno));
		return -1;
	}

	/* count number of rows in CSV */
	while (fgets(buf, sizeof(buf), mf) != NULL) {
		rowcount++;
	}

	if (rowcount >= maxrows) {
		/* we need to make sure that the master file does not grow beyond
		   maxrows number of rows. This is done by creating a new CSV that
		   excludes the excess rows. This operation is probably quite I/O
		   intensive. */

		rewind(mf);

		ast_debug(1, "Removing %d row%s in order to resize log\n", rowcount - maxrows, (rowcount - maxrows == 1) ? "" : "s");
		if ((tmpf = fopen(csvtmp, "w"))) {
			while (rowcount > maxrows) {
				/* "throw away" rows */
				fgets(buf, sizeof(buf), mf);
				rowcount--;
			}

			/* copy rows to the temporary file */
			while (fgets(buf, sizeof(buf), mf) != NULL) {
				fputs(buf, tmpf);
			}

			fclose(mf);
			fclose(tmpf);

			/* replace master with temporary file */
			if (rename(csvtmp, csvmaster) == -1) {
				ast_log(LOG_ERROR, "Failed to resize master file %s : %s\n", csvmaster, strerror(errno));
				return -1;
			}
		} else {
			ast_log(LOG_ERROR, "Unable to open temporary file %s : %s\n",
					csvtmp, strerror(errno));
			fclose(mf);
			return -1;
		}
	}

	return 0;
}

static int remove_cdr(const char *uniqueid)
{
	FILE *mf = NULL;
	FILE *tmpf = NULL;
	char buf[1024];
	char token[32];
	char csvmaster[PATH_MAX];
	char csvtmp[PATH_MAX];

	snprintf(csvmaster, sizeof(csvmaster),"%s/%s/%s", ast_config_AST_LOG_DIR, CSV_LOG_DIR, CSV_MASTER);
	snprintf(csvtmp, sizeof(csvtmp),"%s/%s/%s.tmp", ast_config_AST_LOG_DIR, CSV_LOG_DIR, CSV_MASTER);

	if ((mf = fopen(csvmaster, "r")) == NULL) {
		ast_log(LOG_ERROR, "Unable to open master file %s : %s\n", csvmaster, strerror(errno));
		return -1;
	}

	if ((tmpf = fopen(csvtmp, "w")) == NULL) {
		ast_log(LOG_ERROR, "Unable to open temporary file %s : %s\n",
				csvtmp, strerror(errno));
		fclose(mf);
		return -1;
	}

	static char delim = ',';

	int foundcdr = 0;
	while (fgets(buf, sizeof(buf), mf) != NULL) {
		if (!foundcdr) {
			/* parse CSV row to check if row contains the CDR with the given
			 * unique id */

			/* reset CSV row parser state */
			char *start = buf;
			char *cursor = start;
			int inquotation = 0;
			int tokenindex = 0;

			while (cursor < (buf + sizeof(buf)) && *cursor) {
				if (inquotation) {
					if (cursor[0] == '"') {
						if (&cursor[1] < (buf + sizeof(buf)) && cursor[1] == '"') {
							/* quotation mark inside string */
							cursor += 2;
							continue;
						} else {
							/* exit quoted string */
							inquotation = 0;
						}
					}
				}
				else {
					if (cursor[0] == '"') {
						/* enter quoted string */
						inquotation = 1;
					}
					else if (cursor[0] == delim || cursor[0] == '\n') {
						/* found new token */
						memset(token, 0, sizeof(token));
						if (start[0] == '"') {
							/* strip quotations */
							strncpy(token, &start[1], (size_t)(cursor - start - 2));
						}
						else {
							strncpy(token, start, (size_t)(cursor - start));
						}

						if (tokenindex == 16) {
							/* compare uniqueids */
							if (strncmp(token, uniqueid, sizeof(token)) == 0) {
								foundcdr = 1;
							}
						}

						start = cursor + sizeof(delim);
						tokenindex++;
					}
				}

				cursor++;
			}

			if (foundcdr) {
				continue;
			}
		}

		/* copy the row to the temporary file */
		fputs(buf, tmpf);
	}

	fclose(mf);
	fclose(tmpf);

	/* replace master with temporary file */
	if (rename(csvtmp, csvmaster) == -1) {
		ast_log(LOG_ERROR, "Failed to update master file %s : %s\n", csvmaster, strerror(errno));
		return -1;
	}

	return 0;
}

static int csv_log(struct ast_cdr *cdr)
{
	FILE *mf = NULL;
	/* Make sure we have a big enough buf */
	char buf[1024];
	char csvmaster[PATH_MAX];
	snprintf(csvmaster, sizeof(csvmaster),"%s/%s/%s", ast_config_AST_LOG_DIR, CSV_LOG_DIR, CSV_MASTER);
#if 0
	printf("[CDR] %s ('%s' -> '%s') Dur: %ds Bill: %ds Disp: %s Flags: %s Account: [%s]\n", cdr->channel, cdr->src, cdr->dst, cdr->duration, cdr->billsec, ast_cdr_disp2str(cdr->disposition), ast_cdr_flags2str(cdr->amaflags), cdr->accountcode);
#endif
	if (build_csv_record(buf, sizeof(buf), cdr)) {
		ast_log(LOG_WARNING, "Unable to create CSV record in %d bytes.  CDR not recorded!\n", (int)sizeof(buf));
		return 0;
	}

	/* because of the absolutely unconditional need for the
	   highest reliability possible in writing billing records,
	   we open write and close the log file each time */
	ast_mutex_lock(&mf_lock);

	if (maxrows > 0) {
		if (resize_log(maxrows - 1) == -1) {
			/* not safe to continue */
			ast_mutex_unlock(&mf_lock);
			return -1;
		}
	}

	if ((mf = fopen(csvmaster, "a"))) {
		fputs(buf, mf);
		fflush(mf); /* be particularly anal here */
		fclose(mf);
		mf = NULL;
		ast_mutex_unlock(&mf_lock);
	} else {
		ast_mutex_unlock(&mf_lock);
		ast_log(LOG_ERROR, "Unable to re-open master file %s : %s\n", csvmaster, strerror(errno));
	}

	if (accountlogs && !ast_strlen_zero(cdr->accountcode)) {
		if (writefile(buf, cdr->accountcode))
			ast_log(LOG_WARNING, "Unable to write CSV record to account file '%s' : %s\n", cdr->accountcode, strerror(errno));
	}

	return 0;
}

static char *cdr_csv_remove_cdr(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *uniqueid = NULL;

	if (cmd == CLI_INIT) {
		e->command = "cdr_csv remove cdr";
		e->usage =
			"Usage: cdr_csv remove cdr <uniqueid>\n"
			"       Remove a CDR given a unique channel identifier for the call.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

    if (a->argc <= 3) {
        return CLI_SHOWUSAGE;
    }

    uniqueid = a->argv[3];
    remove_cdr(uniqueid);

	return CLI_SUCCESS;
}

/*! \brief CLI commands definition */
static struct ast_cli_entry cli_cdr_csv[] = {
	AST_CLI_DEFINE(cdr_csv_remove_cdr,  "Remove a call data record"),
};

static int unload_module(void)
{
	/* Unregister CLI commands */
	ast_cli_unregister_multiple(cli_cdr_csv, ARRAY_LEN(cli_cdr_csv));

	ast_cdr_unregister(name);
	loaded = 0;
	return 0;
}

static int load_module(void)
{
	int res;

	if(!load_config(0))
		return AST_MODULE_LOAD_DECLINE;

	if ((res = ast_cdr_register(name, ast_module_info->description, csv_log))) {
		ast_log(LOG_ERROR, "Unable to register CSV CDR handling\n");
	} else {
		loaded = 1;
	}

	/* Register all CLI functions this module */
	ast_cli_register_multiple(cli_cdr_csv, ARRAY_LEN(cli_cdr_csv));

	return res;
}

static int reload(void)
{
	if (load_config(1)) {
		loaded = 1;
	} else {
		loaded = 0;
		ast_log(LOG_WARNING, "No [csv] section in cdr.conf.  Unregistering backend.\n");
		ast_cdr_unregister(name);
	}

	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Comma Separated Values CDR Backend",
		.load = load_module,
		.unload = unload_module,
		.reload = reload,
		.load_pri = AST_MODPRI_CDR_DRIVER,
	       );
