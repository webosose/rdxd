// Copyright (c) 2008-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @file util.c
 *
 * @brief
 * This file contains generic utility functions.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>


#include "util.h"

//#######################################################################

#define RDXD_CRASH_PREFIX "RDXD"
#define RDXD_LIBRDX_TRIGGER_PATH WEBOS_INSTALL_LOGDIR "/reports/librdx"

//#######################################################################

/***********************************************************************
 * ParseBool
 ***********************************************************************/
bool ParseBool(const char *valStr, bool *bP)
{
	g_assert(bP);
	g_return_val_if_fail(valStr != NULL, false);
	g_return_val_if_fail(bP != NULL, false);

	if (strcasecmp(valStr, "false") == 0)
	{
		*bP = false;
		return true;
	}

	if (strcasecmp(valStr, "true") == 0)
	{
		*bP = true;
		return true;
	}

	return false;
}

/***********************************************************************
 * ParseInt
 ***********************************************************************/
bool ParseInt(const char *valStr, int *nP)
{
	long int    n;
	char       *endptr;

	endptr = NULL;
	errno = 0;
	n = strtol(valStr, &endptr, 0);

	if ((endptr == valStr) || (*endptr != 0) || (errno != 0))
	{
		return false;
	}

	//TODO: range checking
	*nP = (int) n;
	return true;
}

gchar *
read_string_conf(GKeyFile *keyfile, gchar *cat, gchar *key, bool mandatory)
{
	gchar *ret = 0;
	GError *gerror = NULL;
	ret = g_key_file_get_string(keyfile, cat, key, &gerror);

	if (!gerror)
	{
		LOG_RDXD_DEBUG("read prop %s = %s", key, ret);
	}
	else if (mandatory)
	{
		LOG_RDXD_WARNING(MSGID_G_KEY_FILE_STR_ERR, 1, PMLOGKS(ERRTEXT, gerror->message),
		                 "");
	}

	if (gerror != NULL)
	{
		g_error_free(gerror);
	}

	return ret;
}

gchar *get_file_modified_time(const char *path)
{
	struct stat sb;

	if (stat(path, &sb) == -1)
	{
		LOG_RDXD_WARNING(MSGID_STAT_ERR, 2, PMLOGKS(PATH, path), PMLOGKS(ERRTEXT,
		                 strerror(errno)), "");
		return NULL;
	}

	GTimeVal gts;
	gts.tv_sec = sb.st_mtime;
	gts.tv_usec = 0;

	return g_time_val_to_iso8601(&gts);
}


/**
 * @brief compress_file
 *
 * Compress a file at the given path, new file name will
 * be old filename with .gz appended
 *
 * @param path
 *
 * @return
 */
bool compress_file(const char *path)
{
	LOG_RDXD_DEBUG("%s: compressing %s", __func__, path);
	gchar *args[] = {"gzip", (gchar *) path, NULL};
	bool ret = false;
	int status = 0;
	gchar *std_err = NULL;
	GError *error = NULL;
	LOG_RDXD_DEBUG("%s running %s %s", __func__, args[0], args[1]);
	ret = g_spawn_sync(NULL, args, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL,
	                   &std_err, &status, &error);
	SHOW_STDERR(std_err);
	if (NULL != error)
	{
		LOG_RDXD_WARNING(MSGID_FILE_COMPRESS_ERR, 2,
		                 PMLOGKS(PATH, path),
		                 PMLOGKS(ERRTEXT, error->message),
		                 "Failed to compress file %s: %s",
		                 path, error->message);
		g_error_free(error);
	}
	return ret && (status == 0);
}

bool mark_as_seen(gchar *crash_path, bool is_success, GError **error)
{
	int ret = true;
	gchar *dst_path = NULL;
	gchar *dst_filename = NULL;
	gchar *trigger_file = NULL;

	if (!crash_path)
	{
		LOG_RDXD_WARNING(MSGID_MARK_AS_SEEN_ERR, 1, PMLOGKS(REASON, "No crash trigger file in request"),
		                 "");
		return false;
	}

	trigger_file = g_path_get_basename(crash_path);

	if (is_success) //report was created
	{
		dst_filename = g_strdup_printf("%s_%s", RDXD_CRASH_PREFIX, trigger_file);
	}
	else //report could not be created
	{
		if ((error) && (*error))
		{
			dst_filename = g_strdup_printf("%sErr%d_%s", RDXD_CRASH_PREFIX, (*error)->code,
			                               trigger_file);
		}
		else
		{
			dst_filename = g_strdup_printf("%sErrUnknown_%s", RDXD_CRASH_PREFIX,
			                               trigger_file);
		}
	}
	dst_path = g_build_filename(RDXD_LIBRDX_TRIGGER_PATH, dst_filename, NULL);

	LOG_RDXD_DEBUG("Trying to rename %s to %s", crash_path, dst_path);

	// rename file to make sure it is no longer marked as orphan
	if (g_rename(crash_path, dst_path) == -1)
	{
		LOG_RDXD_WARNING(MSGID_FILE_RENAME_ERR, 1, PMLOGKS(ERRTEXT, g_strerror(errno)),
		                 "Failed to rename file %s to %s", crash_path, dst_path);
		ret = false;
	}
	else if (!compress_file(dst_path))
	{
		ret = false;
	}

	g_free(trigger_file);
	g_free(dst_filename);
	g_free(dst_path);

	return ret;
}

bool run_script(const char *cmd, gchar **output)
{
	gchar *stderror = NULL;
	GError *error = NULL;
	bool res = g_spawn_command_line_sync(cmd,
	                                     output,
	                                     &stderror,
	                                     NULL /* status */,
	                                     &error);
	SHOW_STDERR(stderror);
	g_free(stderror);

	if (error != NULL)
	{
		LOG_RDXD_WARNING(MSGID_PROC_SPAWN_TRACE_ERR, 0, "%s", error->message);
		g_error_free(error);
	}

	return res;
}

void free_report_spec(ReportSpec_t *spec)
{
	if (!spec)
		return;

	g_free(spec->reportCause);
	g_free(spec->reportComponent);
	g_free(spec->reportDetail);
	g_free(spec->reportPath);
	g_free(spec->reportTime);
	g_free(spec->reportFileName);
	g_free(spec->reportFormat);
	g_free(spec->reportSysInfoSnapshot);
	g_free(spec);
}
