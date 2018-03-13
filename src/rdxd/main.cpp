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
 * @file main.c
 *
 * @brief
 * This file contains the Remote Diagnostics daemon process implementation.
 *
 * The daemon watches for any critical events as indicated by core/mini-core
 * dump files appearing.  It also listens for explicit events as
 * indicated from externally via IPC.
 *
 * When an event occurs, the event + device state is passed to
 * upload services configured in /etc/rdxd.d.
 *
 *  Device filesystem overview:
 *
 *  @WEBOS_INSTALL_SYSCONFDIR@/
 *      rdxd.conf   # configuration file (read only)
 *      rdxd.d      # directory for upload services configuration files
 *
 *  @WEBOS_INSTALL_SBINDIR@/
 *      rdxd    # this daemon process
 *
 *  @WEBOS_INSTALL_DATADIR@/rdxd/
 *      parse_*.sh  # scripts to parse specific crash files
 *      make_*.sh  # scripts to produce logs containing context information to the report
 *
 *  /tmp/rdxd/<type>               # staging area, used for preparing files
 *      Process.PID                # before pass to upload services
 *      messages.log
 *      sysinfo.txt
 *      etc..
 *
 */

//->Start of API documentation comment block
/**
@page com_webos_rdxd com.webos.rdxd

@brief RDX Daemon

Each call has a standard return in the case of a failure, as follows:

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | False to inidicate an error
errorCode | Yes | Integer | Error code
errorText | Yes | String | Error description

@{
@}
*/
//->End of API documentation comment block

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>

#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include <pbnjson.hpp>

#include "contextlogs.h"
#include "log.h"
#include "logging.h"
#include "util.h"
#include "watch.h"
#include "config.h"

#define MAX_IDX_LENGTH 32

/***********************************************************************
 * Get/Set for AutoUpload preference
 ***********************************************************************/

static bool get_Upload_Switch_LS(LSHandle *pHandle, LSMessage *pMessage, void *pUserData);
static bool set_Upload_Switch_LS(LSHandle *pHandle, LSMessage *pMessage, void *pUserData);

#define TMP_CRASH_REPORT_DIR "/tmp/rdxd/crash"
#define TMP_ANALYTICS_REPORT_DIR "/tmp/rdxd/analytics"
#define TMP_OVERVIEW_REPORT_DIR "/tmp/rdxd/overview"

/***********************************************************************
 * internal error codes
 * See GLib documentation for how to use GError
 ***********************************************************************/

#define RDX_ERROR rdx_error_quark ()

GQuark
rdx_error_quark(void)
{
	return g_quark_from_static_string("rdx-main");
}

enum
{
	RDX_ERR_NONE            = 0,
	RDX_ERR_LUNA_PREFS,
	RDX_ERR_SERVICE,
	RDX_ERR_CTXLOG
};

/***********************************************************************
 * constants
 ***********************************************************************/

#define DEFAULT_CONFIG_PATH WEBOS_INSTALL_SYSCONFDIR"/rdxd.conf"
#define DEFAULT_CONFIG_DIR  WEBOS_INSTALL_SYSCONFDIR"/rdxd.d"

/***********************************************************************
 * settings
 ***********************************************************************/

static gboolean sAreVerbose = FALSE;
static bool sDoUploadAnalyticsLog = true;
static bool sDoUploadCrashLog = true;

static bool autoUpload = false;

static LSHandle  *sServiceHandle = NULL;
static GMainLoop *sMainLoop = NULL;

/**
 * @brief check_devmode
 */
static bool
check_devmode()
{
	static const char * devmode_file_path = WEBOS_INSTALL_SYSMGR_LOCALSTATEDIR"/preferences/devmode_enabled";
	return (g_file_test(devmode_file_path, G_FILE_TEST_EXISTS));
}

/**
 * @brief ensure_working_dirs_exist
 */
static void
ensure_working_dirs_exist(void)
{
	//make sure all needed temporary directories exist
	const char *paths[] = {TMP_CRASH_REPORT_DIR, TMP_ANALYTICS_REPORT_DIR, TMP_OVERVIEW_REPORT_DIR, NULL};
	for (int i = 0; paths[i] != NULL; i++)
	{
		if (g_mkdir_with_parents(paths[i], 0700) != 0)
		{
			LOG_RDXD_WARNING(MSGID_MK_TMP_FOLDER_ERR, 2, PMLOGKS(DIR_PATH, paths[i]),
			                 PMLOGKS(ERRTEXT, strerror(errno)), "");
		}
	}
}

/**
 * @brief rotate_analytics
 *
 * Trigger log daemon to perform log rotation
 *
 */
static void
rotate_analytics()
{
	LSError lserror;
	LSErrorInit(&lserror);

	if (!LSCallOneReply(sServiceHandle,
	                    "luna://com.webos.pmlogd/forcerotate",
	                    "{}", NULL, NULL, NULL, &lserror))
	{
		LSREPORT(lserror);
	}

	LSErrorFree(&lserror);
}

/**
 * @brief make_tmpfile
 *
 * Creates unique empty file in destination directory and returns its name
 *
 * @param dst_dir destination directory
 * @param base_name   file name prefix
 * @return unique file name of created file, NULL on failure
 */
static gchar *
make_tmpfile(const gchar *dst_dir, const gchar *name_prefix)
{
	if (NULL == dst_dir)
	{
		return NULL;
	}

	gchar *tmp_file_name = g_strdup_printf("%s/%s.XXXXXX", dst_dir, name_prefix);
	gint tmp_file = -1;
	if (-1 != (tmp_file= g_mkstemp(tmp_file_name)))
	{
		close(tmp_file);
		return tmp_file_name;
	}
	else
	{
		LOG_RDXD_WARNING(MSGID_MK_TMP_FILE_ERR, 3,
		                 PMLOGKS(DIR_PATH, dst_dir),
		                 PMLOGKS(ERRTEXT, strerror(errno)),
		                 PMLOGKFV(ERRCODE, "%d", errno),
		                 "Failed to make unique file in %s: %s", dst_dir, strerror(errno));
		g_free(tmp_file_name);
		return NULL;
	}
}

/**
 * @brief copy_file
 *
 * Copies file
 *
 * @param src_path  source file path
 * @param dst_path  destination file path
 * @param error     GError pointer
 * @return true on success, false otherwise
 */
static bool
copy_file(const char *src_path, const char *dst_path)
{
	bool ret = false;
	void *src_buf = NULL, *dst_buf = NULL;
	int src_file = -1, dst_file = -1;
	struct stat sb;
	int error = 0;

	if (-1 == (src_file = open(src_path, O_RDONLY)))
	{
		error = errno;
		goto end;
	}

	if (-1 == fstat(src_file, &sb))
	{
		error = errno;
		goto end;
	}

	if (sb.st_size == 0)
	{
		ret = true;
		goto end;
	}

	if (MAP_FAILED == (src_buf = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, src_file, 0)))
	{
		error = errno;
		goto end;
	}

	if (-1 == (dst_file = open(dst_path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)))
	{
		error = errno;
		goto end;
	}

	if (-1 == ftruncate(dst_file, sb.st_size))
	{
		error = errno;
		goto end;
	}

	if (MAP_FAILED == (dst_buf = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, dst_file, 0)))
	{
		error = errno;
		goto end;
	}

	memcpy(dst_buf, src_buf, sb.st_size);

	if (-1 == msync(dst_buf, sb.st_size, MS_SYNC))
	{
		error = errno;
		goto end;
	}

	ret = true;

end:

	if (error)
	{
		LOG_RDXD_WARNING(MSGID_COPY_ERR, 4,
		                 PMLOGKS(OLDPATH, src_path),
		                 PMLOGKS(NEWPATH, dst_path),
		                 PMLOGKS(ERRTEXT, strerror(error)),
		                 PMLOGKFV(ERRCODE, "%d", error),
		                 "Failed to copy file %s to %s: %s", src_path, dst_path, strerror(error));
	}

	if (src_buf) munmap(src_buf, sb.st_size);
	if (dst_buf) munmap(dst_buf, sb.st_size);
	if (src_file >= 0) close(src_file);
	if (dst_file >= 0) close(dst_file);

	return ret;
}

/**
 * @brief copy_to_temporary
 *
 * Creates unique file in destination directory and copies source into it
 *
 * @param src_path  source
 * @param dst_dir   destination directory
 * @param dst_path  destination file
 * @param error     error pointer
 *
 * @return  unique temporary file path of copied file if success, NULL otherwise
 */
static gchar *
copy_to_temporary(const gchar *src_path, const gchar *dst_dir, const char *name_prefix)
{
	gchar *dst_path = make_tmpfile(dst_dir, name_prefix);
	if (!dst_path)
	{
		return dst_path;
	}

	// copy source file into temporary unique file
	if (!copy_file(src_path, dst_path))
	{
		g_free(dst_path);
		dst_path = NULL;
	}

	return dst_path;
}

/**
 * @brief get_json_for_report_spec
 *
 * Make JSON object from report specification.
 *
 * @param report                ReportSpec_t report specification
 *
 * @return pbnjson::JValue
 */
pbnjson::JValue get_json_for_report_spec(const ReportSpec_t *report)
{
	pbnjson::JValue result = pbnjson::Object();
	result.put("type", GetNameForType(report->reportType));
	if (report->reportCause) result.put("cause", report->reportCause);
	if (report->reportComponent) result.put("component", report->reportComponent);
	if (report->reportDetail) result.put("detail", report->reportDetail);
	if (report->reportPath) result.put("reportFile", report->reportPath);
	if (report->reportFileName) result.put("originalName", report->reportFileName);
	if (report->reportSysInfoSnapshot) result.put("sysinfo", report->reportSysInfoSnapshot);
	if (report->reportFormat) result.put("format", report->reportFormat);
	if (report->reportTime) result.put("time", report->reportTime);

	return result;
}

/**
 * @brief handle_report_processing_cb
 *
 * Callback for report processing calls
 * Used for logging report handling responses
 */
static bool handle_report_processing_cb(LSHandle *sh, LSMessage *reply, void *ctx)
{
	pbnjson::JValue json = pbnjson::JDomParser::fromString(LSMessageGetPayload(reply));
	if (!json || !json["returnValue"].isBoolean())
	{
		LOG_RDXD_WARNING(MSGID_INVALID_JOBJ, 3,
		                 PMLOGKS(SERVICE, LSMessageGetSenderServiceName(reply)),
		                 PMLOGKS(CATEGORY, LSMessageGetCategory(reply)),
		                 PMLOGKS(METHOD, LSMessageGetMethod(reply)),
		                 "Response from processing method (%s/%s/%s) is invalid/incomplete JSON: %s",
		                 LSMessageGetSenderServiceName(reply), LSMessageGetCategory(reply),
		                 LSMessageGetMethod(reply), LSMessageGetPayload(reply));
		return false;
	}

	if (json["returnValue"].asBool())
	{
		LOG_RDXD_INFO(MSGID_REPORT_PROCESSING_INFO, 3,
		                 PMLOGKS(SERVICE, LSMessageGetSenderServiceName(reply)),
		                 PMLOGKS(CATEGORY, LSMessageGetCategory(reply)),
		                 PMLOGKS(METHOD, LSMessageGetMethod(reply)),
		                 "Successfully processed report with %s/%s/%s",
		                 LSMessageGetSenderServiceName(reply), LSMessageGetCategory(reply),
		                 LSMessageGetMethod(reply));
	}
	else
	{
		gchar *errorText = (json["errorText"].isString()) ?
				(g_strescape(json["errorText"].asString().c_str(), NULL)) : (g_strdup("Unknown error"));
		int errorCode = (json["errorCode"].isNumber()) ? (json["errorCode"].asNumber<int>()) : (-1);

		const char *reason = "Failed to process report with ";
		if (LSMessageIsHubErrorMessage(reply))
		{
			reason = "Hub error while processing report with ";
		}
		LOG_RDXD_WARNING(MSGID_REPORT_PROCESSING_FAIL, 5,
		                 PMLOGKS(SERVICE, LSMessageGetSenderServiceName(reply)),
		                 PMLOGKS(CATEGORY, LSMessageGetCategory(reply)),
		                 PMLOGKS(METHOD, LSMessageGetMethod(reply)),
		                 PMLOGKS(ERRTEXT, errorText),
		                 PMLOGKFV(ERRCODE,"%d", errorCode),
		                 "%s %s/%s/%s - %s (%d)", reason,
		                 LSMessageGetSenderServiceName(reply), LSMessageGetCategory(reply),
		                 LSMessageGetMethod(reply), errorText, errorCode);

		g_free(errorText);
	}
	return true;
}


/**
 * @brief post_report
 *
 * Post report to subsribed services.
 *
 * @param report                ReportSpec_t report specification
 * @param error                 GError pointer
 *
 * @return true on success
 */
static bool
post_report(const ReportSpec_t *report, GError **error)
{
	g_assert(report);
	LOG_RDXD_DEBUG("%s: called with type %d and report %s (original %s, sysinfo %s, cause %s, component %s)",
	                 __func__, report->reportType, report->reportPath,
	                 report->reportFileName, report->reportSysInfoSnapshot,
	                 report->reportCause, report->reportComponent);

	std::vector<std::string> *handlers = GetHandlersForType(report->reportType);
	if (!handlers)
	{
		LOG_RDXD_ERROR(MSGID_INVALID_REPORT_TYPE, 1,
		                 PMLOGKFV(TYPE, "%d", report->reportType),
		                 "Invalid report type %d (%s)",
		                 static_cast<int>(report->reportType), report->reportCause);
		g_set_error(error,
		                 RDX_ERROR,
		                 RDX_ERR_SERVICE,
		                 "Invalid report type %d (%s)",
		                 report->reportType, report->reportCause);
		return false;
	}

	if (handlers->empty())
	{
		LOG_RDXD_INFO(MSGID_NO_HANDLERS_FOR_REPORT, 1,
		                 PMLOGKFV(TYPE,"%d", report->reportType),
		                 "No services configured to process reports of type %d (%s)",
		                 report->reportType, report->reportCause);
		return true;
	}

	auto report_json = get_json_for_report_spec(report);

	gchar *report_link_name = NULL;
	gulong report_link_len = 0;
	if (report->reportPath)
	{
		report_link_len = strlen(report->reportPath) + MAX_IDX_LENGTH + 1;
		report_link_name = (gchar *)g_malloc0(report_link_len);
	}
	gchar *sysinfo_link_name = NULL;
	gulong sysinfo_link_len = 0;
	if (report->reportSysInfoSnapshot)
	{
		sysinfo_link_len = strlen(report->reportSysInfoSnapshot) + MAX_IDX_LENGTH + 1;
		sysinfo_link_name = (gchar *)g_malloc0(sysinfo_link_len);
	}

	LSError lserror;
	LSErrorInit(&lserror);
	uint idx = 0;
	std::string call_url;
	std::string call_payload;
	for (const std::string &url : *handlers)
	{
		++idx;
		if (report->reportPath && report_link_name)
		{
			g_snprintf(report_link_name, report_link_len, "%s.%u", report->reportPath, idx);
			if (-1 == link(report->reportPath, report_link_name))
			{
				LOG_RDXD_ERROR(MSGID_MAKE_HARDLINK_FAIL, 2,
				                 PMLOGKS(OLDPATH, report->reportPath),
				                 PMLOGKS(NEWPATH, report_link_name),
				                 "Failed to make report hard link from %s to %s",
				                 report->reportPath, report_link_name);
				continue;
			}
			else
			{
				report_json.put("reportFile", report_link_name);
			}
		}

		if (report->reportSysInfoSnapshot && sysinfo_link_name)
		{
			g_snprintf(sysinfo_link_name, sysinfo_link_len, "%s.%u", report->reportSysInfoSnapshot, idx);
			if (-1 == link(report->reportSysInfoSnapshot, sysinfo_link_name))
			{
				LOG_RDXD_ERROR(MSGID_MAKE_HARDLINK_FAIL, 2,
				                 PMLOGKS(OLDPATH, report->reportSysInfoSnapshot),
				                 PMLOGKS(NEWPATH, sysinfo_link_name),
				                 "Failed to make sysinfo hard link from %s to %s",
				                 report->reportSysInfoSnapshot, sysinfo_link_name);
				continue;
			}
			else
			{
				report_json.put("sysinfo", sysinfo_link_name);
			}
		}

		call_url = "luna://" + url;
		call_payload = report_json.stringify(" ");

		if (!LSCallOneReply(sServiceHandle,
		                    call_url.c_str(),
		                    call_payload.c_str(),
		                    handle_report_processing_cb,
		                    NULL, NULL, &lserror))
		{
			LSREPORT(lserror);
		}
		else
		{
			LOG_RDXD_INFO(MSGID_REPORT_POSTED_INFO, 6,
			                 PMLOGKS(URL, call_url.c_str()),
			                 PMLOGKFV(TYPE, "%d",report->reportType),
			                 PMLOGKS(CAUSE, report->reportCause),
			                 PMLOGKS(COMPONENT, report->reportComponent),
			                 PMLOGKS(PATH, report->reportPath),
			                 PMLOGKS(FILENAME, report->reportFileName),
			                 "Successfully posted report to %s : type %d path %s name %s cause %s component %s",
			                 call_url.c_str(), report->reportType, report->reportPath, report->reportFileName,
			                 report->reportCause, report->reportComponent);
		}
	}

	LSErrorFree(&lserror);
	if (report_link_name)
		g_free(report_link_name);
	if (sysinfo_link_name)
		g_free(sysinfo_link_name);

	return true;
}

/**
 * @brief upload_overview
 *
 * This will take the overview and post it to upload services.
 */
static void
upload_overview()
{
	// make starting overview and send to all interested "overview" up-loaders
	LOG_RDXD_DEBUG("Sending starting overview");

	gchar *dst_path = make_tmpfile(TMP_OVERVIEW_REPORT_DIR, "overview");
	if (!dst_path)
	{
		LOG_RDXD_ERROR(MSGID_MK_TMP_FILE_ERR, 1,
		                 PMLOGKS(PATH, TMP_OVERVIEW_REPORT_DIR),
		                 "Failed to make temporary unique file in %s", TMP_OVERVIEW_REPORT_DIR);
		return;
	}

	if (!CLCreateOverview(dst_path))
	{
		LOG_RDXD_ERROR(MSGID_MK_TMP_FILE_ERR, 1,
		                 PMLOGKS(PATH, dst_path),
		                 "Failed to make starting overview into file %s", dst_path);
		g_unlink(dst_path);
		g_free(dst_path);
		return;
	}

	if (0 != g_chmod(dst_path, S_IRUSR))
	{
		LOG_RDXD_WARNING(MSGID_FILE_CHMOD_FAILED, 3,
		                 PMLOGKS(PATH, dst_path),
		                 PMLOGKFV(ERRCODE, "%d", errno),
		                 PMLOGKS(ERRTEXT, strerror(errno)),
		                 "Failed to change permissions for file %s: %s",
		                 dst_path, strerror(errno));
	}

	ReportSpec_t *report = g_new0(ReportSpec_t, 1);
	report->reportType = RDX_INPUT_TYPE_OVERVIEW;
	report->reportCause = g_strdup("Overview");
	report->reportFileName = g_strdup("overview.txt");
	report->reportPath = g_strdup(dst_path);
	GError *error = NULL;
	if (!post_report(report, &error))
	{
		LOG_RDXD_ERROR(MSGID_POST_REPORT_ERR, 3,
		                 PMLOGKS(PATH, report->reportPath),
		                 PMLOGKS(FILENAME, report->reportFileName),
		                 PMLOGKFV(TYPE, "%d", report->reportType),
		                 "Failed to post overview %s (%s) to upload services: %s (%d)",
		                 report->reportPath, report->reportFileName, error->message, error->code);
	}

	free_report_spec(report);
	if (error)
		g_error_free(error);
	if (dst_path)
	{
		g_unlink(dst_path);
		g_free(dst_path);
	}
}

/**
 * @brief process_crash_report
 *
 * This will take the given ReportSpec_t for crash report,
 * copy report source into temporary location, generate sysinfo snapshot
 * and pass crash report to upload services
 *
 * @param spec
 * @param error
 *
 * @return
 */
static bool
process_crash_report(ReportSpec_t *spec, GError **error)
{
	g_assert(spec);

	bool ret = false;
	gchar *originalReportPath = NULL;
	gchar *tmpReportPath = NULL;

	if (!sDoUploadCrashLog)
	{
		LOG_RDXD_INFO(MSGID_REPORT_PROCESSING_INFO, 0,
		                 "Upload switch is disabled for crash reports - report will not be processed");
		g_set_error(error,
		            RDX_ERROR,
					RDX_ERR_SERVICE,
		            "Upload switch is disabled for crash reports");
		goto done;
	}

	if (spec->reportFileName && spec->reportPath)
	{
		if (!g_file_test(spec->reportPath, G_FILE_TEST_EXISTS))
		{
			LOG_RDXD_ERROR(MSGID_UNKNOWN_FILE, 1,
			                 PMLOGKS(PATH, spec->reportPath),
			                 "Input crash report %s does not exist", spec->reportPath);
			g_set_error(error,
			                 RDX_ERROR,
			                 RDX_ERR_SERVICE,
			                 "Crash report does not exist");
			goto done;
		}

		tmpReportPath = copy_to_temporary(spec->reportPath, TMP_CRASH_REPORT_DIR, "crash");
		if (!tmpReportPath)
		{
			LOG_RDXD_ERROR(MSGID_COPY_ERR, 2,
			                 PMLOGKS(PATH, spec->reportPath),
			                 PMLOGKS(TMP_FOLDER, TMP_CRASH_REPORT_DIR),
			                 "Failed to copy file %s into temporary folder %s with unique name",
			                 spec->reportPath, TMP_CRASH_REPORT_DIR);
			g_set_error(error,
			                 RDX_ERROR,
			                 RDX_ERR_SERVICE,
			                 "Could not copy crash report into temporary location");
			goto done;
		}

		if (0 != g_chmod(tmpReportPath, S_IRUSR))
		{
			LOG_RDXD_WARNING(MSGID_FILE_CHMOD_FAILED, 3,
			                 PMLOGKS(PATH, tmpReportPath),
			                 PMLOGKFV(ERRCODE, "%d", errno),
			                 PMLOGKS(ERRTEXT, strerror(errno)),
			                 "Failed to change permissions for file %s: %s",
			                 tmpReportPath, strerror(errno));
		}

		originalReportPath = spec->reportPath;
		spec->reportPath = tmpReportPath;
	}

	spec->reportSysInfoSnapshot = make_tmpfile(TMP_CRASH_REPORT_DIR, "sysinfo");
	if (!spec->reportSysInfoSnapshot)
	{
		LOG_RDXD_ERROR(MSGID_MK_TMP_FILE_ERR, 1,
		                 PMLOGKS(PATH, TMP_CRASH_REPORT_DIR),
		                 "Failed to make temporary unique file in %s", TMP_CRASH_REPORT_DIR);
		g_set_error(error,
		                 RDX_ERROR,
		                 RDX_ERR_SERVICE,
		                 "Could not make unique temporary file");
		goto done;
	}

	//make sysinfo snapshot with CLDumpSysInfo
	if (!CLDumpSysInfo(spec->reportSysInfoSnapshot))
	{
		LOG_RDXD_ERROR(MSGID_MK_TMP_FILE_ERR, 1,
		                 PMLOGKS(PATH, spec->reportSysInfoSnapshot),
		                 "Failed to make sysinfo dump into file %s", spec->reportSysInfoSnapshot);
		g_set_error(error,
		                 RDX_ERROR,
		                 RDX_ERR_SERVICE,
		                 "Could not make sysinfo dump");
		goto done;
	}

	spec->reportType = RDX_INPUT_TYPE_CRASH;
	if (!post_report(spec, error))
	{
		LOG_RDXD_ERROR(MSGID_POST_REPORT_ERR, 3,
		                 PMLOGKS(PATH, spec->reportPath),
		                 PMLOGKS(FILENAME, spec->reportFileName),
		                 PMLOGKFV(TYPE, "%d", spec->reportType),
		                 "Failed to post crash report %s (%s) to upload services: %s (%d)",
		                 spec->reportPath, spec->reportFileName, (*error)->message, (*error)->code);
		goto done;
	}

	rotate_analytics();
	ret = true;

done:

	if (originalReportPath)
	{
		spec->reportPath = originalReportPath;
		originalReportPath = NULL;
	}
	mark_as_seen(spec->reportPath, ret, error);

	if (tmpReportPath)
	{
		g_unlink(tmpReportPath);
		g_free(tmpReportPath);
	}

	if (spec->reportSysInfoSnapshot)
	{
		g_unlink(spec->reportSysInfoSnapshot);
		g_free(spec->reportSysInfoSnapshot);
		spec->reportSysInfoSnapshot = NULL;
	}

	return ret;
}


//->Start of API documentation comment block
/**
@page com_webos_rdxd com.webos.rdxd
@{
@section com_webos_rdxd_makeReport makeReport

Record a problem for reporting

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
detail | Yes | String | Details of the report
cause | No | String | Triggering event for the report (Default is "manual report")
component | No | String | Component originating the report

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
reportId | yes | Integer | ID Code for the generated report

@par Returns(Subscription)
None
@}
*/
//->End of API documentation comment block

/**
 * @brief make_report_LS
 *
 * Handle the 'makereport' command, to handle a user-initiated
 * manual report.
 *
 * @param lshandle
 * @param message
 * @param wd
 *
 * @return
 */
static bool make_report_LS(LSHandle *lshandle, LSMessage *message, void *wd)
{
	bool retVal = false;
	LSError lserror;
	LSErrorInit(&lserror);

	LSTRACE_LSMESSAGE(message);

	gchar *status = NULL;
	int result = 0;
	gchar *detail = NULL;
	gchar *cause = NULL;
	gchar *component = NULL;
	gchar *reportPath = NULL;
	gchar *reportName = NULL;
	const gchar *errorText = NULL;
	GError *error = NULL;
	ReportSpec_t *spec = NULL;

	jvalue_ref parsedObj = NULL;
	jvalue_ref detailObj = NULL;
	jvalue_ref causeObj = NULL;
	jvalue_ref componentObj = NULL;
	jvalue_ref reportPathObj = NULL;
	jvalue_ref reportNameObj = NULL;

	jerror *jerr = NULL;
	const char *payload_schema_json = R"({
				"type": "object",
				"properties": {
					"detail": {"type": "string"},
					"cause": {"type": "string"},
					"component": {"type": "string"},
					"reportPath": {"type": "string"},
					"reportName": {"type": "string"}
				},
				"required": ["detail"],
				"additionalProperties": false
			})";
	jschema_ref payload_schema = jschema_create(j_cstr_to_buffer(payload_schema_json), &jerr);
	if (jerr)
	{
		char error_msg[256] = {0};
		jerror_to_string(jerr, error_msg, sizeof(error_msg));
		g_set_error(&error, RDX_ERROR, RDX_ERR_SERVICE, "Error parsing schema: %s", error_msg);
		jerror_free(jerr);
		result = RDX_ERR_SERVICE;
		goto respond;
	}

	parsedObj = jdom_create(j_cstr_to_buffer(LSMessageGetPayload(message)), payload_schema, &jerr);
	jschema_release(&payload_schema);
	if (jerr)
	{
		char error_msg[256] = {0};
		jerror_to_string(jerr, error_msg, sizeof(error_msg));
		g_set_error(&error, RDX_ERROR, RDX_ERR_SERVICE, "Error parsing payload: %s", error_msg);
		jerror_free(jerr);
		result = RDX_ERR_SERVICE;
		goto respond;
	}

	if (jis_null(parsedObj))
	{
		// input failed to parse (this is OK since we only allow parsing of top level elements (an object or array)
		j_release(&parsedObj);
		return retVal;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("detail"), &detailObj))
	{
		raw_buffer detail_buf = jstring_get(detailObj);
		detail = g_strdup(detail_buf.m_str);
		jstring_free_buffer(detail_buf);
	}
	else
	{
		errorText = "no detail in payload";
		result = RDX_ERR_SERVICE;
		goto respond;
	}


	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("cause"), &causeObj))
	{
		raw_buffer cause_buf = jstring_get(causeObj);
		cause = g_strdup(cause_buf.m_str);
		jstring_free_buffer(cause_buf);
	}
	else
	{
		LOG_RDXD_DEBUG("%s: no cause in payload.. using \"manual report\"", __func__);
		cause = g_strdup("manual report");
	}


	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("component"), &componentObj))
	{
		raw_buffer component_buf = jstring_get(componentObj);
		component = g_strdup(component_buf.m_str);
		jstring_free_buffer(component_buf);
	}
	else
	{
		LOG_RDXD_DEBUG("%s: no component in payload", __func__);
		component = g_strdup("");
	}

	LOG_RDXD_DEBUG("%s called with detail=\"%s\"", __func__, detail);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("reportPath"), &reportPathObj))
	{
		raw_buffer reportPath_buf = jstring_get(reportPathObj);
		reportPath = g_strdup(reportPath_buf.m_str);
		jstring_free_buffer(reportPath_buf);
	}
	else
		LOG_RDXD_DEBUG("%s: no reportPath in payload", __func__);

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("reportName"), &reportNameObj))
	{
		raw_buffer reportName_buf = jstring_get(reportNameObj);
		reportName = g_strdup(reportName_buf.m_str);
		jstring_free_buffer(reportName_buf);
	}
	else
		LOG_RDXD_DEBUG("%s: no reportName in payload", __func__);


	spec = g_new0(ReportSpec_t, 1);

	spec->reportCause       = g_strdup(cause);
	spec->reportDetail      = g_strdup(detail);
	spec->reportComponent   = g_strdup(component);
	if (reportPath) spec->reportPath = g_strdup(reportPath);
	if (reportName) spec->reportFileName = g_strdup(reportName);

	if (!process_crash_report(spec, &error))
	{
		result = RDX_ERR_SERVICE;
		goto respond;
	}

	result = RDX_ERR_NONE;

respond:

	if (result == RDX_ERR_NONE)
	{
		status = g_strdup_printf(R"({"returnValue":true})");
	}
	else if (errorText != NULL)
	{
		status = g_strdup_printf(R"({"returnValue":false,"errorText":"%s"})", errorText);
	}
	else if (error != NULL)
	{
		status = g_strdup_printf(R"({"returnValue":false,"errorCode":%d,"errorText":"%s"})",
		                         error->code, error->message);
	}
	else
	{
		status = g_strdup_printf(R"({"returnValue":false,"errorText":"%s"})",
		                         "unknown error");
	}

	LOG_RDXD_DEBUG("%s return status=%s.", __func__, status);

	retVal = LSMessageReply(lshandle, message, status, &lserror);
	if (!retVal)
	{
		LSREPORT(lserror);
	}

	j_release(&parsedObj);
	LSErrorFree(&lserror);
	free_report_spec(spec);

	if (error)
		g_error_free(error);

	g_free(status);
	g_free(cause);
	g_free(component);
	g_free(detail);
	g_free(reportPath);
	g_free(reportName);

	return retVal;

}

/**
 * @brief payload_extract_filepath
 *
 * Extract "filepath" element from LSMessage paylod.
 *
 * @param message
 *
 * @return
 */
static gchar *payload_extract_filepath(LSMessage *message)
{
	LSTRACE_LSMESSAGE(message);

	gchar *filePath = NULL;

	JSchemaInfo schemaInfo;
	jvalue_ref parsedObj = NULL;
	jvalue_ref filepathObj = NULL;

	jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);
	parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);

	if (jis_null(parsedObj))
	{
		return NULL;
	}

	if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("filepath"), &filepathObj))
	{
		raw_buffer filepath_buf;
		filepath_buf = jstring_get(filepathObj);
		filePath = g_strdup(filepath_buf.m_str);
		jstring_free_buffer(filepath_buf);
	}

	j_release(&parsedObj);

	return filePath;
}

/**
 * @brief process_analytics_log_report
 *
 * This will take the given report from "filePath",
 * copy report source into temporary location
 * and pass analytical report to upload services
 *
 * @param filePath
 * @param status
 *
 * @return
 */
static void process_analytics_log_report(const gchar *filePath, gchar **status)
{
	const char *errorText = NULL;
	int result = -1;
	GError *error = NULL;
	gchar *originalFileName = NULL;
	gchar *newFilePath = NULL;
	gchar *tmpFilePath = NULL;
	ReportSpec_t *report = NULL;

	if (check_devmode())
	{
		errorText = "Devmode is enabled, analytics reports will not be generated";
		result = RDX_ERR_SERVICE;
		goto done;
	}

	if (!sDoUploadAnalyticsLog)
	{
		LOG_RDXD_INFO(MSGID_REPORT_PROCESSING_INFO, 0,
		                 "Upload switch is disabled for analytic reports - report will not be processed");
		errorText = "Upload switch is disabled for analytic reports";
		result = RDX_ERR_SERVICE;
		goto done;
	}

	if (!g_file_test(filePath, G_FILE_TEST_EXISTS))
	{
		LOG_RDXD_ERROR(MSGID_UNKNOWN_FILE, 1,
		                 PMLOGKS(PATH, filePath),
		                 "Input analytical report %s does not exist", filePath);
		errorText = "Specified file does not exist";
		result = RDX_ERR_SERVICE;
		goto done;
	}

	originalFileName = g_path_get_basename(filePath);

	// filter analytical report source
	newFilePath = CLFilterLogs(filePath);
	if (!newFilePath)
	{
		LOG_RDXD_WARNING(MSGID_FILTER_ERR, 0, "Filtering went wrong");
	}
	else
	{
		filePath = newFilePath;
	}

	tmpFilePath = copy_to_temporary(filePath, TMP_ANALYTICS_REPORT_DIR, "analytics");
	if (!tmpFilePath)
	{
		LOG_RDXD_ERROR(MSGID_COPY_ERR, 2,
		                 PMLOGKS(PATH, filePath),
		                 PMLOGKS(TMP_FOLDER, TMP_ANALYTICS_REPORT_DIR),
		                 "Failed to copy file %s into temporary folder %s with unique name",
		                 filePath, TMP_ANALYTICS_REPORT_DIR);
		errorText = "Could not copy report into temporary location";
		result = RDX_ERR_SERVICE;
		goto done;
	}

	if (0 != g_chmod(tmpFilePath, S_IRUSR))
	{
		LOG_RDXD_WARNING(MSGID_FILE_CHMOD_FAILED, 3,
		                 PMLOGKS(PATH, tmpFilePath),
		                 PMLOGKFV(ERRCODE, "%d", errno),
		                 PMLOGKS(ERRTEXT, strerror(errno)),
		                 "Failed to change permissions for file %s: %s",
		                 tmpFilePath, strerror(errno));
	}

	report = g_new0(ReportSpec_t, 1);
	report->reportType = RDX_INPUT_TYPE_ANALYTICAL;
	report->reportCause = g_strdup("Analytics");
	report->reportFileName = g_strdup(originalFileName);
	report->reportPath = g_strdup(tmpFilePath);

	if (!post_report(report, &error))
	{
		LOG_RDXD_ERROR(MSGID_POST_REPORT_ERR, 3,
		                 PMLOGKS(PATH, report->reportPath),
		                 PMLOGKS(FILENAME, report->reportFileName),
		                 PMLOGKFV(TYPE, "%d", report->reportType),
		                 "Failed to post analytical report %s (%s) to upload services: %s (%d)",
		                 report->reportPath, report->reportFileName, error->message, error->code);
		result = RDX_ERR_SERVICE;
		goto done;
	}

	result = RDX_ERR_NONE;

done:
	if (status)
	{
		if (result == RDX_ERR_NONE)
		{
			*status = g_strdup_printf("{\"returnValue\":true}");
		}
		else if (error != NULL)
		{
			*status = g_strdup_printf(R"({"returnValue":false,"errorCode":%d,"errorText":"%s"})",
							error->code, error->message);
		}
		else
		{
			const gchar *eeText = errorText ? errorText : "unknown error";
			LOG_RDXD_DEBUG(eeText);
			*status = g_strdup_printf(R"({"returnValue":false, "errorCode":-1, "errorText":"%s"})", eeText);
		}
	}

	if (newFilePath)
		g_unlink(newFilePath);
	if (tmpFilePath)
		g_unlink(tmpFilePath);

	g_free(originalFileName);
	g_free(newFilePath);
	g_free(tmpFilePath);
	free_report_spec(report);

	if (error)
		g_error_free(error);

}


/////////////////////////////////////////////////////////////////
//                                                             //
//            Start of API documentation comment block         //
//                                                             //
/////////////////////////////////////////////////////////////////
/**
@page com_webos_rdxd com.webos.rdxd
@{
@section com_webos_rdxd_makeLogReport makeLogReport

Create a analytics log report and upload it

@par Parameters

Name | Required | Type | Description
-----|--------|------|----------
filepath | Yes | String | Folder of log file
fielname | Yes | String | Filename of rotated log file

@par Returns(Call)

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True if successful, false otherwise with errorText

@par Returns(Subscription)

Not applicable.

@}
*/

/////////////////////////////////////////////////////////////////
//                                                             //
//            End of API documentation comment block           //
//                                                             //
/////////////////////////////////////////////////////////////////

/**
 * @brief make_analytics_log_report_LS
 *
 * Handle the 'makelogreport' LS2 call
 *
 * @param lshandle
 * @param message
 * @param wd
 *
 * @return
 */
static bool make_analytics_log_report_LS(LSHandle *lshandle, LSMessage *message, void *wd)
{
	const char *fpError = R"({"returnValue":false,"errorText":"Could not extract filepath"})";

	bool retVal = false;
	gchar *status = NULL;
	gchar *filePath = payload_extract_filepath(message);

	if (filePath != NULL)
		process_analytics_log_report(filePath, &status);

	LSError lserror;
	LSErrorInit(&lserror);

	retVal = LSMessageReply(lshandle, message, status != NULL ? status : fpError, &lserror);
	if (!retVal)
	{
		LSREPORT(lserror);
		LSErrorFree(&lserror);
	}

	g_free(status);
	g_free(filePath);

	return retVal;
}

/**
 * @brief log_rotation_handler_LS
 *
 * Handle pmlogdaemon log rotation
 *
 * @param lshandle
 * @param message
 * @param wd
 *
 * @return
 */
static bool log_rotation_handler_LS(LSHandle *lshandle, LSMessage *message, void *wd)
{
	gchar *filePath = payload_extract_filepath(message);
	if (filePath)
	{
		process_analytics_log_report(filePath, NULL);

		// compress log file to reduce memory
		if(!compress_file(filePath))
		{
		        LOG_RDXD_DEBUG("compress_file fail \n");
		        goto END;
		}

		std::string filePathStr(filePath);
		std::string newFilePath = filePathStr + ".gz";
		std::string prefix = filePathStr.substr(0,filePathStr.find_last_of("."));
		std::string newPath, oldPath;
		// rotate log files
		for (int i = 9; i > 0; --i)
		{
			oldPath = prefix + "." + std::to_string(i-1) + ".gz";
			newPath = prefix + "." + std::to_string(i) + ".gz";
			(void) rename(oldPath.c_str(), newPath.c_str());
		}

		if (rename(newFilePath.c_str(), oldPath.c_str()) < 0)
		{
			LOG_RDXD_WARNING(MSGID_FILE_RENAME_ERR, 3, PMLOGKS(OLDPATH, newFilePath.c_str()),
			                 PMLOGKS(NEWPATH, oldPath.c_str()),
			                 PMLOGKS(ERRTEXT, strerror(errno)), "Failed to rename file");
		}
		remove(filePath);
	}
END:
	g_free(filePath);

	return true;
}

static LSMethod ourMethods[] =
{
	{ "makeReport", make_report_LS },
	{ "makeLogReport", make_analytics_log_report_LS },
	{ "getLogSettings", get_Upload_Switch_LS},
	{ "setLogSettings", set_Upload_Switch_LS},
	{},
};

/**
 * @brief parse_params
 * Parse the command line parameters.
 *
 * @param argc number of arguments
 * @param argv array of arguements
 * @param *config_path
 * @param verbose
 * @param useSyslog
 *
 * @return Return result code.
 */
static bool
parse_params(int argc, char *argv[], gchar **config_path, gboolean *verbose,
             gboolean *useSyslog)
{
	GOptionEntry entries[] =
	{
		{
			"configuration", 'f', 0, G_OPTION_ARG_FILENAME, config_path,
			"Specify configuration file to read from", "N"
		},
		{
			"verbose", 'v', 0, G_OPTION_ARG_NONE, verbose,
			"Be verbose", NULL
		},
		{
			"syslog", 's', 0, G_OPTION_ARG_NONE, useSyslog,
			"Log to syslog", NULL
		},
		{ NULL }
	};
	GError *error = NULL;
	GOptionContext *context =
	    g_option_context_new("- is the remote diagnostics server.");
	g_assert(context);
	g_option_context_add_main_entries(context, entries, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		LOG_RDXD_ERROR(MSGID_OPTION_PARSE_ERR, 1, PMLOGKS(REASON, error->message), "");
		if (error)
			g_error_free(error);
		return false;
	}

	g_option_context_free(context);

	if (config_path && *config_path)
	{
		LOG_RDXD_DEBUG("configPath set to %s", *config_path);
	}

	LOG_RDXD_DEBUG("sAreVerbose set to %d", *verbose);
	LOG_RDXD_DEBUG("useSyslog set to %d", *useSyslog);
	return true;
}

/**
 * @brief quit
 *
 * exit based on external signal
 *
 * @param sig unused
 */
void
quit(int G_GNUC_UNUSED(sig))
{
	LOG_RDXD_DEBUG("rdxd exiting...");

	g_main_loop_quit(sMainLoop);
}

/**
 * @brief reinit
 *
 * Called when rdxd should reinitialize watch and cloud settings
 *
 * @param data unused
 */
static gboolean
reinit(gpointer data)
{
	WTFini();
	ensure_working_dirs_exist();
	WTInit(process_crash_report);

	return false;
}

/**
 * @brief sighandler_hup
 *
 * Asynchronously called when rdxd should reinitialize watch settings.
 * e.g when /var/log is nuked by logd
 *
 * @param sig unused
 */
void
sighandler_hup(int G_GNUC_UNUSED(sig))
{
	g_timeout_add(0, reinit, NULL);
}

/***********************************************************************
 * main
 ***********************************************************************/
int
main(int argc, char *argv[])
{
	LSError lserror;
	LSErrorInit(&lserror);

	(void) signal(SIGINT, quit);
	(void) signal(SIGQUIT, quit);
	(void) signal(SIGTERM, quit);
	(void) signal(SIGHUP, sighandler_hup);

	LOG_RDXD_DEBUG("%s called", __func__);
	sAreVerbose = false;
	gboolean useSyslog = false;

	LOGInit(); // initialize logging

	static gchar *config_path = NULL;

	g_assert(parse_params(argc, argv, &config_path, &sAreVerbose, &useSyslog));

	if (sAreVerbose)
	{
		LOGSetLevel(G_LOG_LEVEL_DEBUG);
	}
	else
	{
		LOGSetLevel(G_LOG_LEVEL_INFO);
	}

	if (useSyslog)
	{
		LOGSetHandler(LOGSyslog);
	}

	GKeyFile *config_file = NULL;
	bool retVal = true;
	GError *gerror = NULL;

	config_file = g_key_file_new();

	if (!config_file)
	{
		LOG_RDXD_ERROR(MSGID_CREATE_KEYFILE_ERR, 0, " ");
		exit(EXIT_FAILURE);
	}

	if (config_path == NULL)
	{
		config_path = g_strdup(DEFAULT_CONFIG_PATH);
	}

	LOG_RDXD_DEBUG("%s: parsing config path %s", __func__, config_path);

	retVal = g_key_file_load_from_file(config_file, config_path, G_KEY_FILE_NONE,
	                                   &gerror);

	if (!retVal)
	{
		LOG_RDXD_ERROR(MSGID_CONF_FILE_READ_ERR, 1,
		               PMLOGKS(ERRTEXT, (gerror) ? gerror->message : "Reason Unknown"),
		               "Daemon Exiting - failed to read configuration file");

		if (gerror)
		{
			g_error_free(gerror);
		}

		exit(EXIT_FAILURE);
	}

	// read the main conf & LP settings
	ReadProps(config_file, &autoUpload);
	ReadHandlersConfig(DEFAULT_CONFIG_DIR);

	LOG_RDXD_DEBUG("rdxd running");

	LOG_RDXD_DEBUG("Registering %s", RDXD_APP_ID);

	if (!LSRegister(RDXD_APP_ID, &sServiceHandle, &lserror))
	{
		LSREPORT(lserror);
		LOG_RDXD_ERROR(MSGID_SRVC_REGISTER_ERR, 1,
				PMLOGKS(SRVC_ID, RDXD_APP_ID),
				"");
		exit(EXIT_FAILURE);
	}

	// check working directories
	ensure_working_dirs_exist();
	// initialize context logs
	CLInit(sServiceHandle, sMainLoop, config_file);

	// Subscribe to log rotations
	if (!LSCall(sServiceHandle,
	            "luna://com.webos.pmlogd/subscribeOnRotations",
	            "{\"subscribe\":true}",
	            log_rotation_handler_LS,
	            NULL,
	            NULL,
	            &lserror))
	{
		LSREPORT(lserror);
	}

	sMainLoop = g_main_loop_new(NULL, FALSE);

	if (sMainLoop == NULL)
	{
		goto error;
	}

	(void) reinit(NULL);

	retVal = LSRegisterCategory(sServiceHandle, "/", ourMethods, NULL, NULL, &lserror);
	if (!retVal)
	{
		LSREPORT(lserror);
		goto error;
	}

	retVal = LSGmainAttach(sServiceHandle, sMainLoop, &lserror);

	if (!retVal)
	{
		LSREPORT(lserror);
		exit(EXIT_FAILURE);
	}

	if (config_file)
	{
		g_key_file_free(config_file);
	}

	// upload starting overview
	upload_overview();

	g_main_loop_run(sMainLoop);
	g_main_loop_unref(sMainLoop);

	retVal = LSUnregister(sServiceHandle, &lserror);

	if (!retVal)
	{
		LSREPORT(lserror);
	}

error:

	WTFini();

	LSErrorFree(&lserror);

	exit(EXIT_SUCCESS);
}

//->Start of API documentation comment block
/**
@page com_webos_rdxd com.webos.rdxd
@{
@section com_webos_rdxd_getLogSettings getLogSettings

Retrieve current setting to allow/deny analytics/crash feature

@note Currently parameters are ignored and "AutoUpdate" is hardcoded!

@par Parameters
None

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
analyticsLog | yes | Boolean | Status of analytics upload feature
crashLog | yes | Boolean | Status of crash upload feature

@par Returns(Subscription)
None
@}
*/
//->End of API documentation comment block

/**
 * @brief get_Upload_Switch_LS
 *
 * retrieve current setting to allow/deny analytics/crash feature
 * Currently parameters are ignored and "AutoUpdate" is hardcoded!
 *
 * @param pHandle
 * @param pMessage
 * @param pUserData
 *
 * @return
 */
static bool
get_Upload_Switch_LS(LSHandle *pHandle, LSMessage *pMessage, void *pUserData)
{
	gchar *pPayload = NULL;
	bool bRetVal = false;
	LSError lsError;
	const char *analyticsLogSwitch = "analyticsLog";
	const char *crashLogSwitch = "crashLog";

	LSErrorInit(&lsError);

	pPayload =
	    g_strdup_printf(R"({"returnValue":true,"%s":%s,"%s":%s})",
	                    analyticsLogSwitch,
	                    (sDoUploadAnalyticsLog ? "true" : "false"),
	                    crashLogSwitch,
	                    (sDoUploadCrashLog ? "true" : "false"));

	bRetVal = LSMessageReply(pHandle, pMessage, pPayload, &lsError);

	if (!bRetVal)
	{
		LOG_RDXD_WARNING(MSGID_LSMSG_REPLY_ERR, 2, PMLOGKFV(ERRCODE, "%d",
		                 lsError.error_code), PMLOGKS(ERRTEXT, lsError.message), "");
	}

	if (pPayload)
	{
		g_free(pPayload);
	}

	LSErrorFree(&lsError);

	return bRetVal;

}

//->Start of API documentation comment block
/**
@page com_webos_rdxd com.webos.rdxd
@{
@section com_webos_rdxd_setLogSettings setLogSettings

Set switch for crash and analytics log to determine to upload
log report to cloud server

@par Parameters
Name | Required | Type | Description
-----|--------|------|----------
analyticsLog | yes | Boolean | true to enable analytic upload feature
crashLog | yes | Boolean | true to enable crash upload feature

@par Returns(Call)
Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True
analyticsLog | yes | Boolean | Status of analytics upload feature
crashLog | yes | Boolean | Status of crash upload feature

@par Returns(Subscription)
None
@}
*/
//->End of API documentation comment block

/**
 * @brief set_Upload_Switch_LS
 *
 * Set switch for crash and analytics log to determine to upload
 * log report to cloud server
 *
 * @param pHandle
 * @param pMessage
 * @param pUserData
 *
 * @return
 */
static bool
set_Upload_Switch_LS(LSHandle *pHandle, LSMessage *pMessage, void *pUserData)
{
	gchar *pPayload = NULL;

	using namespace pbnjson;

	static const JSchemaFragment params_schema{R"(
		{
			"type": "object",
			"properties": {
				"analyticsLog": {"type": "boolean"},
				"crashLog": {"type": "boolean"}
			},
			"required": ["analyticsLog", "crashLog"]
		}
		)"};

	LOG_RDXD_DEBUG("%s(), response : %s", __func__, LSMessageGetPayload(pMessage));

	JDomParser parser;
	if (parser.parse(LSMessageGetPayload(pMessage), params_schema))
	{
		auto parsedObj = parser.getDom();
		sDoUploadAnalyticsLog = parsedObj["analyticsLog"].asBool();
		sDoUploadCrashLog = parsedObj["crashLog"].asBool();

		pPayload = g_strdup_printf(R"({"returnValue":true,"analyticsLog":%s,"crashLog":%s})",
		                           sDoUploadAnalyticsLog ? "true":"false",
		                           sDoUploadCrashLog ? "true":"false");
	}
	else
	{
		pPayload = g_strdup(R"({"returnValue":false, "errorCode":-1, "errorText":"parameter not found"})");
	}

	LSError lsError;
	LSErrorInit(&lsError);

	// send progress
	bool bRetVal = LSMessageReply(pHandle, pMessage, pPayload, &lsError);

	if (!bRetVal)
	{
		LOG_RDXD_WARNING(MSGID_LSMSG_REPLY_ERR, 2, PMLOGKFV(ERRCODE, "%d",
		                 lsError.error_code), PMLOGKS(ERRTEXT, lsError.message), "");
	}

	g_free(pPayload);
	LSErrorFree(&lsError);

	return bRetVal;
}
