// Copyright (c) 2008-2019 LG Electronics, Inc.
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
 * @file watch.c
 *
 * @brief
 * Rdxd will watch certain folders and create a report whenever a new file
 * is found.
 * This file contains the logic concerning these watched folders.
 *
 */

#include <sys/inotify.h>
#include <sys/wait.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <luna-service2/lunaservice.h>

#include "watch.h"
#include "util.h"
#include "logging.h"

#define RDX_WATCH_ERROR watch_error_quark()
#define RDXD_CRASH_PREFIX "RDXD"

#define RDXD_LIBRDX_TRIGGER_PATH WEBOS_INSTALL_LOGDIR "/reports/librdx"
#define RDXD_LIBRDX_TRIGGER_LOG_FORMAT "bin, non-indexed"
#define CRASH_COMPONENT_FILE "/tmp/crash_component"

GQuark
watch_error_quark(void)
{
	return g_quark_from_static_string("rdx-watch");
}

enum
{
	RDX_WATCH_ERROR_CYCLIC_CRASH,
	RDX_WATCH_ERROR_TRIGGER_NOT_FOUND,
	RDX_WATCH_ERROR_PARSE_FUNC,
	RDX_WATCH_ERROR_SPEC_ERROR
};

static gint sINotifyFD = -1;

static WTReportFunc sReportCB;

static int sEventSourceID = 0;

static void
replace_char(gchar *str, char orig_char, char new_char)
{
	g_return_if_fail(str);

	int i = 0;

	for (i = 0; i < strlen(str); i++)
	{
		if (str[i] == orig_char)
		{
			str[i] = new_char;
		}
	}
}

/**
 * @brief new_report_spec
 *
 * The constructor for the ReportSpec.  It parses the
 * spec (all the metadata for the report) out of the given payload file.
 * librdx will have embedded the metadata in the filename.
 *
 * This used to be generic and handle multiple watch types.
 * Now it only knows how to parse reports from librdx
 *
 * @param path
 *
 * @return ReportSpec_t
 */
static ReportSpec_t *
new_report_spec(const char *path)
{
	int n;
	size_t len;
	gchar *metadata_str;
	FILE *fp;
	struct stat file_stat;

	ReportSpec_t *spec = g_new0(ReportSpec_t , 1);

	fp = fopen(path, "r+");

        if (!fp)
        {
                LOG_RDXD_WARNING(MSGID_FOPEN_ERR, 2,
                                 PMLOGKS(PATH, path), PMLOGKFV(ERRCODE, "%d", errno), ""); // 'n' not used
                return spec;
        }

	int fd = fileno(fp);

        // read meta data.
	if (fstat(fd, &file_stat) == -1)
	{
		LOG_RDXD_WARNING(MSGID_STAT_ERR, 2,
		                 PMLOGKS(PATH, path), PMLOGKFV(ERRCODE, "%d", errno), ""); // 'n' not used
                fclose(fp);
		return spec;
	}

	if (fseek(fp, -sizeof(size_t), SEEK_END))
	{
		LOG_RDXD_WARNING(MSGID_FSEEK_ERR, 1, PMLOGKFV(ERRCODE, "%d", errno), "fseek error");
		fclose(fp);
		return spec;
	}
	n = fread(&len, 1, sizeof(size_t), fp);

	if (n != sizeof(size_t) || len >= file_stat.st_size)
	{
		LOG_RDXD_WARNING(MSGID_FREAD_METADATA_LEN_ERR, 3,
		                 PMLOGKFV(METADATALEN, "%zu", len), PMLOGKFV(BYTES_READ, "%d", n),
		                 PMLOGKFV(ERRCODE, "%d", errno), "cannot read meta data length");
		fclose(fp);
		return spec;
	}

	metadata_str = g_malloc(len + 1);

	if (!metadata_str)
	{
		LOG_RDXD_ERROR(MSGID_G_MALLOC_ERR, 1, PMLOGKFV(METADATALEN, "%zu", len + 1),
		               "cannot g_malloc a memory to store meta data");
		fclose(fp);
		return spec;
	}

	if (fseek(fp, -(len + sizeof(size_t)), SEEK_END))
	{
		LOG_RDXD_WARNING(MSGID_FSEEK_METADATA_ERR, 1, PMLOGKFV(ERRCODE, "%d", errno), "fseek error");
		g_free(metadata_str);
		fclose(fp);
		return spec;
	}
	n = fread(metadata_str, 1, len, fp);

	if (n != len)
	{
		LOG_RDXD_WARNING(MSGID_FREAD_METADATA_ERR, 3,
		                 PMLOGKFV(METADATALEN, "%zu", len), PMLOGKFV(BYTES_READ, "%d", n),
		                 PMLOGKFV(ERRCODE, "%d", errno), "cannot read meta data");
		g_free(metadata_str);
		fclose(fp);
		return spec;
	}

	metadata_str[n] = 0;

	n = ftruncate(fd, file_stat.st_size - len - sizeof(size_t));

	if (n < 0)
	{
		LOG_RDXD_WARNING(MSGID_FILE_TRUNCATE_ERR, 0,
		                 "failed to truncate file from size=%zd to size=%zd\n",
		                 (ssize_t)file_stat.st_size,
		                 (ssize_t)file_stat.st_size - len - sizeof(size_t));
		g_free(metadata_str);
		fclose(fp);
		return spec;
	}
	fclose(fp);
	replace_char(metadata_str, 2, '/');
	replace_char(metadata_str, 3, '"');

	// this is the order elements are found in the metadata string
	enum
	{
		COMPONENT_PART = 0,
		CAUSE_PART,
		DETAIL_PART,
		FILENAME_PART,
		PARTS_COUNT
	};

	gchar **split = g_strsplit(metadata_str, "\x0001", PARTS_COUNT);

	int i = 0;

	for (i = 0; i < PARTS_COUNT; i++)
	{
		if (!split[i])
		{
			LOG_RDXD_WARNING(MSGID_STR_SPLIT_ERR, 1,
			                 PMLOGKS(METADATA_STR, metadata_str),
			                 "unexpected filename pattern for metadata string");
			goto error;
		}
	}

	spec->reportComponent = g_strdup(split[COMPONENT_PART]);
	spec->reportCause = g_strdup(split[CAUSE_PART]);
	spec->reportDetail = g_strdup(split[DETAIL_PART]);
	spec->reportFileName = g_strdup(split[FILENAME_PART]);
	spec->reportTime = get_file_modified_time(path);
	spec->reportPath = g_strdup(path);
	spec->reportFormat = g_strdup(RDXD_LIBRDX_TRIGGER_LOG_FORMAT);

	LOG_RDXD_DEBUG("%s: cause = '%s', component = '%s', detail = '%s', time = '%s', logFileName = '%s'",
	               __func__,
	               spec->reportCause,
	               spec->reportComponent,
	               spec->reportDetail,
	               spec->reportTime,
	               spec->reportFileName);

error:
	g_strfreev(split);
	g_free(metadata_str);

	return spec;
}


/**
 * @brief report
 *
 * @param trigger_filename
 * @param *error
 *
 * @return true on success
 */
static bool
report(const char *trigger_filename, GError **error)
{
	bool ret = false;
	int i = 0;
	ReportSpec_t *spec = NULL;
	gchar prev_crash_comp[128] = {0};
	FILE *fp = NULL;

	LOG_RDXD_DEBUG("%s called with p=%s f=%s", __func__, RDXD_LIBRDX_TRIGGER_PATH,
	               trigger_filename);

	gchar *crash_path = g_build_filename(RDXD_LIBRDX_TRIGGER_PATH, trigger_filename,
	                                     NULL);

	if (!g_file_test(crash_path, G_FILE_TEST_EXISTS))
	{
		g_set_error(error,
		            RDX_WATCH_ERROR,
		            RDX_WATCH_ERROR_TRIGGER_NOT_FOUND,
		            "%s: Trigger file %s no longer exists.. must have been cleaned out before we had a chance to make the report",
		            __func__, crash_path);
		goto cleanup;
	}

	spec = new_report_spec(crash_path);

	if (!spec)
	{
		LOG_RDXD_WARNING(MSGID_SPEC_ERROR, 1, PMLOGKS("crash file", crash_path),
		                 "Could not create spec for %s", crash_path);

		g_set_error(error,
		            RDX_WATCH_ERROR,
		            RDX_WATCH_ERROR_SPEC_ERROR,
		            "%s: Could not create spec for %s", __func__, crash_path);
		mark_as_seen(crash_path, false, error);
		goto cleanup;
	}

	if (spec->reportComponent)
	{
		// list of component names we will carefully report on, preventing cyclic crashes
		LOG_RDXD_DEBUG("%s: spec->reportComponent found : %s", __func__, spec->reportComponent);
		const char *black_list[] = { "rdxd", "uploadd", NULL };

		for (i = 0; black_list[i] != NULL; i++)
		{
			if (strcmp(black_list[i], spec->reportComponent) == 0)
			{
				LOG_RDXD_DEBUG("%s: Found blacklist component %s", __func__, black_list[i]);
				fp = fopen(CRASH_COMPONENT_FILE, "r");
				if (fp)
				{
					if (fgets(prev_crash_comp, sizeof(prev_crash_comp), fp) == NULL)
					{
						prev_crash_comp[0] = '\0';
					}
					LOG_RDXD_DEBUG("%s: Reading from %s, prev crash comp is %s", __func__, CRASH_COMPONENT_FILE,
					               prev_crash_comp);
					fclose(fp);
				}

				if ((prev_crash_comp[0] != '\0') &&
				        (strncmp(prev_crash_comp, spec->reportComponent, sizeof(prev_crash_comp)) == 0))
				{
					LOG_RDXD_DEBUG("%s: Found cyclic crash for component %s", __func__, black_list[i]);
					//cyclic crash detected on rdxd or uploadd
					g_set_error(error,
					            RDX_WATCH_ERROR,
					            RDX_WATCH_ERROR_CYCLIC_CRASH,
					            "%s: Cyclic crash of %s detected, not reporting on it", __func__,
					            black_list[i]);
					mark_as_seen(crash_path, false, error);
					goto cleanup;
				}
			}
		}

		if (g_file_test(CRASH_COMPONENT_FILE, G_FILE_TEST_EXISTS))
		{
			if (g_remove(CRASH_COMPONENT_FILE) != 0)
			{
				LOG_RDXD_DEBUG("%s: g_remove failed for %s", __func__, CRASH_COMPONENT_FILE);
			}
		}

		fp = fopen(CRASH_COMPONENT_FILE, "w");
		if (fp)
		{
			LOG_RDXD_DEBUG("%s: Writing to %s, the component %s", __func__, CRASH_COMPONENT_FILE,
			               spec->reportComponent);
			fputs(spec->reportComponent, fp);
			fclose(fp);
		}
	}

	ret = sReportCB(spec, error);

cleanup:
	PMLOG_TRACE("%s: Now in cleanup", __func__);
	g_free(crash_path);
	free_report_spec(spec);

	return ret;
}

/**
 * @brief trigger_was_seen
 *
 * Determines if the crash trigger was already processed by
 * remote diagnostics.
 *
 * @param filename
 *
 * @return
 */
static bool
trigger_was_seen(const char *filename)
{
	return (g_str_has_prefix(filename, RDXD_CRASH_PREFIX));
}

/**
 * @brief report_on_all_strays
 *
 * This will look for strayed crashes, i.e crashes that occured while rdxd was down, and hence
 * not able to accurately correlate the crash to a specific set of logs.  We will report on these
 * anyways but the crash log may not be totally accurate
 *
 */
static void report_on_all_strays()
{
	LOG_RDXD_DEBUG("%s: called", __func__);
	GDir *dp = NULL;
	GError *error = NULL;
	const gchar *d = NULL;

	dp = g_dir_open(RDXD_LIBRDX_TRIGGER_PATH, 0, &error);

	if (dp == NULL)
	{
		if (error)
		{
			LOG_RDXD_ERROR(MSGID_TRIGGER_PATH_OPEN_ERR, 2, PMLOGKS(PATH,
			               RDXD_LIBRDX_TRIGGER_PATH),
			               PMLOGKS(ERRTEXT, error->message), "cannot open trigger path");
			g_error_free(error);
		}
		else
		{
			LOG_RDXD_ERROR(MSGID_TRIGGER_PATH_OPEN_ERR, 2, PMLOGKS(PATH,
			               RDXD_LIBRDX_TRIGGER_PATH),
			               PMLOGKS(REASON, "UNKNOWN"), "cannot open trigger path");
		}

		return;
	}

	for (;;)
	{
		d = g_dir_read_name(dp);

		if (d == NULL)
		{
			break;
		}

		// Make sure we havent already processed this crash file
		if (trigger_was_seen(d))
		{
			continue;
		}

		error = NULL;

		if (!report(d, &error))
		{
			if (error != NULL)
			{
				gchar *errmsg = g_strescape(error->message, NULL);
				gchar *escaped_errmsg = g_strescape(errmsg, NULL);
				LOG_RDXD_WARNING(MSGID_REPORT_CREATE_ERR, 2,
				                 PMLOGKS(PATH, RDXD_LIBRDX_TRIGGER_PATH),
				                 PMLOGKS(ERRTEXT, escaped_errmsg), "could not create report");
				g_free(errmsg);
				g_free(escaped_errmsg);
			}
			else
			{
				LOG_RDXD_WARNING(MSGID_REPORT_CREATE_ERR, 2,
				                 PMLOGKS(PATH, RDXD_LIBRDX_TRIGGER_PATH),
				                 PMLOGKS(REASON, "UNKNOWN"), "could not create report");
			}
		}

		if (error)
		{
			g_error_free(error);
		}
	}

	g_dir_close(dp);
}

/**
 * @brief handle_new_crash
 *
 * A function that is called when one of the dump
 * directories changes.  This is registered with
 * g_io_add_watch
 *
 * @param source
 * @param condition
 * @param data
 *
 * @return
 */
static gboolean
handle_new_crash(GIOChannel *source, GIOCondition condition, gpointer data)
{
	GIOStatus status;
	struct inotify_event event;
	gsize size;
	char *name = NULL;
	GError *err = NULL;

	// for every crash
	LOG_RDXD_DEBUG("%s: got condition %d", __func__, condition);

	while (condition & G_IO_IN)
	{
		status = g_io_channel_read_chars(source, (char *) &event,
		                                 sizeof(struct inotify_event), &size, &err);

		if (status == G_IO_STATUS_EOF)
		{
			return true;
		}

		if (status == G_IO_STATUS_ERROR && NULL != err)
		{
			LOG_RDXD_WARNING(MSGID_INOTIFY_EVENT_READ_ERR, 1, PMLOGKS(ERRTEXT, err->message),
			                 "error reading inotify event");
			goto error;
		}
		else if (status != G_IO_STATUS_NORMAL)
		{
			LOG_RDXD_WARNING(MSGID_INOTIFY_EVENT_READ_STATUS, 1, PMLOGKFV(STATUS, "%d",
			                 status), "");
			goto error;
		}

		if (event.len)
		{
			name = g_new(char, event.len + 1);
			name[event.len] = '\0';

			status = g_io_channel_read_chars(source, name, event.len, &size, &err);

			if (status == G_IO_STATUS_ERROR && NULL != err)
			{
				LOG_RDXD_WARNING(MSGID_INOTIFY_NAME_READ_ERR, 1, PMLOGKS(ERRTEXT, err->message),
				                 "error reading inotify name");
				goto error;
			}
			else if (status != G_IO_STATUS_NORMAL)
			{
				LOG_RDXD_WARNING(MSGID_INOTIFY_NAME_READ_STATUS, 1, PMLOGKFV(STATUS, "%d",
				                 status), "");
				goto error;
			}
		}

		LOG_RDXD_DEBUG("%s: got event mask 0x%x", __func__, event.mask);

		if (event.mask & (IN_CLOSE_WRITE | IN_MOVED_TO))
		{
			LOG_RDXD_DEBUG("%s: got event in IN_CLOSE_WRITE name='%s'", __func__, name);

			if (trigger_was_seen(name))
			{
				LOG_RDXD_DEBUG("%s: ignoring %s has already been seen.", __func__, name);
			}
			else
			{
				if (!report(name, &err))
				{
					if (err)
					{
						gchar *errmsg = g_strescape(err->message, NULL);
						gchar *escaped_errmsg = g_strescape(errmsg, NULL);
						LOG_RDXD_ERROR(MSGID_WATCH_TRIGGER_REPORT_ERR, 1, PMLOGKS(ERRTEXT,
						               escaped_errmsg),
						               "could not create watch trigger report");
						g_free(errmsg);
						g_free(escaped_errmsg);
						g_error_free(err);
						err = NULL;
					}
					else
					{
						LOG_RDXD_ERROR(MSGID_WATCH_TRIGGER_REPORT_ERR, 1, PMLOGKS(REASON, "UNKNOWN"),
						               "could not create watch trigger report for unknown reason");
					}
				}
			}

		}
		else if (event.mask & IN_DELETE_SELF)
		{
			LOG_RDXD_WARNING(MSGID_WATCH_FILE_DELETED, 1, PMLOGKS(PATH,
			                 RDXD_LIBRDX_TRIGGER_PATH),
			                 "watched file was deleted. Regenerating");
			WTFini();
			WTInit(NULL);
			break;
		}
		else
		{
			LOG_RDXD_DEBUG("%s: got event mask=0x%08X name='%s'", __func__, event.mask,
			               name);
		}


		condition = g_io_channel_get_buffer_condition(source);
		g_free(name);
		name = NULL;
	}

error:

	if (err != NULL)
	{
		g_error_free(err);
	}
	g_free(name);

	return TRUE;
}

/**
 * @brief WTInit
 *
 * Parse the given config file and setup the inotify channel (and the corresponding watches)
 *
 * @param report_cb
 */
void
WTInit(WTReportFunc report_cb)
{
	LOG_RDXD_DEBUG("%s: called", __func__);
	GIOChannel *inotify_channel;

	if (report_cb)
	{
		sReportCB = report_cb;
	}

	g_assert(sReportCB);

	// see http://www.linuxjournal.com/article/8478 for a description
	// of the read buffering approach.

	sINotifyFD = inotify_init();

	if (sINotifyFD == -1)
	{
		LOG_RDXD_ERROR(MSGID_INOTIFY_INIT_ERR, 1, PMLOGKS(ERRTEXT, strerror(errno)),
		               "");
		return;
	}

	// create directory
	if (g_mkdir_with_parents(RDXD_LIBRDX_TRIGGER_PATH, 0777) != 0)
	{
		LOG_RDXD_WARNING(MSGID_MK_LIBRDX_TRIGGER_PATH_ERR, 2, PMLOGKS(TRIGGER_PATH,
		                 RDXD_LIBRDX_TRIGGER_PATH),
		                 PMLOGKS(ERRTEXT, strerror(errno)), "could not create Trigger path");
	}

	// setup watch
	int result;
	result = inotify_add_watch(sINotifyFD, RDXD_LIBRDX_TRIGGER_PATH,
	                           IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE_SELF);

	if (result == -1)
	{
		LOG_RDXD_ERROR(MSGID_INOTIFY_ADD_WATCH_ERR, 2, PMLOGKS(PATH,
		               RDXD_LIBRDX_TRIGGER_PATH),
		               PMLOGKS(ERRTEXT, strerror(errno)), "");
	}

	// check for stray triggers
	report_on_all_strays();

	inotify_channel = g_io_channel_unix_new(sINotifyFD);
	GError *error = NULL;

	if (G_IO_STATUS_NORMAL != g_io_channel_set_encoding(inotify_channel, NULL,
	        &error))
	{
		LOG_RDXD_WARNING(MSGID_G_IO_ENCODING_ERR, 1, PMLOGKS(ERRTEXT, error->message),
		                 "g_io_channel_set_encoding error");
	}

	sEventSourceID = g_io_add_watch(inotify_channel, G_IO_IN, handle_new_crash,
	                                NULL);
	g_io_channel_unref(inotify_channel);

	if (error)
	{
		g_error_free(error);
	}
}

/**
 * @brief WTFini
 *
 * Destructor for watches.  Noop if WTInit had never been called
 */
void
WTFini()
{
	// remove the watches
	LOG_RDXD_DEBUG("%s: called", __func__);

	if (sINotifyFD > 0)
	{
		if (close(sINotifyFD) != 0)
		{
			LOG_RDXD_WARNING(MSGID_INOTIFY_CLOSE_ERR, 1, PMLOGKS(ERRTEXT, strerror(errno)),
			                 "");
		}

		sINotifyFD = 0;
	}

	if (sEventSourceID)
	{
		g_source_remove(sEventSourceID);
		sEventSourceID = 0;
	}
}
