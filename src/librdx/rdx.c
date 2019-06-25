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
 * @file rdx.c
 *
 * @brief a wrapper around logging an rdx report
 *
 */

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <rdx.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include "librdxlog.h"

#define RDX_FOLDER_PATH WEBOS_INSTALL_LOGDIR "/reports/librdx"
#define RDX_PENDING_UPLOAD_FOLDER WEBOS_INSTALL_LOGDIR "/rdxd/pending"
#define RDX_TEMP_PATH WEBOS_INSTALL_LOGDIR "/temp/librdx"
//TODO: these two defines should be shared with rdxd
#define RDX_SEEN_PREFIX "RDXD"
#define RDX_NUM_TRIGGERS_TO_KEEP 5
#define RDX_MAX_PENDING_REPORTS 100

struct rdx_report_metadata_t
{
	char *component;
	char *cause;
	char *detail;
	char *filename;
};

#define PREVENT_CHAR(string, prevent) \
    if (NULL != strchr(string, prevent)) { \
        LOG_LIBRDX_WARNING(MSGID_INVALID_CHAR_ERR, 0, "character '0x%02X' is not permitted",prevent); \
        return false; \
    }

#define MAX_MD_LENGTH 256

static bool
_set_md_parameter(RdxReportMetadata md, char **parameter, const char *new_val)
{
	g_return_val_if_fail(md, false);
	g_return_val_if_fail(new_val, false);
	g_assert(parameter != NULL);

	// we prevent /, and some control characters we're using
	PREVENT_CHAR(new_val, 1); // used to seperate metadata in filename
	PREVENT_CHAR(new_val, 2); // used to replace '/' in filename
	PREVENT_CHAR(new_val, 3); // used to replace '"' in filename
	PREVENT_CHAR(new_val, '\n'); // newlines not permitted

	if (strlen(new_val) > MAX_MD_LENGTH)
	{
		LOG_LIBRDX_ERROR(MSGID_METADATA_LEN_TOO_LONG, 2, PMLOGKFV(MD_MAX_LENGTH, "%d",
		                 MAX_MD_LENGTH),
		                 PMLOGKFV(MD_LENGTH, "%zu", strlen(new_val)), "");
		return false;
	}

	if (*parameter)
	{
		g_free(*parameter);
	}

	*parameter = g_strdup(new_val);

	// Have to replace / with ^B so that we can place it in filename
	// TODO: no longer use filenames to house metadata
	int i = 0;

	for (i = 0; i < strlen(*parameter); i++)
	{
		if ((*parameter)[i] == '/')
		{
			(*parameter)[i] = 2;
		}

		if ((*parameter)[i] == '"')
		{
			(*parameter)[i] = 3;
		}
	}

	return true;
}

bool
rdx_report_metadata_set_component(RdxReportMetadata md, const char *component)
{
	return _set_md_parameter(md, &(md->component), component);
}

bool
rdx_report_metadata_set_cause(RdxReportMetadata md, const char *cause)
{
	return _set_md_parameter(md, &(md->cause), cause);
}

bool
rdx_report_metadata_set_detail(RdxReportMetadata md, const char *detail)
{
	return _set_md_parameter(md, &(md->detail), detail);
}

bool
rdx_report_metadata_set_payload_filename(RdxReportMetadata md,
        const char *filename)
{
	/* TODO: need to do error checking on filename.. we need
	 * to make sure they dont use a filename that is used in context logs
	 */
	return _set_md_parameter(md, &(md->filename), filename);
}

RdxReportMetadata
create_rdx_report_metadata()
{
	RdxReportMetadata ret = g_new0(struct rdx_report_metadata_t, 1);

	return ret;
}

bool
destroy_rdx_report_metadata(RdxReportMetadata md)
{
	g_return_val_if_fail(md != NULL, false);
	g_free(md->component);
	g_free(md->cause);
	g_free(md->detail);
	g_free(md);
	return true;
}

/**
 * @brief secure_mkstemp
 *
 * A wrapper for mkstemp command that sets and resets the umask
 *
 * Generate a unique temporary file name from TEMPLATE.
 * The last six characters of TEMPLATE must be "XXXXXX";
 * they are replaced with a string that makes the filename unique.
 * Returns a file descriptor open on the file for reading and writing,
 * or -1 if it cannot create a uniquely-named fi
 *
 * This function is a possible cancellation points and therefore not
 * marked with __THROW.
 *
 * @param __template
 *
 * @return the file descriptor on success; -1 on failure.
 */
static int
secure_mkstemp(char *template)
{
	//TODO: once we support glib 2.22 move to g_mkstemp_full
	int fd;
        umask(0022);
	fd = mkstemp(template);
        if(fd >= 0)
            fchmod(fd, 0666);
	return fd;
}

time_t
get_modified_date(const gchar *filename)
{
	g_return_val_if_fail(filename, 0);

	gchar *path = g_build_filename(RDX_FOLDER_PATH, filename, NULL);
	time_t ret;
	struct stat s;

	if (0 == stat(path, &s))
	{
		ret = s.st_mtime;
	}
	else
	{
		LOG_LIBRDX_WARNING(MSGID_GET_MOD_DATE_ERR, 3, PMLOGKS(PATH, path),
		                   PMLOGKFV(ERRCODE, "%d", errno),
		                   PMLOGKS(ERRTEXT, strerror(errno)), "");
		ret = LONG_MAX;
	}

	g_free(path);
	return ret;
}

/**
 * @brief rdx_file_compare_func
 * sorts them in order of priority (lower is better)
 *
 * @param a
 * @param b
 * @param user_data
 *
 * @return negative value if a < b; zero if a = b; positive value if a > b.
 */
static gint
rdx_file_compare_func(gconstpointer a, gconstpointer b, gpointer user_data)
{
	g_assert(a);
	g_assert(b);


	const gchar *fa = a;
	const gchar *fb = b;
	bool sa = g_str_has_prefix(fa, RDX_SEEN_PREFIX);
	bool sb = g_str_has_prefix(fb, RDX_SEEN_PREFIX);

	if (sa && !sb)
	{
		return 1;
	}
	else if (sb && !sa)
	{
		return -1;
	}
	else
	{
		return get_modified_date(fb) - get_modified_date(fa);
	}
}

static void
delete_file_if_seen(gpointer data, gpointer user_data)
{
	g_assert(data);

	const gchar *file = data;
	int *num_removed = (int *) user_data;

	if (g_str_has_prefix(file, RDX_SEEN_PREFIX))
	{
		gchar *path = g_build_filename(RDX_FOLDER_PATH, file, NULL);
		LOG_LIBRDX_DEBUG("%s: removing %s", __func__, path);
		if (g_remove(path) !=0)
		{
			LOG_LIBRDX_DEBUG("%s: g_remove failed for %s", __func__, path);
		}
		g_free(path);
		(*num_removed)++;
	}
}

/**
 * @brief make_room_for_new_trigger
 * both tiddies up (nukes old seen reports) and then returns wether theres room for more
 *
 * TODO: serialize this.  Note we have no mutex here so potentially we could have problems:
 * - rdxd could change a file underneath us, altering our cleanup logic
 * - another librdx process could call make_room at the same time, leading to conflicts
 *
 * @return true iff theres room for more reports
 */
bool
make_room_for_new_trigger()
{
	GSequence *sorted_files = g_sequence_new(g_free);
	GDir *rdx_folder = g_dir_open(RDX_FOLDER_PATH , 0, NULL);

	// no rdx folder.. rdxd must not have started yet.. hence to my knowledge theres room
	if (!rdx_folder)
	{
		LOG_LIBRDX_WARNING(MSGID_RDX_DIR_OPEN_ERR, 1, PMLOGKS(PATH, RDX_FOLDER_PATH),
		                   "cannot open rdx directory");
		return true;
	}

	const gchar *file_name;

	while ((file_name = g_dir_read_name(rdx_folder)))
	{
		g_sequence_append(sorted_files, g_strdup(file_name));
	}

	g_dir_close(rdx_folder);

	g_sequence_sort(sorted_files, rdx_file_compare_func, NULL);

	GSequenceIter *bit = g_sequence_get_iter_at_pos(sorted_files,
	                     RDX_NUM_TRIGGERS_TO_KEEP - 1);
	GSequenceIter *eit = g_sequence_get_end_iter(sorted_files);
	int num_removed = 0;
	g_sequence_foreach_range(bit, eit, delete_file_if_seen, &num_removed);

	// determine if were full.. do we have at least one RDXD prefixed one we can remove
	int num_existing = (g_sequence_get_length(sorted_files) - num_removed);
	g_sequence_free(sorted_files);

	if (num_existing >= RDX_NUM_TRIGGERS_TO_KEEP)
	{
		LOG_LIBRDX_ERROR(MSGID_RDX_TRIGGERS_ERR, 2, PMLOGKFV(RDX_EXISTING_TRIGGERS,
		                 "%d", num_existing),
		                 PMLOGKFV(NUM_TRIGGERS_TO_KEEP, "%d", RDX_NUM_TRIGGERS_TO_KEEP),
		                 "Too many existing rdx-triggers");
	}

	return (num_existing < RDX_NUM_TRIGGERS_TO_KEEP);
}

static bool
have_room_for_more_rdx_reports()
{
	GDir *rdx_folder = g_dir_open(RDX_PENDING_UPLOAD_FOLDER, 0, NULL);

	// folder doesnt exist yet.. rdxd will do that
	if (!rdx_folder)
	{
		return true;
	}

	int count = 0;

	while (g_dir_read_name(rdx_folder))
	{
		count++;
	}

	g_dir_close(rdx_folder);

	return (count <= RDX_MAX_PENDING_REPORTS);
}

static bool IsStatsZeroIfUnlimited()
{

    struct statfs stats;

    if (statfs(WEBOS_INSTALL_LOGDIR, &stats) != 0)
        return false;

    switch (stats.f_type) {
        case TMPFS_MAGIC:
        case RAMFS_MAGIC:
            return true;
    }
    return false;
}

// 40K needed
#define RDX_MIN_DISK_SPACE_NEEDED 40960

static bool
have_enough_disk_space(unsigned long payload_size)
{
    struct statvfs fs;

    if ((statvfs(WEBOS_INSTALL_LOGDIR, &fs)) < 0)
    {
        LOG_LIBRDX_ERROR(MSGID_LOGDIR_STAT_ERR, 1, PMLOGKS(ERRTEXT, strerror(errno)),
            "STAT call failed");
        // assuming not enough space
        return false;
    }
    else
    {
        //do not have to check disk space in ramfs or tempfs
        if ((fs.f_bavail == 0) && (IsStatsZeroIfUnlimited())) return true;
        const unsigned long avail = (fs.f_bavail * (unsigned long)fs.f_bsize);
        return (avail >= (RDX_MIN_DISK_SPACE_NEEDED + payload_size));
    }

}

/**
 * @brief rdx_make_report_from_file
 *
 * @param md the metadata
 * @param path the path to the payload
 *
 * @return
 */
bool
rdx_make_report_from_file(RdxReportMetadata md, const char *path)
{

	bool ret = false;
	FILE *src_file = NULL;
	int dest_fd = -1;

	g_return_val_if_fail(md, false);
	g_return_val_if_fail(md->component, false);

	if (!g_file_test(path, G_FILE_TEST_IS_REGULAR))
	{
		LOG_LIBRDX_ERROR(MSGID_NO_PATH_FOUND, 2, PMLOGKS(PATH, path), PMLOGKS(IMPACT,
		                 "Cannot create rdx report from file"), "");
		return false;
	}

	struct stat s;

        src_file = fopen(path, "r");

        if (!src_file)
        {
                LOG_LIBRDX_ERROR(MSGID_FOPEN_ERR, 4, PMLOGKS(PATH, path), PMLOGKFV(ERRCODE,
                                 "%d", errno),
                                 PMLOGKS(ERRTEXT, strerror(errno)), PMLOGKS(IMPACT,
                                         "Cannot create rdx report from file"), "");
                return false;
        }

	if (-1 == stat(path, &s))
	{
		LOG_LIBRDX_ERROR(MSGID_REPORT_FILE_STAT_ERR, 3, PMLOGKFV(ERRCODE, "%d", errno),
		                 PMLOGKS(ERRTEXT, strerror(errno)),
		                 PMLOGKS(IMPACT, "Cannot create rdx report from file"), "");
                fclose(src_file);
		return false;
	}

	if (0 == (S_IFREG & s.st_mode))
	{
		LOG_LIBRDX_ERROR(MSGID_REGULAR_FILE_CHK_ERR, 1, PMLOGKS(IMPACT,
		                 "Cannot create rdx report from file"),
		                 "wrong st_mode: %u", s.st_mode);
                fclose(src_file);
		return false;
	}

#define RDX_MAX_CRASH_BYTES 10000000 // 10MB

	if (s.st_size >= RDX_MAX_CRASH_BYTES)
	{
		LOG_LIBRDX_ERROR(MSGID_REPORT_FILE_SIZE_ERR, 3, PMLOGKS(PATH, path),
		                 PMLOGKFV(FILE_SIZE, "%ld", s.st_size),
		                 PMLOGKS(IMPACT, "Cannot create rdx report from file"), "File too large");
                fclose(src_file);
		return false;
	}

	if (!have_room_for_more_rdx_reports())
	{
		LOG_LIBRDX_ERROR(MSGID_MAX_REPORTS_LIMIT_REACHED, 1, PMLOGKS(IMPACT,
		                 "Cannot create rdx report from file"),
		                 "no room for new reports");
                fclose(src_file);
		return false;
	}

	if (!make_room_for_new_trigger())
	{
		LOG_LIBRDX_ERROR(MSGID_NEW_REPORT_TRIGGER_ERR, 1, PMLOGKS(IMPACT,
		                 "Cannot create rdx report from file"),
		                 "no room for new report triggers");
                fclose(src_file);
		return false;
	}

	if (!have_enough_disk_space(s.st_size))
	{
		LOG_LIBRDX_ERROR(MSGID_NEW_REPORTS_SPACE_ERR, 1, PMLOGKS(IMPACT,
		                 "Cannot create rdx report from file"),
		                 "not enough disk space for new reports");
                fclose(src_file);
		return false;
	}

	if (-1 == g_mkdir_with_parents(RDX_FOLDER_PATH, 0777))
	{
		LOG_LIBRDX_ERROR(MSGID_CREATE_RDX_FOLDER_ERR, 4, PMLOGKS(PATH, RDX_FOLDER_PATH),
		                 PMLOGKFV(ERRCODE, "%d", errno),
		                 PMLOGKS(ERRTEXT, strerror(errno)), PMLOGKS(IMPACT,
		                         "Cannot create rdx report from file"), "");
                fclose(src_file);
		return false;
	}

	gchar *template_file_name = NULL;
	gchar *template_file_name_ex = NULL;

	template_file_name = g_strdup_printf("%s__%s__%s__%s.XXXXXX",
	                                     md->component,
	                                     md->cause ? md->cause : "",
	                                     md->detail ? md->detail : "",
	                                     md->filename ? md->filename : "payload");

	template_file_name_ex =  g_strdup_printf("%s\x0001%s\x0001%s\x0001%s",
	                         md->component,
	                         md->cause ? md->cause : "",
	                         md->detail ? md->detail : "",
	                         md->filename ? md->filename : "payload");

	gchar *dest_path = g_build_filename(RDX_FOLDER_PATH, template_file_name, NULL);

	//TODO: uniqueness in name in temp folder doesnt guarantee
	//uniqueness of name in the librdx folder
	dest_fd = secure_mkstemp(dest_path);

        if (dest_fd == -1)
        {
            if (errno == ENAMETOOLONG)
            {
                gchar *template_file_simple_name = NULL;
                char simple_cause[NAME_MAX / 2] = {0, };
                snprintf(simple_cause, sizeof(simple_cause), "%s", md->cause);
                template_file_simple_name = g_strdup_printf("%s__%s__%s__%s.XXXXXX",
                                            md->component,
                                            simple_cause,
                                            md->detail ? md->detail : "",
                                            md->filename ? md->filename : "payload");
                // retry with short name ( template should be less than NAME_MAX(256) )
                g_free(dest_path);
                dest_path = g_build_filename(RDX_FOLDER_PATH, template_file_simple_name, NULL);
                if((dest_fd = secure_mkstemp(dest_path)) == -1)
                {
                    LOG_LIBRDX_ERROR(MSGID_REPORT_FILE_CREATE_ERR, 3, PMLOGKFV(ERRCODE, "%d",
                                     errno), PMLOGKS(ERRTEXT, strerror(errno)),
                                     PMLOGKS(IMPACT, "Cannot create rdx report from file"),
                                     "secure temp file create error");
                    g_free(template_file_simple_name);
                    goto end;
                }
                g_free(template_file_simple_name);
            }
            else
            {
                LOG_LIBRDX_ERROR(MSGID_REPORT_FILE_CREATE_ERR, 3, PMLOGKFV(ERRCODE, "%d",
                                 errno), PMLOGKS(ERRTEXT, strerror(errno)),
                                 PMLOGKS(IMPACT, "Cannot create rdx report from file"),
                                 "secure temp file create error");
                goto end;
            }
        }

	// copy data from src to dest
	{
		ret = true;
		char buf[1024];
		ssize_t rb = 0;
		ssize_t wb = 0;
		ssize_t tot = 0;

		while (!feof(src_file))
		{
			rb = fread(buf, 1, sizeof(buf), src_file);

			if (rb <= 0)
			{
				if (ferror(src_file))
				{
					LOG_LIBRDX_WARNING(MSGID_FREAD_ERR, 3, PMLOGKS(PATH, path), PMLOGKFV(ERRCODE,
					                   "%d", errno),
					                   PMLOGKS(ERRTEXT, strerror(errno)), "could not read file");
					ret = false;
					break;
				}
				else
				{
					//eof
					continue;
				}
			}

			// write contents
			wb = write(dest_fd, buf, rb);

			if (wb != rb)
			{
				LOG_LIBRDX_WARNING(MSGID_FWRITE_ERR, 2, PMLOGKFV(ERRCODE, "%d", errno),
				                   PMLOGKS(ERRTEXT, strerror(errno)), "Write to secure tmp failed");
				ret = false;
				break;
			}

			tot += wb;

			if (tot >= RDX_MAX_CRASH_BYTES)
			{
				LOG_LIBRDX_WARNING(MSGID_TMP_FILE_SIZE_ERR, 2, PMLOGKS(PATH, path),
				                   PMLOGKS(IMPACT, "Cannot create rdx report from file"),
				                   "Tmp File size too large");
				ret = false;
				break;
			}
		}

		//write meta data
		size_t len = strlen(template_file_name_ex);

		wb = write(dest_fd, template_file_name_ex, len);
		wb += write(dest_fd, &len, sizeof(size_t));

		if (wb != len + sizeof(size_t))
		{
			LOG_LIBRDX_ERROR(MSGID_MD_WRITE_ERR, 3, PMLOGKFV(BYTES_READ, "%zu",
			                 len + sizeof(size_t)),
			                 PMLOGKFV(BYTES_WRITTEN, "%zd", wb), PMLOGKS(IMPACT,
			                         "Cannot create rdx report from file"),
			                 "Metadata write failed");
			ret = false;
		}

		close(dest_fd);

		if (!ret)
		{
			LOG_LIBRDX_ERROR(MSGID_RDX_REPORT_ERR, 1, PMLOGKS(IMPACT,
			                 "Cannot create rdx report from file"),
			                 "failed to create a rdx report");
			if (g_remove(dest_path) != 0)
			{
				LOG_LIBRDX_DEBUG("%s: g_remove failed for %s", __func__, dest_path);
			}
		}
	}

end:

	if (src_file != NULL)
	{
		fclose(src_file);
	}

	g_free(template_file_name);
	g_free(template_file_name_ex);
	g_free(dest_path);

	return ret;

}

/**
 * @brief rdx_make_report
 *
 * @param component
 * @param cause
 * @param detail
 * @param payload the contents of the payload
 *
 * @return
 */
bool
rdx_make_report(RdxReportMetadata md, const char *contents)
{
	bool ret = false;
	g_return_val_if_fail(md, false);
	g_return_val_if_fail(md->component, false);

	if (-1 == g_mkdir_with_parents(RDX_TEMP_PATH, 0x755))
	{
		LOG_LIBRDX_ERROR(MSGID_RDX_TEMP_PATH_ERR, 3, PMLOGKS(PATH, RDX_TEMP_PATH),
		                 PMLOGKFV(ERRCODE, "%d", errno), PMLOGKS(ERRTEXT, strerror(errno)),
		                 "RDX_TEMP_PATH create failed");
		return false;
	}

	if (!have_room_for_more_rdx_reports())
	{
		LOG_LIBRDX_ERROR(MSGID_MAX_PENDING_REPORTS_ERR, 0, "no room for new reports");
		return false;
	}

	if (!make_room_for_new_trigger())
	{
		LOG_LIBRDX_ERROR(MSGID_TRIGGER_LIMIT_REACHED, 0,
		                 "no room for new report triggers");
		return false;
	}

	const long contents_len = contents ? strlen(contents) : 0;

	if (!have_enough_disk_space(contents_len * sizeof(*contents)))
	{
		LOG_LIBRDX_ERROR(MSGID_NO_DISK_SPACE, 0,
		                 "not enough disk space for new reports");
		return false;
	}

	gchar *template_file_name = NULL;
	gchar *template_file_name_ex = NULL;

	template_file_name = g_strdup_printf("%s__%s__%s__%s.XXXXXX",
	                                     md->component,
	                                     md->cause ? md->cause : "",
	                                     md->detail ? md->detail : "",
	                                     md->filename ? md->filename : "payload");
	template_file_name_ex =  g_strdup_printf("%s\x0001%s\x0001%s\x0001%s",
	                         md->component,
	                         md->cause ? md->cause : "",
	                         md->detail ? md->detail : "",
	                         md->filename ? md->filename : "payload");

	gchar *temp_path = g_build_filename(RDX_TEMP_PATH, template_file_name, NULL);
	gchar *dest_path = NULL;
	gchar *temp_filename = NULL;
	size_t len = 0;
	ssize_t wb = 0;

	//TODO: uniqueness in name in temp folder doesnt guarantee
	//uniqueness of name in the librdx folder
	int fd = secure_mkstemp(temp_path);

	if (fd == -1)
	{
		LOG_LIBRDX_ERROR(MSGID_SECURE_TMPFILE_CREATE_ERR, 2, PMLOGKFV(ERRCODE, "%d",
		                 errno),
		                 PMLOGKS(ERRTEXT, strerror(errno)), "secure temp file create error");
		goto end;
	}

	temp_filename = g_path_get_basename(temp_path);
	dest_path = g_build_filename(RDX_FOLDER_PATH, temp_filename, NULL);
	g_free(temp_filename);

	// write contents
	if (contents)
	{
		ssize_t wb = write(fd, contents, contents_len);

		if (wb != contents_len)
		{
			LOG_LIBRDX_ERROR(MSGID_CONTENTS_WRITE_ERR, 2, PMLOGKFV(ERRCODE, "%d", errno),
			                 PMLOGKS(ERRTEXT, strerror(errno)), "Payload contents write failed");
			close(fd);
			if (g_remove(temp_path) != 0) {
				LOG_LIBRDX_DEBUG("%s: g_remove failed for %s", __func__, temp_path);
			}
			goto end;
		}
	}

	//write meta data
	len = strlen(template_file_name_ex);

	wb = write(fd, template_file_name_ex, len);
	wb += write(fd, &len, sizeof(size_t));

	if (wb != len + sizeof(size_t))
	{
		LOG_LIBRDX_ERROR(MSGID_MD_WRITE_ERR, 2, PMLOGKFV(BYTES_READ, "%zu",
		                 len + sizeof(size_t)),
		                 PMLOGKFV(BYTES_WRITTEN, "%zd", wb), "Metadata write failed");
		ret = false;
	}

	close(fd);

	if (-1 == g_mkdir_with_parents(RDX_FOLDER_PATH, 0777))
	{
		LOG_LIBRDX_ERROR(MSGID_CREATE_RDX_FOLDER_ERR, 3, PMLOGKS(PATH, RDX_FOLDER_PATH),
		                 PMLOGKFV(ERRCODE, "%d", errno), PMLOGKS(ERRTEXT, strerror(errno)), "");
		if (g_remove(temp_path) != 0)
		{
			LOG_LIBRDX_DEBUG("%s: g_remove failed for %s", __func__, temp_path);
		}
		goto end;
	}

	if (-1 == rename(temp_path, dest_path))
	{
		LOG_LIBRDX_ERROR(MSGID_PATH_RENAME_ERR, 2, PMLOGKFV(ERRCODE, "%d", errno),
		                 PMLOGKS(ERRTEXT, strerror(errno)), "");
		if (g_remove(temp_path) != 0)
		{
			LOG_LIBRDX_DEBUG("%s: g_remove failed for %s", __func__, temp_path);
		}
	}
	else
	{
		ret = true;
	}

end:
	g_free(temp_path);
	g_free(template_file_name);
	g_free(dest_path);
	g_free(template_file_name_ex);

	return ret;
}
