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
 * @file contextlogs.c
 *
 * @brief
 * When a crash occurs, some logs are gathered in addition
 * to the crash data.  These additional logs help provide some
 * context to the report to help figure out why the report needed
 * to be made.  This data is managed here.
 *
 * context logs are produced by running a given command (usually a script)
 * and naming the output.  Context logs also need a format (e.g "text, indexed")
 * that is used by the server to determine how to store the data
 *
 */

#include "contextlogs.h"
#include "util.h"
#include "logging.h"


static ContextLogType sOverviewCL; // context log settings for the overview
static ContextLogType sSysInfoCL; // system dynamic info context
static ContextLogType sFilterCL; // filter command

/**
 * @brief Filter logs from sensitive information
 *
 * @param file_name name of the archive with logs
 *
 * @return transformed logs archive file path, if success
 */
char *
CLFilterLogs(const char *file_path)
{
	gchar *output = NULL;
	gchar *cmd = g_strdup_printf("%s \"%s\"", sFilterCL.makeCmd, file_path);
	if (cmd)
	{
		if (!run_script(cmd, &output))
		{
			g_free(output);
			output = NULL;
		}
		g_free(cmd);
	}
	return output;
}

/**
 * @brief CLCreateOverview
 *
 * This will create starting overview
 *
 * @param file_path overview file path for overview file
 *
 * @return
 */
bool
CLCreateOverview(const char *file_path)
{
	g_assert(file_path != NULL);
	gchar *cmd = g_strdup_printf("%s \"%s\" \"\"", sOverviewCL.makeCmd, file_path);

	LOG_RDXD_DEBUG("%s: running %s", __func__, cmd);
	bool ret = run_script(cmd, NULL);

	g_free(cmd);

	return ret;
}

/**
 * @brief CLDumpSysInfo
 *
 * This will dump system state snapshot
 *
 * @param file_path file path to write sysinfo dump
 *
 * @return
 */
bool
CLDumpSysInfo(const char *file_path)
{
	g_assert(file_path != NULL);
	gchar *cmd = g_strdup_printf("%s \"%s\"", sSysInfoCL.makeCmd, file_path);

	LOG_RDXD_DEBUG("%s: running %s", __func__, cmd);
	bool ret = run_script(cmd, NULL);

	g_free(cmd);

	return ret;
}

/**
 * @brief CLInit
 *
 * Initializer,
 * 1. parse the given config_file to populate our list of
 * context log settings
 * 2. Setup whatever callbacks we need using sh and main_loop
 *
 * @param sh
 * @param main_loop
 * @param config_file
 */
void
CLInit(LSHandle *sh, GMainLoop *main_loop, GKeyFile *config_file)
{
	gsize num_groups = 0;
	gchar **groups = g_key_file_get_groups(config_file, &num_groups);

	const char *group_pfx = "CONTEXTLOG=";
	int group_pfx_len = strlen(group_pfx);
	const char *group_sfx = NULL;
	ContextLogType *cl;

	for (int i = 0; i < num_groups; i++)
	{
		// only care about Watch section
		if (g_str_has_prefix(groups[i], group_pfx))
		{
			group_sfx = &(groups[i][group_pfx_len]);
			// fill the WatchSettings object
			if (!strcmp("sysinfo", group_sfx))
			{
				cl = &sSysInfoCL;
			}
			else if (!strcmp("overview", group_sfx))
			{
				cl = &sOverviewCL;
			}
			else if (!strcmp("filter", group_sfx))
			{
				cl = &sFilterCL;
			}
			else
			{
				LOG_RDXD_WARNING(MSGID_CONF_FILE_READ_ERR, 1,
				                 PMLOGKS(PROPERTY, group_sfx),
				                 "Unknown group suffix: %s\n", group_sfx);
				continue;
			}

			cl->name = g_strdup(group_sfx);
			cl->makeCmd = read_string_conf(config_file, groups[i], "MakeLogScript", true);
		}
	}

	g_strfreev(groups);

}
