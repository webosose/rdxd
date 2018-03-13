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
 * @file log.c
 *
 * @brief
 * logging interface.
 *
 * This is for redirecting GLib's logging commands (g_message, g_debug, g_error)
 * to the appropriate handlers
 *
 */

#include <stdio.h>
#include <glib.h>
#include <syslog.h>
#include <stdbool.h>
#include "log.h"
//include <PmLogLib.h>
//
//TODO: may want to use PmLogLib

static int sLogLevel = G_LOG_LEVEL_DEBUG;

static LOGHandler sHandler = LOGGlibLog;

/**
 * @brief LOGSetLevel
 *
 * @param level
 */
void
LOGSetLevel(int level)
{
	// asserting this is a log level
	g_assert((level & G_LOG_LEVEL_MASK) != 0);
	g_assert((level | G_LOG_LEVEL_MASK) == G_LOG_LEVEL_MASK);
	sLogLevel = level;

}

/*
int LOGGetLevel()
{
    return sLogLevel;
}
*/

/**
 * @brief logFilter
 * filter we use to redirect glib's messages
 *
 * @param log_domain
 * @param log_level
 * @param message
 * @param unused_data
 */
static void
logFilter(const gchar *log_domain, GLogLevelFlags log_level,
          const gchar *message, gpointer unused_data)
{
	if (log_level > sLogLevel)
	{
		return;
	}

	g_assert(sHandler < LOG_NUM_HANDLERS);
	g_assert(sHandler >= 0);

	int priority;

	switch (sHandler)
	{
		case LOGSyslog:

			switch (log_level & G_LOG_LEVEL_MASK)
			{
				case G_LOG_LEVEL_ERROR:
					priority = LOG_CRIT;
					break;

				case G_LOG_LEVEL_CRITICAL:
					priority = LOG_ERR;
					break;

				case G_LOG_LEVEL_WARNING:
					priority = LOG_WARNING;
					break;

				case G_LOG_LEVEL_MESSAGE:
					priority = LOG_NOTICE;
					break;

				case G_LOG_LEVEL_DEBUG:
					priority = LOG_DEBUG;
					break;

				case G_LOG_LEVEL_INFO:
				default:
					priority = LOG_INFO;
					break;
			}

			syslog(priority, "%s", message);
			break;

		case LOGGlibLog:
			g_log_default_handler(log_domain, log_level, message, unused_data);
			break;

		/*
		case LOGPmLogLib:
			switch (log_level & G_LOG_LEVEL_MASK)
			{
				case G_LOG_LEVEL_ERROR:
					priority = kPmLogLevel_Error;
					break;
				case G_LOG_LEVEL_CRITICAL:
					priority = kPmLogLevel_Critical;
					break;
				case G_LOG_LEVEL_WARNING:
					priority = kPmLogLevel_Warning;
					break;
				case G_LOG_LEVEL_MESSAGE:
					priority = kPmLogLevel_Notice;
					break;
				case G_LOG_LEVEL_DEBUG:
					priority = kPmLogLevel_Debug;
					break;
				case G_LOG_LEVEL_INFO:
				default:
					priority = kPmLogLevel_Info;
					break;
			}
			(void) PmLogPrint(kPmLogGlobalContext, priority, message);
			break;
		*/

		default:
			fprintf(stderr, "%s: no handler %d for log message\n", __func__, sHandler);
			abort();
	}
}

/**
 * @brief LOGSetHandler
 *
 * @param h
 */
void
LOGSetHandler(LOGHandler h)
{
	g_assert(h < LOG_NUM_HANDLERS);
	g_assert(h >= 0);
	sHandler = h;
}

/**
 * @brief LOGInit
 */
void
LOGInit()
{
	g_log_set_default_handler(logFilter, NULL);
}
