// Copyright (c) 2008-2020 LG Electronics, Inc.
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
 * @file config.c
 *
 * @brief
 * This file contains the functions to read the .conf configuration
 * file and the preferences is luna-prefs for the main settings.  Watch
 * specific conf settings, and context log specific conf settings are read
 * by those modules themselves in their initialization.
 *
 * All settings is luna-prefs will replace those read in the conf file;
 * the conf file should be viewed as the defaults if the luna-prefs are
 * missing
 *
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <glib.h>

#include <lunaprefs.h>
#include <pbnjson.hpp>

#include "logging.h"
#include "config.h"

#define kSectionKey_RDXD	"rdxd"

#define JSON_FILE_SUFFIX_RDXD  ".json"
#define JSON_TYPE_KEY_RDXD     "type"
#define JSON_HANDLER_KEY_RDXD  "handlerURL"

using std::string;
using std::vector;

static std::vector<std::string> crashHandlers;
static std::vector<std::string> analyticsHandlers;
static std::vector<std::string> overviewHandlers;

/***********************************************************************
 * rdxd section parsing
 *
 *  Example configuration section:
 *
 *  [rdxd]
 *  AutoUpload=false
 ***********************************************************************/
/**
 * @brief ReadProps
 *
 * Read properties from .conf files and from luna prefs.
 * Luna prefs should trump settings in the conf file since the conf
 * file will be used as default only.
 *
 * @param config_file GKeyFile object to parse
 * @param autoUpload prop to read
 * @param maxPending prop to read
 *
 * @return true iff we were able to read the properties
 */
bool
ReadProps(GKeyFile *config_file, bool *autoUpload)
{
	LOG_RDXD_DEBUG("%s called", __func__);
	LPErr lerr = 0;
	LPAppHandle handle;

	lerr = LPAppGetHandle(RDXD_APP_ID, &handle);

	if (lerr !=  LP_ERR_NONE)
	{
		LOG_RDXD_ERROR(MSGID_OPEN_SYS_PROP_ERR, 2, PMLOGKS(APP_ID, RDXD_APP_ID),
		               PMLOGKFV(ERRCODE, "%d", lerr), "Couldn't open system properties");
		return false;
	}
        const char* tempName = "AutoUpload";
	typedef enum { teBool = 1, teInt } typeEnum;

	struct
	{
		typeEnum type;
		const char *name;
		const char *cat;
		bool mandatory;
		void *dest;
	} css[] =
	{
		{teBool, tempName, kSectionKey_RDXD, true, autoUpload},
		{teBool, NULL, NULL, false, NULL}
	};

	int i = 0;

	for (i = 0; css[i].name != 0; i++)
	{
		// first read the .conf file
		bool conf_set = false;
		bool is_set = false;
		GError *gerror = NULL;

		switch (css[i].type)
		{
			case teBool:
			{
				gboolean boolVal = g_key_file_get_boolean(config_file, css[i].cat, css[i].name,
				                   &gerror);

				if (!gerror)
				{
					*((bool *)css[i].dest) = boolVal;
					LOG_RDXD_DEBUG("read prop %s = %s", css[i].name, boolVal ? "true" : "false");
					conf_set = true;
				}

				break;
			}

			case teInt:
			{
				gint intVal = g_key_file_get_integer(config_file, css[i].cat, css[i].name,
				                                     &gerror);

				if (!gerror)
				{
					*((int *) css[i].dest) = intVal;
					LOG_RDXD_DEBUG("read prop %s = %d", css[i].name, intVal);
					conf_set = true;
				}

				break;
			}

			default:
			{
				LOG_RDXD_WARNING(MSGID_CONF_READ_INVALID_TYPE, 1, PMLOGKFV(TYPE, "%d",
				                 css[i].type), "");
			}
		}

		is_set = conf_set;

		if (gerror != NULL)
		{
			LOG_RDXD_WARNING(MSGID_READ_CONF_ERR, 1, PMLOGKS(ERRTEXT, gerror->message), "");
			g_error_free(gerror);
			gerror = NULL;
		}

		// read from LP
		bool lpSet = false;
		char *valTmp = NULL;
		LPErr lerr = 0;
		lerr = LPAppCopyValueString(handle, css[i].name, &valTmp);

		if (lerr == LP_ERR_NONE)
		{
			switch (css[i].type)
			{
				case teBool:
					if (!ParseBool(valTmp, (bool *) css[i].dest))
					{
						LOG_RDXD_WARNING(MSGID_LP_PARSE_BOOL, 1, PMLOGKS(PROPERTY, css[i].name),
						                 "LP property requires a boolean value");
					}
					else
					{
						lpSet = true;
						LOG_RDXD_DEBUG("read prop %s = %s", css[i].name, valTmp);
					}

					break;

				case teInt:
					if (!ParseInt(valTmp, (int *)css[i].dest))
					{
						LOG_RDXD_WARNING(MSGID_LP_PARSE_INT, 1, PMLOGKS(PROPERTY, css[i].name),
						                 "LP property requires an integer value");
					}
					else
					{
						lpSet = true;
						LOG_RDXD_DEBUG("read prop %s = %s", css[i].name, valTmp);
					}

					break;

				default:
					LOG_RDXD_WARNING(MSGID_LP_READ_INVALID_TYPE, 1, PMLOGKFV(TYPE, "%d", css[i].type), "");
			}

			is_set |= lpSet;
		}
		else if (lerr == LP_ERR_NO_SUCH_KEY)
		{
			LOG_RDXD_DEBUG("Could not find lunapref property %s", css[i].name);
		}
		else
		{
			LOG_RDXD_WARNING(MSGID_LP_READ_ERR, 2, PMLOGKS(PROPERTY, css[i].name),
			                 PMLOGKFV(ERRCODE, "%d", lerr),
			                 "error while reading lunapref property. Falling back to conf file default");
		}

		g_free(valTmp);

		// bitch if it wasnt set
		if (css[i].mandatory && (!is_set))
		{
			LOG_RDXD_ERROR(MSGID_SET_CONF_ERR, 1, PMLOGKS(PROPERTY, css[i].name),
			               "Configuration was not set");
			return false;
		}
	}

	lerr = LPAppFreeHandle(handle, false /*commit*/);

	if (lerr != LP_ERR_NONE)
	{
		LOG_RDXD_ERROR(MSGID_CLOSE_SYS_PROP_ERR, 1, PMLOGKFV(ERRCODE, "%d", lerr),
		               "Couldn't close system properties");
	}

	return true;
}

void AddReportHandler(const std::string &type, const std::string &url)
{
	LOG_RDXD_DEBUG("%s: add handler url %s for report type %s", __func__, url.c_str(), type.c_str());

	if (type.empty() || url.empty())
	{
		LOG_RDXD_WARNING(MSGID_CONF_FILE_JSON_ERR, 2,
		                 PMLOGKS(TYPE, type.c_str()),
		                 PMLOGKS(URL, url.c_str()),
		                 "Report type and handler URL should not be empty");
		return;
	}

	if (type == JSON_CONFIG_REPORT_TYPE_CRASH)
		crashHandlers.push_back(url);
	else if (type == JSON_CONFIG_REPORT_TYPE_ANALYTIC)
		analyticsHandlers.push_back(url);
	else if (type == JSON_CONFIG_REPORT_TYPE_OVERVIEW)
		overviewHandlers.push_back(url);
	else
	{
		LOG_RDXD_WARNING(MSGID_CONF_FILE_JSON_ERR, 2,
		                 PMLOGKS(TYPE, type.c_str()),
		                 PMLOGKS(URL, url.c_str()),
		                 "Unknown report type %s with url %s", type.c_str(), url.c_str());
	}

}

/***********************************************************************
 * Report handlers configuration parsing
 *
 *  Example JSON file with handler service configuration:
 *  {
 *	"type":"analytic|crash|overview",
 *	"url":"com.webos.service.uploadd/processReport"
 *   }
 ***********************************************************************/
/**
 * @brief ReadHandlerConfig
 *
 * Parse JSON file with handler configuration
 *
 * @param file_name JSON configuration file path
 */
void ReadHandlerConfig(const char *file_name)
{
	g_assert(file_name);
	LOG_RDXD_DEBUG("%s: parsing handler configuration JSON %s", __func__, file_name);

	static const pbnjson::JSchemaFragment conf_schema{R"(
		{
			"type": "object",
			"properties": {
				"type": {"type": "string"},
				"handlerURL": {"type": "string"}
			},
			"required": ["type", "handlerURL"]
		}
		)"};

	pbnjson::JValue json = pbnjson::JDomParser::fromFile(file_name, conf_schema);
	if (!json)
	{
		LOG_RDXD_WARNING(MSGID_CONF_FILE_JSON_ERR, 1,
		                 PMLOGKS(FILENAME, file_name),
		                 "Error while parsing JSON configuration file %s", file_name);
		return;
	}

	AddReportHandler(json[JSON_TYPE_KEY_RDXD].asString(), json[JSON_HANDLER_KEY_RDXD].asString());

}

/**
 * @brief ReadHandlersConfig
 *
 * Scan configuration directory for JSON files
 * and loads list of report handlers
 *
 * @param config_dir Configuration directory path
 */
void ReadHandlersConfig(const char *config_dir)
{
	g_assert(config_dir);
	LOG_RDXD_DEBUG("%s: parsing configuration directory %s", __func__, config_dir);

	GError *gerror = NULL;
	GDir *dir = g_dir_open(config_dir, 0, &gerror);
	if (!dir)
	{
		LOG_RDXD_WARNING(MSGID_CONFIG_DIR_ERR, 3,
		                 PMLOGKS(DIR_PATH, config_dir),
		                 PMLOGKS(ERRTEXT, gerror->message),
		                 PMLOGKFV(ERRCODE, "%d", gerror->code),
		                 "Failed to read configuration directory %s: %d (%s)",
		                 config_dir, gerror->code, gerror->message);
		g_error_free(gerror);
		return;
	}

	// clear lists
	crashHandlers.clear();
	analyticsHandlers.clear();
	overviewHandlers.clear();

	const char *file_name = NULL;
	std::string full_path;
	while ((file_name = g_dir_read_name(dir)) != NULL)
	{
		if (!g_str_has_suffix(file_name, JSON_FILE_SUFFIX_RDXD))
			continue;
		full_path = config_dir + (std::string)"/" + file_name;
		ReadHandlerConfig(full_path.c_str());
	}

	g_dir_close(dir);
}

/**
 * @brief GetHandlersForType
 * @param type Report type
 *
 * returns handlers vector for passed report type
 */
std::vector<std::string> * GetHandlersForType(RDX_INPUT_TYPE type)
{
	if (type == RDX_INPUT_TYPE_CRASH)
		return &crashHandlers;
	else if (type == RDX_INPUT_TYPE_ANALYTICAL)
		return &analyticsHandlers;
	else if (type == RDX_INPUT_TYPE_OVERVIEW)
		return &overviewHandlers;

	return NULL;
}

/**
 * @brief GetNameForType
 * @param type Report type
 *
 * returns name for report type
 */
const char * GetNameForType(RDX_INPUT_TYPE type)
{
	switch(type)
	{
		case RDX_INPUT_TYPE_CRASH: return JSON_CONFIG_REPORT_TYPE_CRASH;
		case RDX_INPUT_TYPE_ANALYTICAL: return JSON_CONFIG_REPORT_TYPE_ANALYTIC;
		case RDX_INPUT_TYPE_OVERVIEW: return JSON_CONFIG_REPORT_TYPE_OVERVIEW;
		default: return JSON_CONFIG_REPORT_TYPE_UNKNOWN;
	}
}
