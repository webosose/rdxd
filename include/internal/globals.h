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
 * @file globals.h
 *
 * @brief
 * note the line between globals.h and utils.h is very thin.. should probably combine them
 *
 */

#ifndef __RDXD__GLOBALS_H__
#define __RDXD__GLOBALS_H__

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

// AppID for Luna Prefs handle and for service registry
#define RDXD_APP_ID "com.webos.rdxd"

/***********************************************************************
 * Structures and enumerations used in different modules
 *
 * RDX_INPUT_TYPE
 * ReportSpec_t
 ***********************************************************************/

typedef enum
{
	RDX_INPUT_TYPE_CRASH,
	RDX_INPUT_TYPE_ANALYTICAL,
	RDX_INPUT_TYPE_OVERVIEW
}
RDX_INPUT_TYPE;

// JSON configuration report types
#define JSON_CONFIG_REPORT_TYPE_CRASH     "crash"
#define JSON_CONFIG_REPORT_TYPE_ANALYTIC  "analytic"
#define JSON_CONFIG_REPORT_TYPE_OVERVIEW  "overview"
#define JSON_CONFIG_REPORT_TYPE_UNKNOWN   "unknown"

typedef struct
{
	RDX_INPUT_TYPE reportType;
	gchar *reportCause;
	gchar *reportComponent;
	gchar *reportDetail;
	gchar *reportPath;
	gchar *reportTime;
	gchar *reportFileName;
	gchar *reportFormat;
	gchar *reportSysInfoSnapshot;
}
ReportSpec_t;

#ifdef __cplusplus
extern "C"
#endif

#endif //  __RDXD_GLOBALS_H__
