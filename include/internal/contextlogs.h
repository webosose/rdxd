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

#ifndef __RDXD__CONTEXTLOGS_H__
#define __RDXD__CONTEXTLOGS_H__

#include <luna-service2/lunaservice.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ContextLogType_t;

typedef struct ContextLogType_t
{
	gchar *name;  // file name of result
	gchar *makeCmd;  // command to run to produce the log
} ContextLogType;

char *CLFilterLogs(const char *file_path);

bool CLCreateOverview(const char *file_path);

bool CLDumpSysInfo(const char *file_path);

void CLInit(LSHandle *sh, GMainLoop *main_loop, GKeyFile *config_file);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // __RDXD__CONTEXTLOGS_H__
