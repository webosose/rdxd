// Copyright (c) 2015-2018 LG Electronics, Inc.
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

#ifndef __RDXD__CONFIG_H__
#define __RDXD__CONFIG_H__

#include <vector>
#include <string>

#include <glib.h>

#include "util.h"


bool ReadProps(GKeyFile *config_file, bool *sAutoUpload);

void ReadHandlersConfig(const char *config_dir);

std::vector<std::string> * GetHandlersForType(RDX_INPUT_TYPE type);

const char * GetNameForType(RDX_INPUT_TYPE type);

#endif //__RDXD__CONFIG_H__
