# Copyright (c) 2008-2018 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

#
# rdxd/src/rdx_reporter/CMakeLists.txt
#

add_executable(rdx_reporter main.c)
target_link_libraries(rdx_reporter librdx ${GLIB2_LDFLAGS} ${PMLOG_LDFLAGS})

webos_build_program(NAME rdx_reporter ADMIN)
