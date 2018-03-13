# Copyright (c) 2012-2018 LG Electronics, Inc.
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

include(FindPkgConfig)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++11")

pkg_check_modules(ZLIB REQUIRED zlib)
include_directories(${ZLIB_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${ZLIB_CFLAGS_OTHER})

pkg_check_modules(PMLOGLIB REQUIRED PmLogLib>=3.1.0)
include_directories(${PMLOGLIB_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOGLIB_CFLAGS_OTHER})

pkg_check_modules(PBNJSON_CXX pbnjson_cpp)
include_directories(${PBNJSON_CXX_INCLUDE_DIRS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PBNJSON_CXX_CXXFLAGS_OTHER}")

file(GLOB SOURCE_FILES *.cpp *.c)

# Build the rdxd executable
add_executable(rdxd ${SOURCE_FILES})

webos_add_compiler_flags(ALL -Wall -fPIC)

target_link_libraries(rdxd
                      ${LUNAPREFS_LDFLAGS}
                      ${GLIB2_LDFLAGS}
                      ${LUNASERVICE2_LDFLAGS}
                      ${PBNJSON_C_LDFLAGS}
                      ${PBNJSON_CXX_LDFLAGS}
                      ${PMLOGLIB_LDFLAGS}
                      ${LIBCURL_LDFLAGS}
                      ${ZLIB_LDFLAGS}
                      )

webos_build_daemon()
