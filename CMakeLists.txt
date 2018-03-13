# Copyright (c) 2012-2018 LG Electronics, Inc.
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

cmake_minimum_required(VERSION 2.8.7)

project(rdxd C CXX)

include(webOS/webOS)
webos_modules_init(1 6 1)
webos_component(4 0 2)

webos_include_install_paths()
include_directories(include/public include/internal)
add_subdirectory(src)

# In the days before Open webOS we used ipkg to manage packages.
#
# The following configuration variable lets us select the correct paths
# for the package manager in use.
#
# We default to oe-core's opkg package manager
if(WEBOS_USE_LEGACY_PACKAGE_MANAGER)
	set(PACKAGE_MANAGER "ipkg" CACHE STRING "Packaging tool to use in updates")
else()
	set(PACKAGE_MANAGER "opkg" CACHE STRING "Packaging tool to use in updates")
endif()

# install the script files
set (SCRIPT_LOCATION files/scripts/private)
set (SYS_INFO_FILE_PATH ${SCRIPT_LOCATION})

if(EXISTS "${CMAKE_SOURCE_DIR}/${SCRIPT_LOCATION}/${WEBOS_TARGET_DISTRO}")
        set(SYS_INFO_FILE_PATH ${SCRIPT_LOCATION}/${WEBOS_TARGET_DISTRO})
endif()

webos_configure_source_files(SCRIPT_FILES
					${SCRIPT_LOCATION}/cleanseen.sh
					${SCRIPT_LOCATION}/dumplog.sh
					${SCRIPT_LOCATION}/filter.sh
					${SCRIPT_LOCATION}/make_integcheck.sh
					${SCRIPT_LOCATION}/make_overview.sh
					${SYS_INFO_FILE_PATH}/make_sysinfo.sh
					${SCRIPT_LOCATION}/show_rdx_reports
					${SCRIPT_LOCATION}/logging.sh)
install(PROGRAMS ${SCRIPT_FILES} DESTINATION ${WEBOS_INSTALL_DATADIR}/rdxd)

webos_configure_source_files(UTILITY_SCRIPTS ${SCRIPT_LOCATION}/collect_alllogs.sh)
install(PROGRAMS ${UTILITY_SCRIPTS} DESTINATION ${WEBOS_INSTALL_BINDIR})

install(DIRECTORY DESTINATION ${WEBOS_INSTALL_SYSCONFDIR}/rdxd.d)

# install the init.d script
webos_configure_source_files(INITSCRIPT files/launch/rm_varlogtmp)
install(PROGRAMS ${INITSCRIPT} DESTINATION ${WEBOS_INSTALL_SYSCONFDIR}/init.d/postmountall.d)

# install the configuration file
webos_configure_source_files(CONF_FILE files/conf/rdxd.conf)
install(FILES ${CONF_FILE} DESTINATION ${WEBOS_INSTALL_SYSCONFDIR})

webos_build_system_bus_files()
webos_config_build_doxygen(doc Doxyfile)
#webos_config_build_tests()
