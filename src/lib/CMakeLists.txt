# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

cmake_minimum_required (VERSION 2.8)

project ("passwd_srv_lib")

set (INCL_DIR ${CMAKE_SOURCE_DIR}/include)
set (LIBPASSWDSRV passwd_srv)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror")

add_definitions(-DHAVE_CONFIG_H -DHAVE_SOCKLEN_T)

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)

include_directories (
    ${PROJECT_BINARY_DIR}
    ${PROJECT_SOURCE_DIR}/${INCL_DIR}
    ${OVSCOMMON_INCLUDE_DIRS}
)

# Source files to build ops-passwd-srv
set (LIBSOURCES passwd_srv_yaml.c)
set (YAMLFILE ops-passwd-srv.yaml)
set (ETCPASSWD "/etc/ops-passwd-srv/")

# Rules to build ops-passwd-srv
add_library(${LIBPASSWDSRV} SHARED ${LIBSOURCES})
target_link_libraries(${LIBPASSWDSRV}  -lyaml)

# Rules to install ops-passwd-srv binary in rootfs
install(DIRECTORY DESTINATION ${ETCPASSWD})
install(FILES ${YAMLFILE} DESTINATION ${ETCPASSWD})
install(TARGETS ${LIBPASSWDSRV} LIBRARY DESTINATION lib)
