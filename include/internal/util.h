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

#ifndef __RDXD__UTIL_H__
#define __RDXD__UTIL_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>

#include <glib.h>

#include <pbnjson.h>

#include "logging.h"
#include "globals.h"

#ifdef __cplusplus
extern "C" {
#endif

// lunaservice tracing
#define LSREPORT(lse) LOG_RDXD_ERROR(MSGID_LSREPORT_ERR, 2, PMLOGKS(FUNCTION,(lse).func), PMLOGKS(ERRTEXT,(lse).message), "")

#define LSTRACE_LSMESSAGE(message) \
    do { \
        gchar *payloadstr = NULL; \
        payloadstr = g_strescape(LSMessageGetPayload(message), NULL); \
        JSchemaInfo schemaInfo; \
        jvalue_ref parsedObj = {0}; \
        jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL); \
        parsedObj = jdom_parse(j_cstr_to_buffer(payloadstr), DOMOPT_NOOPT, &schemaInfo); \
        LOG_RDXD_DEBUG("%s(%s)", __func__, (NULL == payloadstr) ? "{}" : payloadstr); \
        g_free(payloadstr); \
        jvalue_ref errorCodeObj = {0}; \
        jvalue_ref errorTextObj = {0}; \
        if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("errorCode"), &errorCodeObj)) \
        { \
            int codenum = -1; \
            ConversionResultFlags retVal = jnumber_get_i32(errorCodeObj, &codenum); \
            if((retVal == CONV_OK) && (codenum != 0)){ \
               LOG_RDXD_WARNING(MSGID_JOBJ_PARSE_ERRCODE, 2, PMLOGKS(FUNCTION,__FUNCTION__), PMLOGKFV(ERRCODE,"%d",codenum), ""); \
            } \
        } \
        if(jobject_get_exists(parsedObj, J_CSTR_TO_BUF("errorText"), &errorTextObj)) {  \
            if(jis_string(errorTextObj)) { \
                raw_buffer errorText_buf = jstring_get(errorTextObj); \
                LOG_RDXD_WARNING(MSGID_JOBJ_PARSE_ERRTEXT, 2, PMLOGKS(FUNCTION,__FUNCTION__), PMLOGKS(ERRTEXT,errorText_buf.m_str), ""); \
                jstring_free_buffer(errorText_buf); \
            } \
        } \
        j_release(&parsedObj); \
    } while (0) \

// glib process spawn tracing
#define SHOW_STDERR(standard_error) \
    if (standard_error != NULL) { \
        if (strlen(standard_error) > 0) { \
            LOG_RDXD_WARNING(MSGID_PROC_SPAWN_TRACE_STDERR, 0, "%s",standard_error); \
        } \
        g_free(standard_error); \
        standard_error = NULL; \
    }

/***********************************************************************
 * ParseBool
 ***********************************************************************/
bool ParseBool(const char *valStr, bool *bP);


/***********************************************************************
 * ParseInt
 ***********************************************************************/
bool ParseInt(const char *valStr, int *nP);

//TODO: document

gchar *read_string_conf(GKeyFile *keyfile, gchar *cat, gchar *key, bool mandatory);

gchar *get_file_modified_time(const char *path);

bool compress_file(const char *path);

bool mark_as_seen(gchar *crash_path, bool is_success, GError **error);

/**
 * @brief Runs a cmd
 *
 * @param cmd command line
 *
 * @param output optional pointer to string for stdout contents
 *
 * @return true if success
 */
bool run_script(const char* cmd, gchar** output);

/**
 * @brief free_report_spec
 *
 * Deconstructor for ReportSpec_t object
 *
 * @param spec ReportSpec_t*
 */
void free_report_spec(ReportSpec_t *spec);

#ifdef __cplusplus
} //extern "C"
#endif

#endif //  __RDXD__UTIL_H__
