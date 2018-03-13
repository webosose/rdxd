// Copyright (c) 2013-2018 LG Electronics, Inc.
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

#ifndef __LIBRDX__LOG_H__
#define __LIBRDX__LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <PmLogLib.h>

/* Logging for librdx main context ********
 * The parameters needed are
 * msgid - unique message id
 * kvcount - count for key-value pairs
 * ... - key-value pairs and free text. key-value pairs are formed using PMLOGKS or PMLOGKFV
 * e.g.)
 * LOG_LIBRDX_CRITICAL(msgid, 2, PMLOGKS("key1", "value1"), PMLOGKFV("key2", "%s", value2), "free text message");
 **********************************************/
#define LOG_LIBRDX_CRITICAL(msgid, kvcount, ...) \
        PmLogCritical(_getlibrdxcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_LIBRDX_ERROR(msgid, kvcount, ...) \
        PmLogError(_getlibrdxcontext(), msgid, kvcount,##__VA_ARGS__)

#define LOG_LIBRDX_WARNING(msgid, kvcount, ...) \
        PmLogWarning(_getlibrdxcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_LIBRDX_INFO(msgid, kvcount, ...) \
        PmLogInfo(_getlibrdxcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_LIBRDX_DEBUG(...) \
        PmLogDebug(_getlibrdxcontext(), ##__VA_ARGS__)

/** main.c */
#define MSGID_RDXREPORTER_OPTPARSE_ERR          "RDXREPORTER_OPTPARSE_ERR"   /* option parsing failed */

/** rdx.c.in */
#define MSGID_FOPEN_ERR                         "FOPEN_ERR"                  /* cannot open file */
#define MSGID_INVALID_CHAR_ERR                  "INVALID_CHAR_ERR"           /* Text containing invalid characters */
#define MSGID_METADATA_LEN_TOO_LONG             "METADATA_LEN_TOO_LONG"      /* Failed to set metadata param value */
#define MSGID_RDX_DIR_OPEN_ERR                  "RDX_DIR_OPEN_ERR"           /* cannot open rdx directory */
#define MSGID_RDX_TRIGGERS_ERR                  "RDX_TRIGGERS_ERR"           /* Too many existing rdx-triggers */
#define MSGID_LOGDIR_STAT_ERR                   "LOGDIR_STAT_ERR"            /* STAT call on WEBOS_INSTALL_LOGDIR failed */
#define MSGID_REPORT_FILE_STAT_ERR              "REPORT_FILE_STAT_ERR"       /* Could not STAT report file */
#define MSGID_REGULAR_FILE_CHK_ERR              "REGULAR_FILE_CHK_ERR"       /* Wrong st_mode */
#define MSGID_REPORT_FILE_SIZE_ERR              "REPORT_FILE_SIZE_ERR"       /* File too large */
#define MSGID_MAX_REPORTS_LIMIT_REACHED         "MAX_REPORTS_FOR_UPLOAD"     /* no room for new reports */
#define MSGID_TRIGGER_LIMIT_REACHED             "TRIGGER_LIMIT_REACHED"      /* no room for new report triggers */
#define MSGID_NO_DISK_SPACE                     "NO_DISK_SPACE"              /* not enough disk space for new reports */
#define MSGID_CREATE_RDX_FOLDER_ERR             "CREATE_RDX_FOLDER"          /* RDX folder with parents create fail */
#define MSGID_SECURE_TMPFILE_CREATE_ERR         "TMPFILE_CREATE_ERR"         /* secure temp file create error */
#define MSGID_FREAD_ERR                         "FREAD_ERR"                  /* could not read file */
#define MSGID_FWRITE_ERR                        "FWRITE_ERR"                 /* Write to secure tmp failed */
#define MSGID_TMP_FILE_SIZE_ERR                 "TMP_FILE_SIZE_ERR"          /* Tmp File size too large */
#define MSGID_MD_WRITE_ERR                      "MD_WRITE_ERR"               /* Metadata write failed */
#define MSGID_RDX_REPORT_ERR                    "RDX_REPORT_ERR"             /* failed to create a rdx report */
#define MSGID_RDX_TEMP_PATH_ERR                 "RDX_TEMP_PATH_ERR"          /* RDX_TEMP_PATH create failed */
#define MSGID_CONTENTS_WRITE_ERR                "CONTENTS_WRITE_ERR"         /* Payload contents write failed */
#define MSGID_PATH_RENAME_ERR                   "PATH_RENAME_ERR"            /* Path rename failed */
#define MSGID_GET_MOD_DATE_ERR                  "GET_MOD_DATE_ERR"           /* Stat() failed, failed to get modified time */
#define MSGID_NO_PATH_FOUND                     "NO_PATH_FOUND"              /* Path doesn't exist */
#define MSGID_REPORT_FILE_CREATE_ERR            "REPORT_FILE_CREATE_ERR"     /* secure temp file create error */
#define MSGID_MAX_PENDING_REPORTS_ERR           "MAX_PENDING_REPORTS_ERR"    /* no room for new reports */
#define MSGID_NEW_REPORTS_SPACE_ERR             "NEW_REPORTS_SPACE_ERR"      /* not enough disk space for new reports */
#define MSGID_NEW_REPORT_TRIGGER_ERR            "NEW_REPORT_TRIGGER_ERR"     /* no room for new report triggers */

/** list of logkey ID's */

#define MD_MAX_LENGTH             "MD_MAX_LENGTH"
#define MD_LENGTH                 "MD_LENGTH"
#define PATH                      "PATH"
#define ERRTEXT                   "ERRTEXT"
#define ERRCODE                   "ERRCODE"
#define FILENAME                  "FILENAME"
#define RDX_EXISTING_TRIGGERS     "RDX_EXISTING_TRIGGERS"
#define NUM_TRIGGERS_TO_KEEP      "NUM_TRIGGERS_TO_KEEP"
#define BYTES_READ                "BYTES_READ"
#define BYTES_WRITTEN             "BYTES_WRITTEN"
#define FILE_SIZE                 "FILE_SIZE"
#define IMPACT                    "IMPACT"
#define INVALID_TEXT              "INVALID_TEXT"

extern PmLogContext _getlibrdxcontext();

#ifdef __cplusplus
} //extern "C"
#endif

#endif // __LIBRDX__LOG_H__
