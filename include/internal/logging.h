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

#ifndef __LOGGING_H__
#define __LOGGING_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <PmLogLib.h>

/* Logging for Rdxd main context ********
 * The parameters needed are
 * msgid - unique message id
 * kvcount - count for key-value pairs
 * ... - key-value pairs and free text. key-value pairs are formed using PMLOGKS or PMLOGKFV
 * e.g.)
 * LOG_RDXD_CRITICAL(msgid, 2, PMLOGKS("key1", "value1"), PMLOGKFV("key2", "%s", value2), "free text message");
 **********************************************/
#define LOG_RDXD_CRITICAL(msgid, kvcount, ...) \
        PmLogCritical(_getrdxdcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_RDXD_ERROR(msgid, kvcount, ...) \
        PmLogError(_getrdxdcontext(), msgid, kvcount,##__VA_ARGS__)

#define LOG_RDXD_WARNING(msgid, kvcount, ...) \
        PmLogWarning(_getrdxdcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_RDXD_INFO(msgid, kvcount, ...) \
        PmLogInfo(_getrdxdcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_RDXD_DEBUG(...) \
        PmLogDebug(_getrdxdcontext(), ##__VA_ARGS__)

#define LOG_TEST_CRITICAL(msgid, kvcount, ...) \
        PmLogCritical(_getrdxdtestcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_TEST_ERROR(msgid, kvcount, ...) \
        PmLogError(_getrdxdtestcontext(), msgid, kvcount,##__VA_ARGS__)

#define LOG_TEST_WARNING(msgid, kvcount, ...) \
        PmLogWarning(_getrdxdtestcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_TEST_INFO(msgid, kvcount, ...) \
        PmLogInfo(_getrdxdtestcontext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_TEST_DEBUG(...) \
        PmLogDebug(_getrdxdtestcontext(), ##__VA_ARGS__)


/**list of MSGID's pairs */

/** main.cpp */
#define MSGID_OPTION_PARSE_ERR                  "OPTION_PARSE_ERR"           /* option parsing failed */
#define MSGID_CREATE_KEYFILE_ERR                "CREATE_KEYFILE_ERR"         /* Failed to create Key file */
#define MSGID_CONF_FILE_READ_ERR                "CONF_FILE_READ_ERR"         /* Failed to read configuration file */
#define MSGID_CONF_FILE_JSON_ERR                "CONF_FILE_JSON_ERR"         /* Invalid JSON in the configuration file */
#define MSGID_SRVC_REGISTER_ERR                 "SRVC_REGISTER_ERR"          /* Failed to register service on luna bus */
#define MSGID_LSMSG_REPLY_ERR                   "LSMSG_REPLY_ERR"            /* LSMessageReply error */
#define MSGID_MKDIR_ERR                         "MKDIR_ERR"                  /* Failed to create pending/uploaded directory */
#define MSGID_INVALID_JOBJ                      "INVALID_JOBJ"               /* Payload is not a json object */
#define MSGID_RESPONSE_MISSING_PATH             "RESPONSE_MISSING_PATH"      /* Pending filepath missing */
#define MSGID_PATH_RENAME_ERR                   "PATH_RENAME_ERR"            /* Filepath rename from pending to uploaded failed */
#define MSGID_MISSING_PATH_ERR                  "MISSING_PATH_ERR"           /* Filepath of file to be uploaded missing */
#define MSGID_MISSING_REPORT_ID                 "MISSING_REPORT_ID"          /* response is missing reportID */
#define MSGID_FALSE_RETURN_VAL                  "FALSE_RETURN_VAL"           /* upload called with false returnValue */
#define MSGID_MAKE_TARBALL_ERR                  "MAKE_TARBALL_ERR"           /* Failed to create *.tar.gz file for given file */
#define MSGID_CHLD_PROC_END_ERR                 "CHLD_PROC_END_ERR"          /* child process abnormal termination */
#define MSGID_CHILD_PROC_STOPPED                "CHILD_PROC_STOPPED"         /* child process stopped executing */
#define MSGID_CP_CHLD_PROC_END_ERR              "CP_CHLD_PROC_END_ERR"       /* Failed to copy file from source to destination */
#define MSGID_CHK_CP_PROC_STOPPED               "CHK_CP_PROC_STOPPED"        /* copy command child process stopped executing */
#define MSGID_MK_TMP_FOLDER_ERR                 "MK_TMP_FOLDER_ERR"          /* create new report file in pending directory */
#define MSGID_CONTEXT_LOG_ERR                   "CONTEXT_LOG_ERR"            /* could not create context logs */
#define MSGID_REPORT_ID_ERR                     "REPORT_ID_ERR"              /* failed to get reportid */
#define MSGID_CRASH_REPORT_CREATED              "CRASH_REPORT_CREATED"       /* crash report created successfully */
#define MSGID_ANALYTICS_REPORT_CREATED          "ANALYTICS_REPORT_CREATED"   /* analytics report created successfully */
#define MSGID_OPEN_PENDING_DIR_ERR              "OPEN_PENDING_DIR_ERR"       /* Failed to open pending directory for upload */
#define MSGID_UNKNOWN_FILE                      "UNKNOWN_FILE"               /* unrecognized filename */
#define MSGID_COPY_ERR                          "COPY_ERR"                   /* File copy error */
#define MSGID_REPORTID_SAVE_ERR                 "REPORTID_SAVE_ERR"          /* Failed to save reportID into Lunaprefs */
#define MSGID_CLEANSEEN_UNDONE                  "CLEANSEEN_UNDONE"           /* reported and seen files could not be removed */
#define MSGID_MAKE_SYMLINK_FAIL                 "MAKE_SYMLINK_FAIL"          /* Failed to make symbolic link file */
#define MSGID_MAKE_HARDLINK_FAIL                "MAKE_HARDLINK_FAIL"         /* Failed to make hard link to file */
#define MSGID_LP_GETHANDLE_ERR                  "LP_GETHANDLE_ERR"           /* Could not get LP Handle for report id number generation */
#define MSGID_CRASH_HEADER_ERR                  "CRASH_HEADER"               /* Error appending crash header */
#define MSGID_FILTER_ERR                        "FILTER_ERR"                 /* filtering went wrong */
#define MSGID_FILE_CHMOD_FAILED                 "FILE_CHMOD_FAILED"          /* File change permissions failed */
#define MSGID_MK_TMP_FILE_ERR                   "MSGID_MK_TMP_FILE_ERR"      /* Failed to make temp file */
#define MSGID_POST_REPORT_ERR                   "POST_REPORT_ERR"            /* Failed to post report to upload services */
#define MSGID_NO_HANDLERS_FOR_REPORT            "NO_HANDLERS_FOR_REPORT"     /* No handlers configured to process report type */
#define MSGID_INVALID_REPORT_TYPE               "INVALID_REPORT_TYPE"        /* Invalid report type */
#define MSGID_REPORT_POSTED_INFO                "REPORT_POSTED_INFO"         /* Report posted to service */
#define MSGID_REPORT_PROCESSING_INFO            "REPORT_PROCESSING_INFO"     /* Report processed by service */
#define MSGID_REPORT_PROCESSING_FAIL            "REPORT_PROCESSING_FAIL"     /* Service failed to process report */

/** config.c */
#define MSGID_OPEN_SYS_PROP_ERR                 "OPEN_SYS_PROP_ERR"          /* Couldn't open system properties */
#define MSGID_CONF_READ_INVALID_TYPE            "CONF_READ_INVALID_TYPE"     /* unrecognized type read from .conf file */
#define MSGID_READ_CONF_ERR                     "READ_CONF_ERR"              /* Failed to read .conf file */
#define MSGID_SET_CONF_ERR                      "SET_CONF_ERR"               /* Failed to set configuration */
#define MSGID_LP_READ_INVALID_TYPE              "LP_READ_INVALID_TYPE"       /* unrecognized type read from Lunaprefs */
#define MSGID_LP_READ_ERR                       "LP_READ_ERR"                /* Failed to read lunapref property */
#define MSGID_CLOSE_SYS_PROP_ERR                "CLOSE_SYS_PROP_ERR"         /* Failed to close system properties */
#define MSGID_LP_PARSE_BOOL                     "LP_PARSE_BOOL"              /* LP property requires a boolean value */
#define MSGID_LP_PARSE_INT                      "LP_PARSE_INT"               /* LP property requires an integer value */
#define MSGID_CONFIG_DIR_ERR                    "MSGID_CONFIG_DIR_ERR"       /* Failed to read configuration directory */

/** util.c */
#define MSGID_G_KEY_FILE_STR_ERR                "G_KEY_FILE_STR_ERR"         /* key value accessed as string error */
#define MSGID_STAT_ERR                          "STAT_ERR"                   /* Failed to get file modify time [via stat()]  */
#define MSGID_RMDIR_ERR                         "RMDIR_ERR"                  /* rmdir failed : g_spawn_err */
#define MSGID_MARK_AS_SEEN_ERR                  "MARK_AS_SEEN_ERR"           /* Cannot mark librdx trigger file as seen */
#define MSGID_FILE_RENAME_ERR                   "FILE_RENAME_ERR"            /* Could not rename file */
#define MSGID_FILE_COMPRESS_ERR                 "FILE_COMPRESS_ERR"          /* Could not zip file */

/** util.h */
#define MSGID_LSREPORT_ERR                      "LSREPORT_ERR"
#define MSGID_JOBJ_PARSE_ERRCODE                "JOBJ_PARSE_ERRCODE"         /* Lunaservice tracing payload parse errcode */
#define MSGID_JOBJ_PARSE_ERRTEXT                "JOBJ_PARSE_ERRTEXT"         /* Lunaservice tracing payload parse err */
#define MSGID_PROC_SPAWN_TRACE_STDERR           "PROC_SPAWN_TRACE_STDERR"    /* glib process spawn tracing stderr */
#define MSGID_PROC_SPAWN_TRACE_ERR              "PROC_SPAWN_TRACE_ERR"       /* glib process spawn tracing err */

/** watch.c */
#define MSGID_FOPEN_ERR                         "FOPEN_ERR"                  /* cannot open file */
#define MSGID_G_MALLOC_ERR                      "G_MALLOC_ERR"               /* cannot g_malloc a memory to store meta data */
#define MSGID_FREAD_METADATA_ERR                "FREAD_METADATA_ERR"         /* cannot read meta data */
#define MSGID_FILE_TRUNCATE_ERR                 "FILE_TRUNCATE_ERR"          /* Failed to truncate file */
#define MSGID_STR_SPLIT_ERR                     "STR_SPLIT_ERR"              /* unexpected filename pattern for metadata string */
#define MSGID_TRIGGER_PATH_OPEN_ERR             "TRIGGER_PATH_OPEN_ERR"      /* cannot open trigger path */
#define MSGID_REPORT_CREATE_ERR                 "REPORT_CREATE_ERR"          /* could not create report */
#define MSGID_INOTIFY_EVENT_READ_ERR            "INOTIFY_EVENT_READ_ERR"     /* error reading inotify event */
#define MSGID_INOTIFY_EVENT_READ_STATUS         "INOTIFY_EVENT_READ_STATUS"  /* status reading inotify event */
#define MSGID_INOTIFY_NAME_READ_ERR             "INOTIFY_NAME_READ_ERR"      /* error reading inotify name */
#define MSGID_INOTIFY_NAME_READ_STATUS          "INOTIFY_NAME_READ_STATUS"   /* status reading inotify name */
#define MSGID_WATCH_TRIGGER_REPORT_ERR          "WATCH_TRIGGER_REPORT_ERR"   /* could not create watch trigger report */
#define MSGID_WATCH_FILE_DELETED                "WATCH_FILE_DELETED"         /* watched file was deleted */
#define MSGID_INOTIFY_INIT_ERR                  "INOTIFY_INIT_ERR"           /* Inotify Init error */
#define MSGID_INOTIFY_ADD_WATCH_ERR             "INOTIFY_ADD_WATCH_ERR"      /* Inotify add watch trigger path failed */
#define MSGID_G_IO_ENCODING_ERR                 "G_IO_ENCODING_ERR"          /* g_io_channel_set_encoding failed */
#define MSGID_INOTIFY_CLOSE_ERR                 "INOTIFY_CLOSE_ERR"          /* Inotify watch close failed */
#define MSGID_FREAD_METADATA_LEN_ERR            "FREAD_METADATA_LEN_ERR"     /* cannot read meta data length */
#define MSGID_MK_LIBRDX_TRIGGER_PATH_ERR        "MK_LIBRDX_TRIGGER_PATH"     /* Failed to create trigger path */
#define MSGID_FSEEK_ERR                         "FSEEK_ERR"                  /* Failed to do fseek on file */
#define MSGID_FSEEK_METADATA_ERR                "FSEEK_METADATA_ERR"         /* Failed to do fseek on file */
#define MSGID_SPEC_ERROR                        "SPEC_ERR"                   /* Failed to create report spec from crash file*/

/** cldata.c */
#define MSGID_SET_LUNA_PROP_ERR                 "SET_LUNA_PROP_ERR"          /* setting luna prop failed */
#define MSGID_GOT_IMEI_NUM                      "GOT_IMEI_NUM"               /* Got IMEI number */
#define MSGID_IMEI_STR_ERR                      "IMEI_STR_ERR"               /* IMEI string creation failed */
#define MSGID_GOT_MEID_NUM                      "GOT_MEID_NUM"               /* Got MEID number */
#define MSGID_MEID_STR_ERR                      "MEID_STR_ERR"               /* MEID string creation failed */
#define MSGID_UNKNOWN_IDENTIFIER                "UNKNOWN_IDENTIFIER"         /* No recognized identifier found */
#define MSGID_TELSERVER_ERR                     "TELSERVER_ERR"              /* telServer value not found */
#define MSGID_TELEPHONY_READY_ERR               "TELEPHONY_READY_ERR"        /* extended/macro payload was not found */
#define MSGID_SERVICENAME_ERR                   "SERVICENAME_ERR"            /* couldn't read serviceName from payload */
#define MSGID_UNKNOWN_SRVC_NAME                 "UNKNOWN_SRVC_NAME"          /* Unrecognized service name */
#define MSGID_LP_KEY_INVALID_VAL                "LP_KEY_INVALID_VAL"         /* Got invalid rid from LP key */
#define MSGID_EXTND_PAYLD_ERR                   "EXTND_PAYLD_ERR"            /* Extended payload not found */
#define MSGID_READY_VAL_NOT_FOUND               "READY_VAL_NOT_FOUND"        /* Telephony ready value not found */
#define MSGID_CONNECTION_ERR                    "CONNECTION_ERR"             /* Couldn't read connected status from payload */

/** test msgid's */
#define MSGID_CMD_EXEC_ERR                     "CMD_EXEC_ERR"
#define MSGID_CMD_EXEC_END_STATUS              "CMD_EXEC_END_STATUS"
#define MSGID_STDERR                           "STD_ERROR"
#define MSGID_TEST_MAKE_REPORT_FAILED          "MAKE_REPORT_FAILED"        /* Failure back from rdx_make_report */
#define MSGID_TEST_FILES_NOT_EXIST             "FILES_NOT_EXIST"           /* /var/log/reports/librdx/\*.gz doesnt exist */
#define MSGID_TEST_UNTAR_FAILED                "UNTAR_FAILED"              /* untar failed */
#define MSGID_TEST_CAUSE_NOT_KNOWN             "CAUSE_NOT_KNOWN"           /* /tmp/overview.txt didnt have correct cause */
#define MSGID_TEST_COMPONENT_NOT_KNOWN         "REPORT_COMPONENT_ERR"      /* /tmp/overview.txt didnt have correct component */
#define MSGID_TEST_REPORT_DETAIL_UNKNOWN       "REPORT_DETAIL_ERR"         /* /tmp/overview.txt didnt have correct detail */
#define MSGID_CMD_EXEC_TERMINATED              "EXEC_TERMINATED"           /* executing the following command failed : abnormal termination */
#define MSGID_CMD_EXEC_STOPPED                 "EXEC_STOPPED"              /* executing the following command failed :child stopped,*/
#define MSGID_CMD_EXEC_FAILED                  "EXEC_FAILED"               /* executing the following command failed with error */
#define MSGID_TEST_RESULT                      "RESULT"                    /* Result */
#define MSGID_TEST_START                       "TEST_START"


/** list of logkey ID's */

#define ERRTEXT                   "ERRTEXT"
#define ERRCODE                   "ERRCODE"
#define DIR_PATH                  "DIR_PATH"
#define REPORT_ID                 "REPORT_ID"
#define OLDPATH                   "OLDPATH"
#define NEWPATH                   "NEWPATH"
#define REASON                    "REASON"
#define SERVICE                   "SERVICE"
#define COMMAND                   "COMMAND"
#define STATUS                    "STATUS"
#define SIGNAL_NUM                "SIGNAL_NUM"
#define CAUSE                     "CAUSE"
#define COMPONENT                 "COMPONENT"
#define DETAIL                    "DETAIL"
#define TMP_FOLDER                "TMP_FOLDER"
#define PATH                      "PATH"
#define FILENAME                  "FILENAME"
#define APP_ID                    "APP_ID"
#define TYPE                      "TYPE"
#define PROPERTY                  "PROPERTY"
#define BYTES_READ                "BYTES_READ"
#define METADATALEN               "METADATALEN"
#define METADATA_STR              "METADATA_STR"
#define TRIGGER_PATH              "TRIGGER_PATH"
#define MD_MAX_LENGTH             "MD_MAX_LENGTH"
#define RDX_EXISTING_TRIGGERS     "EXISTING_TRIGGERS"
#define NUM_TRIGGERS_TO_KEEP      "TRIGGERS_TO_KEEP"
#define FILE_SIZE                 "FILE_SIZE"
#define BYTES_WRITTEN             "BYTES_WRITTEN"
#define IMEI                      "IMEI"
#define SRVC_ID                   "SRVC_ID"
#define MEID                      "MEID"
#define LUNA_PROP                 "LUNA_PROP"
#define LUNA_VAL                  "LUNA_VAL"
#define FUNCTION                  "FUNCTION"
#define OVERVIEW_PATH             "OVERVIEW_PATH"
#define SIZE                      "SIZE"
#define CURLOPT                   "CURLOPT"
#define URL                       "URL"
#define CATEGORY                  "CATEGORY"
#define METHOD                    "METHOD"


/** test logkey ID's */
#define EXPECTED                               "EXPECTED"
#define ACTUAL                                 "ACTUAL"
#define SIGNAL_NUM                             "SIGNAL_NUM"
#define ERROR                                  "ERROR"
#define STDERR                                 "STDERR"


extern PmLogContext _getrdxdcontext();
extern PmLogContext _getrdxdtestcontext();

#ifdef __cplusplus
} //extern "C"
#endif

#endif // __LOGGING_H__
