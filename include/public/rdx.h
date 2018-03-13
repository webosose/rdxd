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
 * @file rdx.h
 */

#ifndef _RDX_H_
#define _RDX_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @mainpage
 *
 * <h1>librdx</h1>
 *
 * <em>Example string based report usage:</em>
 *
@code

bool retVal;
if (something_terrible_happened() ) {
    // make rdx report
    RdxReportMetadata md = create_rdx_report_metadata();
    rdx_report_metadata_set_component(md, "my_component");
    rdx_report_metadata_set_cause(md, "The thingy broke");
    rdx_report_metadata_set_detail(md, "In myfunc() something_terrible_happened()");
    rdx_report_metadata_set_payload_filename(md, "the_payload_name_in_the_report.txt"); // defaults to "payload"
    retVal = rdx_make_report(md, "MY_STACK_TRACE");
    destroy_rdx_report_metadata(md);
 }
@endcode

<em>Example file based report usage:</em>
@code
bool retVal;
if (something_terrible_happened() ) {
    // make rdx report
    g_file_set_contents("/tmp/mypayload.txt", "MY_STACK_TRACE", NULL, NULL);
    RdxReportMetadata md = create_rdx_report_metadata();
    rdx_report_metadata_set_component(md, "my_component");
    rdx_report_metadata_set_cause(md, "The thingy broke");
    rdx_report_metadata_set_detail(md, "In myfunc() something_terrible_happened()");
    rdx_report_metadata_set_payload_filename(md, "the_payload_name_in_the_report.txt"); // defaults to "payload"
    rdx_make_report_from_file(md, "/tmp/mypayload.txt")
    destroy_rdx_report_metadata(md);
 }
@endcode
*/

/**
 * RdxReportMetadata
 * @brief This is an opaque structure containing all the metadata
 * that an rdx report might contain (component, cause, details, etc..).
 */
typedef struct rdx_report_metadata_t *RdxReportMetadata;

/**
 * @brief
 * The metadata constructor
 *
 * @return true on success
 */
RdxReportMetadata create_rdx_report_metadata();

/**
 * @brief
 * the destructor for metadata
 *
 * @param md the metadata
 *
 * @return true on success
 */
bool destroy_rdx_report_metadata(RdxReportMetadata md);

/**
 * @brief
 * sets the component metadata
 *
 * @param md the metadata
 * @param component the component
 *
 * @return true on success
 */
bool rdx_report_metadata_set_component(RdxReportMetadata md,
                                       const char *component);

/**
 * @brief
 * sets the cause metadata
 *
 * @param md the metadata
 * @param cause the cause
 *
 * @return true on success
 */
bool rdx_report_metadata_set_cause(RdxReportMetadata md, const char *cause);

/**
 * @brief
 * sets the detail metadata
 *
 * @param md the metadata
 * @param detail the detail
 *
 * @return true on success
 */
bool rdx_report_metadata_set_detail(RdxReportMetadata md, const char *detail);

/**
 * @brief
 * sets the filename of the payload file.  In the rdx report tarball this will
 * be the name of the file that contains the payload.  If this function is not
 * used, the filename will default to "payload"
 *
 * @param md the metadata
 * @param filename the filename
 *
 * @return true on success
 */
bool rdx_report_metadata_set_payload_filename(RdxReportMetadata md,
        const char *filename);

/**
 * @brief
 * Creates the report with the given payload contents
 *
 * @param md the metadata
 * @param payload the contents of the payload
 *
 * @return true on success
 */
bool rdx_make_report(RdxReportMetadata md, const char *payload);


/**
 * @brief
 * Creates the report with the payload specified in the given path.
 * It just copies the contents of the file at this path into the payload
 * in the report.  If the resulting payload filename is not set with
 * the rdx_report_metadata_set_payload_filename function, then the name
 * defaults to "payload"
 *
 * @param md the metadata
 * @param path the path to the payload
 *
 * @return
 */
bool rdx_make_report_from_file(RdxReportMetadata  md, const char *path);

#ifdef __cplusplus
}
#endif

#endif // _RDX_H_

