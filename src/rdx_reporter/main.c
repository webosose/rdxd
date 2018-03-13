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
 * @file main.c
 *
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <rdx.h>
#include "librdxlog.h"

static gchar *component = NULL;
static gchar *cause = NULL;
static gchar *detail = NULL;
static gchar *contents_file = NULL;
static gchar *payload_filename = NULL;
static gboolean force = false;

static GOptionEntry entries[] =
{
	{ "component", 'C', 0, G_OPTION_ARG_STRING, &component, "The component name of the report", NULL },
	{ "cause", 'c', 0, G_OPTION_ARG_STRING, &cause, "The cause name of the report", NULL },
	{ "detail", 'd', 0, G_OPTION_ARG_STRING, &detail, "The detail name of the report", NULL },
	{ "file", 'f', 0, G_OPTION_ARG_FILENAME, &contents_file, "The path to the file to use as contents (instead of stdin)", NULL },
	{ "payload", 'p', 0, G_OPTION_ARG_FILENAME, &payload_filename, "The filename for the payload", NULL },
	{ "force", 'F', 0, G_OPTION_ARG_NONE, &force, "force this to work even if the user doesnt specify metadata", NULL},
	{ NULL }
};

#define ERR_NOCOMP 1
#define ERR_NOCAUSE 2
#define ERR_NODET 3
#define ERR_BADCOMP 4
#define ERR_BADCAUSE 5
#define ERR_BADDET 6
#define ERR_READFILE 7
#define ERR_BADPAY 8

int
main(int argc, char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;

	context = g_option_context_new("- rdx report generator");
	g_option_context_add_main_entries(context, entries, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		LOG_LIBRDX_ERROR(MSGID_RDXREPORTER_OPTPARSE_ERR, 1, PMLOGKS(ERRTEXT,
		                 error->message), "option parsing failed");
		return 1;
	}

	if (!force)
	{
		g_return_val_if_fail(component, ERR_NOCOMP);
		g_return_val_if_fail(cause, ERR_NOCAUSE);
		g_return_val_if_fail(detail, ERR_NODET);
	}


	RdxReportMetadata md = create_rdx_report_metadata();

	if (component)
	{
		g_return_val_if_fail(rdx_report_metadata_set_component(md, component) ||
		                     force, ERR_BADCOMP);
	}

	if (cause)
	{
		g_return_val_if_fail(rdx_report_metadata_set_cause(md, cause) ||
		                     force, ERR_BADCAUSE);
	}

	if (detail)
	{
		g_return_val_if_fail(rdx_report_metadata_set_detail(md, detail) ||
		                     force, ERR_BADDET);
	}

	if (payload_filename)
	{
		g_return_val_if_fail(rdx_report_metadata_set_payload_filename(md,
		                     payload_filename) || force, ERR_BADPAY);
	}

	if (contents_file)
	{
		rdx_make_report_from_file(md, contents_file);
	}
	else
	{
		gchar *contents = NULL;
		GString *data = g_string_new("");
		char buf[32];

		while (fgets(buf, sizeof(buf), stdin))
		{
			g_string_append(data, buf);
		}

		contents = g_string_free(data, FALSE);
		rdx_make_report(md, contents);
		g_free(contents);
	}

	destroy_rdx_report_metadata(md);

	exit(EXIT_SUCCESS);
}
