/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/************************************************************************//**
 * @ingroup passwd-srvd
 *
 * @file
 * Main source file for the Password Server daemon.
 *
 *    Password server serves other modules in OpenSwitch to perform password
 *     change for the user.
 *
 *    Its purpose in life is:
 *
 *       1. During start up, open UNIX domain socket to listen for password
 *           change request
 *       2. During operations, receive {username, old-password, new-password}
 *           to make password change for username.
 *       3. Manage /etc/shadow file to update password for a given user
 ***************************************************************************/
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <shadow.h>

#include <syslog.h>
#include <stdio.h>
#include <crypt.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>

#if 0
#include <util.h>

#include <daemon.h>
#include <dirs.h>
#include <unixctl.h>
#include <fatal-signal.h>
#include <command-line.h>
#include <vswitch-idl.h>
#include <openvswitch/vlog.h>

#include <pm_cmn.h>
#include <lacp_cmn.h>
#include <mlacp_debug.h>

#include "lacp.h"
#include "mlacp_fproto.h"
#include "lacp_ops_if.h"
#endif

#include "passwd_srv_pri.h"

static char *program_name = "";
//static char *version = "ops-passwd-srv " VERSION;

#if NOTYET
/**
 * password server usage help function.
 *
 */
static void
usage(void)
{
    printf("%s: OpenSwitch Password Server daemon\n"
           "usage: %s [OPTIONS] [DATABASE]\n"
           "where DATABASE is a socket on which ovsdb-server is listening\n"
           "      (default: \"unix:%s/db.sock\").\n",
           program_name, program_name, ovs_rundir());
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n");
    exit(EXIT_SUCCESS);
} /* usage */

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help",        no_argument, NULL, 'h'},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                   "use --help for usage");
    }
} /* parse_options */
#endif

/* password server main function */
int
main (int argc, char **argv)
{
    int socket_fd = 0;

	/* assign program name */
	program_name = argv[0];

	/* TODO: initialze signal handler */

	/* TODO: parse option */

	/* initialize socket connection */
	//socket_fd = create_socket(&sockaddr);
	listen_socket(socket_fd);

	return 0;
}
