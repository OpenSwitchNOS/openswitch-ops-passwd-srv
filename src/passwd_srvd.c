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
#include <sys/stat.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

//#include "openvswitch/vlog.h"

#include <util.h>

#include <daemon.h>
#include <dirs.h>
#include <unixctl.h>
#include <fatal-signal.h>
#include <command-line.h>
#include <vswitch-idl.h>
#include <openvswitch/vlog.h>

//#include "eventlog.h"
#include "passwd_srv_pri.h"

#include <openssl/rsa.h>
//VLOG_DEFINE_THIS_MODULE(passwd-srv);
#define __USE_XOPEN_EXTENDED
#include "/usr/include/ftw.h"

static char *
passwd_srv_parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        OVSDB_OPTIONS_END,
    };

    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"unixctl", required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {"ovsdb-options-end", optional_argument, NULL, OVSDB_OPTIONS_END},
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;
        int end_options = 0;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        default:
            end_options = 1;
            break;
        }
        if (end_options)
            break;
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    return NULL;
} /* passwd_srv_parse_options */


/**
 * delete directory helper function
 */
static int
_delete_helper(const char *fpath, const struct stat *sb, int typeflag,
               struct FTW *ftwbuf)
{
    int ret;
    ret = remove(fpath);
    if (0 > ret) {
        return(-1);
    }
    return(0);
}

/**
 * Setup directory in /var/run to store password server related files
 */
static void
create_directory()
{
    struct stat f_stat = {0};
    struct group *passwd_grp;

    passwd_grp = getgrnam(PASSWD_GROUP);
    setgid(passwd_grp->gr_gid);

    if (0 == stat(PASSWD_RUN_DIR, &f_stat))
    {
        if (0 == remove(PASSWD_RUN_DIR))
        {
            ;
        }
        else if (0 == nftw(PASSWD_RUN_DIR, _delete_helper, 5, FTW_DEPTH | FTW_PHYS))
        {
            ;
        }
        else
        {
            /* unable to delete directory or file */
            /* TODO: logging */
            exit(-1);
        }
    }

    /* deletion was succesful, create directory */
    mkdir(PASSWD_RUN_DIR, S_IRUSR | S_IWUSR | S_IRGRP | S_IXGRP);
}

/* password server main function */
int main(int argc, char **argv) {
    RSA *rsa;
    set_program_name(argv[0]);
    proctitle_init(argc, argv);
    fatal_ignore_sigpipe();

    /* assign program name */
    passwd_srv_parse_options(argc, argv, NULL);

    /* Fork and return in child process; but don't notify parent of
     * startup completion yet. */
    daemonize_start();

    create_directory();
    parse_passwd_srv_yaml();

    /* Notify parent of startup completion. */
    daemonize_complete();

    /* TODO: initialize event log */
    // event_log_init("PASSWD");
    /* TODO: initialize vlog */

    /* generate RSA keypair and create pubkey file */
    rsa = generate_RSA_keypair();

    /* initialize socket connection */
    listen_socket(rsa);

    // do we need signal handling?
    RSA_free(rsa);

    return 0;
}
