/* Passwd srv CLI commands header file
 *
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * File: passwd_srv_vty.h
 *
 * Purpose:  To add declarations required for passwd_srv_vty.c
 */

#ifndef _PASSWD_SRV_VTY_H
#define _PASSWD_SRV_VTY_H

#define PASSWD_SRV_SO_LIB "/usr/lib/libpasswd_srv.so.0.1.0"

#define PASSWD       "/usr/bin/passwd"
#define MAX_OPS_GROUP           16
#define MAX_USERS_PER_GROUP     8
#define MAX_TOTAL_USERS         128
#define MAX_GRP_NAME_SIZE       32
#define MAX_GROUPS_USED         (NGROUPS_MAX / 1000)

#define USER_STR              "User account\n"
#define USER_ADD_STR          "Adding a new user account\n"
#define USER_NAME_STR         "User name to be added\n"
#define USER_GROUP_STR        "Adding user to the group\n"
#define USER_GROUP_ADMIN_STR  "Adding user to the ops_admin group\n"
#define USER_GROUP_NETOP_STR  "Adding user to the ops_netop group\n"
#define USER_DELETE_STR       "Delete a user account\n"
#define USER_NAME_DELETE_STR  "User name to be deleted\n"
#define USER_SHOW_STR         "Displays the list of local users\n"

#define ROOT_USER     "root"
#define ADMIN_USER    "admin"
#define NETOP_USER    "netop"

enum
{
    DISPLAY_GRP,
    OPS_GRP
};
typedef struct _tuple
{
    uid_t uid;
    gid_t gid;
}tuple;

typedef struct _user_list
{
    int user_count[MAX_OPS_GROUP];
    tuple usr_grp_tuple[MAX_OPS_GROUP * MAX_USERS_PER_GROUP];
}user_list;

void cli_pre_init(void);

void cli_post_init(void);

char *get_passwd_sock_fd_path(void);
char *get_passwd_pub_key_path(void);
int passwd_srv_path_manager_init(void);

#endif // _PASSWD_SRV_VTY_H
