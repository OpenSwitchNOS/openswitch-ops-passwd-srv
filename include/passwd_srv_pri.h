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

#ifndef PASSWD_SRV_PRI_H_
#define PASSWD_SRV_PRI_H_

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/un.h>

#include "passwd_srv_pub.h"

#define TRUE  1
#define FALSE 0

#define PASSWD_PASSWORD_FILE "/etc/passwd"      /* file with user info */
#define PASSWD_SHADOW_FILE   "/etc/shadow"      /* file with password info */
#define PASSWD_GROUP_FILE    "/etc/group"       /* file with group info */
#define PASSWD_LOGIN_FILE    "/etc/login.defs"  /* encryption method stored */

#define PASSWD_RUN_DIR       "/var/run/ops-passwd-srv"
#define PASSWD_SRV_PRI_KEY_LOC \
    "/var/run/ops-passwd-srv/ops-passwd-srv-pri.pem" /*private key loc*/

#define PASSWD_SRV_YAML_KEY_MAX 2

/**
 * defines for adding user
 * defect #151 : support useradd
 * userdel for
 *
 */
#define USERADD "/usr/sbin/useradd"
#define OVSDB_GROUP "ovsdb-client"
#define NETOP_GROUP "ops_netop"
#define VTYSH_PROMPT "/usr/bin/vtysh"
#define USERDEL "/usr/sbin/userdel"
#define USER_NAME_MAX_LENGTH 32

/*
 * password server user-object data structure
 */
typedef struct passwd_client
{
    int socket;               /* client socket descriptor */
    passwd_srv_msg_t msg; 	  /* MSG from client */
    struct spwd      *passwd; /* shadow file password structure */
} passwd_client_t;

/*
 * password server internal APIs
 */
int process_client_request(passwd_client_t *client);

int create_socket();
void listen_socket();

int validate_password(passwd_client_t *client);
int validate_user(struct sockaddr_un *sockaddr, passwd_client_t *client);

int create_and_store_password(passwd_client_t *client);
struct spwd *find_password_info(const char *username);

RSA *generate_RSA_keypair();

void create_pubkey_file(RSA *rsa);

/*
 * forward declaration
 */

#endif /* PASSWD_SRV_PRI_H_ */
