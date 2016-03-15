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

#include "passwd_srv_pub.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PASSWD_PASSWORD_FILE "/etc/passwd"      /* file with user info */
#define PASSWD_SHADOW_FILE   "/etc/shadow"      /* file with password info */
#define PASSWD_GROUP_FILE    "/etc/group"       /* file with group info */
#define PASSWD_LOGIN_FILE    "/etc/login.defs"  /* encryption method stored */

#define PASSWD_SRV_PRI_KEY_LOC \
    "/var/run/ops-passwd-srv/ops-passwd-srv-pri.pem" /*private key loc*/

/*
 * password server user-object datat structure
 */
typedef struct passwd_client
{
    int socket;               /* client socket descriptor */
    passwd_srv_msg_t msg; 	  /* MSG from client */
    struct spwd      *passwd; /* shadow file password structure */
} passwd_client_t;

enum PASSWD_error_code_e {
    PASSWD_ERR_OK = 0x0,
    PASSWD_ERR_UNKNOWN_ERROR,
    PASSWD_ERR_INVALID_SOCKET,
    PASSWD_ERR_MAX
};

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
