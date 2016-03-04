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

#ifndef PASSWD_SRV_PUB_H_
#define PASSWD_SRV_PUB_H_

/*
 * global definitions
 */
#define PASSWD_SRV_SOCK_FD \
    "/var/run/ops-passwd-srv/ops-passwd-srv.sock" /* socket descriptor */
#define PASSWD_USERNAME_SIZE 50                         /* size of username */
#define PASSWD_PASSWORD_SIZE 50                         /* size of password */
#define PASSWD_SRV_FP_SIZE   255
#define PASSWD_SRV_PUB_KEY_LOC \
    "/var/run/ops-passwd-srv/ops-passwd-srv-pub.pem" /* public key loc*/

/*
 * Message type definition
 *
 * When client sends message, below are valid messages
 *
 * TODO: for now, client can only request to change password, maybe more
 * 		  in the future
 */
#define PASSWD_MSG_CHG_PASSWORD 1 /* request to change password */


/*
 * Error code definition
 *
 * Password server sends error code whenever client requests to validate
 *  password for the user
 */
#define PASSWD_ERR_FATAL             -1 /* fatal error */
#define PASSWD_ERR_SUCCESS            0  /* operation succeeded */
#define PASSWD_ERR_USER_NOT_FOUND     1  /* user not found */
#define PASSWD_ERR_PASSWORD_NOT_MATCH 2  /* old password cannot be validate */
#define PASSWD_ERR_SHADOW_FILE        3  /* error accessing shadow file */
#define PASSWD_ERR_INVALID_MSG        4  /* received invalid MSG */
#define PASSWD_ERR_INSUFFICIENT_MEM   5  /* failed to alloc memory */
#define PASSWD_ERR_RECV_FAILED        6  /* failed to recv all MSG */
#define PASSWD_ERR_INVALID_OPCODE     7  /* invalid op-code from client */
#define PASSWD_ERR_INVALID_USER       8  /* user does not have privilege */
#define PASSWD_ERR_INVALID_PARAM      9  /* invalid parameter */
#define PASSWD_ERR_PASSWD_UPD_FAIL   10  /* password update failed */
#define PASSWD_ERR_SEND_FAILED       11  /* Failed to send MSG */


/*
 * MSG structure used by client to send user info to server
 */
typedef struct passwd_srv_msg {
    int  op_code;
	char username[PASSWD_USERNAME_SIZE];
	char oldpasswd[PASSWD_PASSWORD_SIZE];
	char newpasswd[PASSWD_PASSWORD_SIZE];
	char file_path[PASSWD_SRV_FP_SIZE];
} passwd_srv_msg_t;


#endif /* PASSWD_SRV_PUB_H_ */
