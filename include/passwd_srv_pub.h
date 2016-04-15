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
#define PASSWD_USERNAME_SIZE 50                         /* size of username */
#define PASSWD_PASSWORD_SIZE 50                         /* size of password */
#define PASSWD_SRV_FP_SIZE   255
#define PASSWD_SRV_MAX_STR_SIZE   255
#define PASSWD_SRV_PUB_KEY_LEN 2048                     /* key length in bits */
#define PASSWDSRV_PAD_OVERHEAD  41
/*
 * Message type definition
 *
 * When client sends message, below are valid messages
 *
 * TODO: for now, client can only request to change password, maybe more
 * 		  in the future
 */
#define PASSWD_MSG_CHG_PASSWORD 1 /* request to change password */
#define PASSWD_MSG_ADD_USER     2 /* request to add user */
#define PASSWD_MSG_DEL_USER     3 /* request to del user */

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
#define PASSWD_ERR_PASSWD_UPD_FAIL    10 /* password update failed */
#define PASSWD_ERR_SEND_FAILED        11 /* Failed to send MSG */
#define PASSWD_ERR_USERADD_FAILED     12 /* Failed to add user */
#define PASSWD_ERR_USER_EXIST         13 /* Failed to add user */
#define PASSWD_ERR_USERDEL_FAILED     14 /* Failed to del user */
#define PASSWD_ERR_DECRYPT_FAILED     15 /* Failed to decrypt client message */
#define PASSWD_ERR_YAML_FILE          16 /* error accessing yaml file */


/*
 * MSG structure used by client to send user info to server
 */
typedef struct passwd_srv_msg {
    int  op_code;
    char username[PASSWD_USERNAME_SIZE+1];
    char oldpasswd[PASSWD_PASSWORD_SIZE+1];
    char newpasswd[PASSWD_PASSWORD_SIZE+1];
} passwd_srv_msg_t;

/*
 * Definitions use to parse YAML file for file path
 */

#define PASSWD_SRV_YAML_FILE "/etc/ops-passwd-srv/ops-passwd-srv.yaml"

enum PASSWD_yaml_path_type_e {
    PASSWD_SRV_YAML_PATH_NONE = 0x0,
    PASSWD_SRV_YAML_PATH_SOCK,
    PASSWD_SRV_YAML_PATH_PUB_KEY,
    PASSWD_SRV_YAML_PATH_MAX
};

enum PASSWD_yaml_key_e {
    PASSWD_SRV_YAML_VALUE = 0x0,
    PASSWD_SRV_YAML_PATH_TYPE,
    PASSWD_SRV_YAML_PATH,
    PASSWD_SRV_YAML_DESC,
    PASSWD_SRV_YAML_MAX
};

typedef struct passwd_yaml_file_path {
    enum PASSWD_yaml_path_type_e type;
    char    path[PASSWD_SRV_MAX_STR_SIZE];
    char    desc[PASSWD_SRV_MAX_STR_SIZE];
    struct  passwd_yaml_file_path *next;
} passwd_yaml_file_path_t;

extern int parse_passwd_srv_yaml();
extern char *get_file_path(enum PASSWD_yaml_path_type_e type);
extern char *get_socket_descriptor_path();
extern char *get_public_key_path();
extern int  init_yaml_parser();
extern int  uninit_yaml_parser();

#endif /* PASSWD_SRV_PUB_H_ */
