/* Password server CLI commands
 *
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * File: passwd_srv_vty.c
 *
 * Purpose: User management clis to add, delete and show users
 */

#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#define _USE_GNU
#define _GNU_SOURCE 1
#include <crypt.h>
#include <ltdl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include "openswitch-idl.h"
#include "vswitch-idl.h"
#include "vtysh/command.h"
#include "vtysh/memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_utils.h"
#include "passwd_srv_vty.h"
#include "passwd_srv_pub.h"
#include "passwd_srv_pri.h"
#include "openvswitch/vlog.h"


VLOG_DEFINE_THIS_MODULE(vtysh_passwd_srv_cli);

static char sock_path[PASSWD_SRV_MAX_STR_SIZE] = {0};
static char pub_key_path[PASSWD_SRV_MAX_STR_SIZE] = {0};
static int  initialized = 0;
static int passwd_srv_pubkey_len;

/**
 * Get socket descriptor path to connect with the password server
 *
 * @return path to socket descriptor
 */
char *get_passwd_sock_fd_path(void)
{
    return (initialized)?sock_path:NULL;
}

/**
 * Get public key path to encrypt message
 *
 * @return path to socket descriptor
 */
char *get_passwd_pub_key_path(void)
{
    return (initialized)?pub_key_path:NULL;
}

/**
 * Load password shared object to retrieve socket/public-key file path
 * from yaml file
 *
 * @return 0 if file paths are retrieved successfully
 */
int passwd_srv_path_manager_init(void)
{
    lt_dlhandle so_handle = 0;
    int (*init_ptr)(void) = NULL; /* function pointer to call init funtion */
    char *(*get_path_ptr)(void) = NULL; /* function pointer to get path */
    char *path_name = NULL;

    lt_dlinit();
    lt_dlerror();

    /* open shared object to be used */
    so_handle = lt_dlopen(PASSWD_SRV_SO_LIB);

    if (lt_dlerror())
    {
        VLOG_ERR ("Failed to load the password server library");
        return -1;
    }

    init_ptr = lt_dlsym(so_handle, "init_yaml_parser");

    if ((lt_dlerror()) || (NULL == init_ptr))
    {
        VLOG_ERR ("Failed to find init_yaml_parser");
        lt_dlclose(so_handle);
        return -1;
    }

    if (PASSWD_ERR_SUCCESS != init_ptr())
    {
        VLOG_ERR ("Failed to parse yaml file");
        lt_dlclose(so_handle);
        return -1;
    }

    get_path_ptr = lt_dlsym(so_handle, "get_socket_descriptor_path");

    if ((lt_dlerror()) || (NULL == init_ptr))
    {
        VLOG_ERR ("Failed to find get_socket_descriptor_path");
        lt_dlclose(so_handle);
        return -1;
    }

    /* get socket descriptor path */
    if ((NULL == (path_name = get_path_ptr())) ||
            (PASSWD_SRV_MAX_STR_SIZE < strlen(path_name)))
    {
        VLOG_ERR ("Failed to get socket fd path");
        lt_dlclose(so_handle);
        return -1;
    }
    else
    {
        /* copy socket fd path */
        memcpy(sock_path, path_name, strlen(path_name));
        path_name = NULL;
    }

    get_path_ptr = lt_dlsym(so_handle, "get_public_key_path");

    if ((lt_dlerror()) || (NULL == init_ptr))
    {
        VLOG_ERR ("Failed to find get_public_key_path");
        lt_dlclose(so_handle);
        return -1;
    }

    /* get public key path */
    if ((NULL == (path_name = get_path_ptr())) ||
            (PASSWD_SRV_MAX_STR_SIZE < strlen(path_name)))
    {
        VLOG_ERR ("Failed to get public key path");
        lt_dlclose(so_handle);
        return -1;
    }
    else
    {
        /* copy socket fd path */
        memcpy(pub_key_path, path_name, strlen(path_name));
    }

    init_ptr = lt_dlsym(so_handle, "uninit_yaml_parser");

    if ((lt_dlerror()) || (NULL == init_ptr))
    {
        VLOG_ERR ("Failed to find init_yaml_parser");
        lt_dlclose(so_handle);
        return -1;
    }

    if (PASSWD_ERR_SUCCESS != init_ptr())
    {
        VLOG_ERR ("Failed to uninit yaml parser");
        lt_dlclose(so_handle);
        return -1;
    }

    initialized = 1;
    lt_dlclose(so_handle);
    return 0;
}

/*Function to check whether user is member of the given group*/
static int
check_user_group( const char *user, const char *group_name)
{
       int j, ngroups;
       gid_t *groups;
       struct passwd *pw;
       struct group *gr;

       ngroups = 10;
       groups = malloc(ngroups * sizeof (gid_t));
       if (groups == NULL) {
           VLOG_DBG("Malloc failed. Function = %s, Line = %d", __func__, __LINE__);
           return false;
       }

       /* Fetch passwd structure (contains first group ID for user) */

       pw = getpwnam(user);
       if (pw == NULL) {
           VLOG_DBG("Invalid User. Function = %s, Line = %d", __func__,__LINE__);
           free(groups);
           return false;
       }

       /* Retrieve group list */

       if (getgrouplist(user, pw->pw_gid, groups, &ngroups) == -1) {
           VLOG_DBG("Retrieving group list failed. Function = %s, Line = %d", __func__, __LINE__);
           free(groups);
           return false;
       }

       /* check user exist in ovsdb-client group */
       for (j = 0; j < ngroups; j++) {
           gr = getgrgid(groups[j]);
           if (gr != NULL) {
               if (!strcmp(gr->gr_name,group_name)) {
                   free(groups);
                   return true;
               }
           }
       }
       free(groups);
       return false;
}

/* Prompt for user to enter password */
static char*
get_password(const char *prompt)
{
    struct termios oflags, nflags;
    enum { sizeof_passwd = 128 };
    char *ret;
    int i;
    /* disabling echo */
    tcflush(fileno(stdin),TCIFLUSH);
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_iflag &= ~(IUCLC|IXON|IXOFF|IXANY);
    nflags.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL);
    if(tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        VLOG_DBG("setattr error");
        get_password(prompt);
    }
    write(STDIN_FILENO,prompt,strlen(prompt));

    ret = malloc(sizeof_passwd);
    i = 0;
    while (1) {
        int r = read(STDIN_FILENO, &ret[i], 1);
        if ((i == 0 && r == 0) || r < 0 ) {                     /* EOF (^D) with no password */
            ret  = NULL;
            break;
        }
        if (r == 0 || ret[i] == '\r' || ret[i] == '\n' || ++i == sizeof_passwd-1 ) {   /* EOF EOL */ /* EOL *//* line limit */
            ret[i] = '\0';
            break;
        }
    }
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        vty_out(vty,"tcsetattr");
        return CMD_SUCCESS;
    }
    return ret;
}

/**
 * This API imports the password server daemon public key from a file and uses
 * it to encrypt a message which can securely be sent to the password server.
 *
 * @param   in  message to be encypted
 * @return  pointer to encrypted message, calling function must free buffer
 */
static unsigned char *encrypt_msg_to_passwd_srv_d(passwd_srv_msg_t in, int *msg_size)
{
    RSA *pubkey = NULL;
    FILE *pubkeyfile = NULL;
    size_t maxEncryptLen = 0;
    unsigned char *enc_msg = NULL;
    int ret, success = 1;
    char *pub_key_path = NULL;

    if (NULL == (pub_key_path = (get_passwd_pub_key_path())))
    {
        VLOG_ERR("Location of the public key is unknown");
        return NULL;
    }

    if (NULL == msg_size)
    {
        VLOG_ERR("Unknown message size is received");
        return NULL;
    }

    pubkey = RSA_new();
    pubkeyfile = fopen(pub_key_path, "r");

    if (pubkeyfile == NULL)
    {
        VLOG_ERR("Cannot access public key location");
        return NULL;
    }
    /* read the PEM file on disk into memory, store thek key into a RSA* */
    pubkey = PEM_read_RSAPublicKey(pubkeyfile, &pubkey, NULL, NULL);
    if (pubkey == NULL) {

        VLOG_ERR("Cannot access public key location");
        success = 0;
        goto cleanup;
    }

    /* maxEncryptLen specifies the longest message we can send using a key of
     * our length with our padding type. Padding type must be consistent between
     * client and server so we let the server dictate what all clients must use.
     * We have chosen RSA_PKCS1_OAEP_PADDING. See man RSA_public_encrypt for
     * more details. For a given padding length, the message to encrypt must be
     * shorter than the maximum key size - x, where x is a constant determined
     * by the chosen padding type. x in our case is PASSSWDSRV_PAD_OVERHEAD */
    passwd_srv_pubkey_len = RSA_size(pubkey);
    /* Store length of the public key in a global variable so that we can free
     * our RSA object before returning from this function, yet still be able to
     * know the length of the encrypted message. */
    maxEncryptLen = RSA_size(pubkey) - PASSWDSRV_PAD_OVERHEAD;
    if (sizeof(passwd_srv_msg_t) > maxEncryptLen) {
        /* TODO: log: message is too large to be encrypted */
        VLOG_ERR("Failed to send the password update request. invalid msg size");
        success = 0;
        goto cleanup;
    }

    enc_msg = (unsigned char*) malloc(passwd_srv_pubkey_len);
    /* encrypt in and store the message into the buffer pointed to by enc_msg */
    ret = RSA_public_encrypt(sizeof(passwd_srv_msg_t), (unsigned char *) &in,
                             enc_msg, pubkey, RSA_PKCS1_OAEP_PADDING);
    if (ret != passwd_srv_pubkey_len)
    {
        VLOG_ERR("Encryption of the message has failed");
        return NULL;
    }

    /* update msg_size to let caller know about the size of the message */
    *msg_size = passwd_srv_pubkey_len;

cleanup:
    fclose(pubkeyfile);
    /* Erases key before returning memory for us, does nothing if pubkey is NULL */
    RSA_free(pubkey);
    if (success)
    {
        return enc_msg;
    }
    return NULL;
}

/**
 * This API sends credential via socket to password server
 *  password server updates password for user specified
 *
 *  @param username user
 *  @param oldpass  old password
 *  @param newpass  new password
 */
static void
send_credential_to_passwd_server(const char* username, const char* groupname, const char* oldpass,
        const char* newpass, int opcode)
{
    int sockfd, sockaddr_len, msg_len, enc_msg_size;
    struct sockaddr_un unSrv;
    passwd_srv_msg_t msg;
    unsigned char *enc_msg;
    int error_code = 0;
    char *op = NULL, *socket_path = NULL;

    if (NULL == username)
    {
        /* username cannot be NULL */
        vty_out(vty, "Invalid argument - username required %s", VTY_NEWLINE);
        return;
    }

    if (PASSWD_USERNAME_SIZE < strlen(username))
    {
        vty_out(vty, "username is not formatted properly %s", VTY_NEWLINE);
        return;
    }

    /* Prepare package for encryption */
    memset(&msg, 0, sizeof(msg));

    /*
     * MSG opcode
     * 1 == request for password update
     * 2 == request for user add
     * 3 == request for user remove
     */
    switch(opcode)
    {
    case PASSWD_MSG_DEL_USER:
    {
        /*
         * Call is made without new and old password which is called from
         * delete_user function.  we are removing user using password
         * server
         */
        msg.op_code = PASSWD_MSG_DEL_USER;
        op = "User remove";
        break;
    }
    case PASSWD_MSG_ADD_USER:
    {
        if (NULL == newpass)
        {
            vty_out(vty, "Invalid argument - require new password %s", VTY_NEWLINE);
            return;
        }
        /* we are adding user */
        msg.op_code = opcode;
        op = "User add";
        memcpy(msg.newpasswd, newpass, strlen(newpass));
        memcpy(msg.groupname, groupname, strlen(groupname));
        VLOG_ERR("Adding user copied user and grp PASSWD_MSG_ADD_USER");
        break;
    }
    case PASSWD_MSG_CHG_PASSWORD:
    {
        if ((NULL == newpass) || (NULL == oldpass))
        {
            vty_out(vty, "Invalid argument - require new & old password %s", VTY_NEWLINE);
            return;
        }

        /* we are changing user password */
        msg.op_code = PASSWD_MSG_CHG_PASSWORD;
        op = "Password update";
        memcpy(msg.newpasswd, newpass, strlen(newpass));
        memcpy(msg.oldpasswd, oldpass, strlen(oldpass));
        break;
    }
    default:
    {
        vty_out(vty, "Invalid argument %s", VTY_NEWLINE);
        return;
    }
    }

    memcpy(msg.username, username, strlen(username));
    enc_msg = encrypt_msg_to_passwd_srv_d(msg, &enc_msg_size);
    if (enc_msg == NULL)
    {
        /* Error should already be logged */
        vty_out(vty, "%s could not be executed successfully.%s", op, VTY_NEWLINE);
        return;
    }
    /*
     * Get socket file path from yaml entry
     */
    if (NULL == (socket_path = get_passwd_sock_fd_path()))
    {
        VLOG_ERR("Cannot find socket descriptor");
        vty_out(vty, "%s could not be executed successfully.%s", op, VTY_NEWLINE);
        return;
    }
    memset(&unSrv, 0, sizeof(unSrv));
    sockaddr_len = sizeof(struct sockaddr_un);
    msg_len      = sizeof(error_code);

    unSrv.sun_family = AF_UNIX;
    strncpy(unSrv.sun_path, socket_path, strlen(socket_path));

    if ((0 > (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) ||
        (0 != connect(sockfd, (struct sockaddr *)&unSrv, sockaddr_len))))
    {
        VLOG_ERR("Failed to open a socket");
        vty_out(vty, "%s could not be executed successfully.%s", op, VTY_NEWLINE);
        return;
    }
    /* send message to password server */
    /* if the message was encrypted succesfully it is necessarily the length of
     * the public key */
    if (0 > send(sockfd, enc_msg, passwd_srv_pubkey_len, MSG_DONTROUTE))
    {
        VLOG_ERR("Failed to send a message to the password server");
        vty_out(vty, "%s could not be executed successfully.%s", op, VTY_NEWLINE);

        /* close connection to server */
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
        return;
    }
    memset(enc_msg, 0, sizeof(enc_msg_size));
    free(enc_msg);
    /* clear msg since MSG has sent */
    memset(&msg, 0, sizeof(msg));

    /* waiting to receive message */
    if (0 > recv(sockfd, &error_code, msg_len, MSG_PEEK))
    {
        VLOG_ERR("Failed to receive a status from the password server");
        vty_out(vty, "%s could be not executed successfully.%s", op, VTY_NEWLINE);

        /* close connection to server */
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
        return;
    }
    /* message received by server, decode opcode */
    switch(error_code)
    {
    case PASSWD_ERR_SUCCESS:
    {
        vty_out(vty, "%s executed successfully.%s", op, VTY_NEWLINE);
        break;
    }
    case PASSWD_ERR_USER_NOT_FOUND:
    {
        vty_out(vty, "User %s is not found.%s", username, VTY_NEWLINE);
        break;
    }
    case PASSWD_ERR_PASSWORD_NOT_MATCH:
    {
        vty_out(vty, "Old password did not match.%s", VTY_NEWLINE);
        break;
    }
    case PASSWD_ERR_SHADOW_FILE:
    case PASSWD_ERR_INVALID_MSG:
    case PASSWD_ERR_INSUFFICIENT_MEM:
    {
        vty_out(vty, "%s failed [server error=%d].%s", op, error_code,
                VTY_NEWLINE);
        break;
    }
    case PASSWD_ERR_USERADD_FAILED:
    {
        vty_out(vty, "User add failed. could not add %s.%s", username, VTY_NEWLINE);
        break;
    }
    case PASSWD_ERR_USER_EXIST:
    {
        vty_out(vty, "User %s exist already.%s", username, VTY_NEWLINE);
        break;
    }
    case PASSWD_ERR_USERDEL_FAILED:
    {
        vty_out(vty, "User %s could not be deleted.%s", username, VTY_NEWLINE);
        break;
    }
    case PASSWD_ERR_DECRYPT_FAILED:
    {
        VLOG_ERR("The password server could not descrypt the message sent");
        vty_out(vty, "%s failed [server error=%d].%s", op, error_code, VTY_NEWLINE);
        break;
    }
    default:
        VLOG_ERR("The unknown status code is sent by the password server");
        vty_out(vty, "%s failed [server error=%d].%s", op, error_code, VTY_NEWLINE);
        break;
    }

    /* close connection to server */
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
}

/*Function to set the user passsword */
static int
set_user_passwd(void)
{
    int ret;
    char *passwd = NULL;
    char *oldpassword = NULL;
    char *cp = NULL;
    struct passwd *pw = NULL;

    pw = getpwuid(geteuid());
    if (pw->pw_name == NULL)
    {
        vty_out(vty, "Could not look up user.%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (pw->pw_uid == 0)
    {
        vty_out(vty, "Cannot change password of root user!%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    /* User must be in ovsdb-client group to change password */
    ret = check_user_group(pw->pw_name, OVSDB_GROUP);
    if (ret!=1)
    {
        vty_out(vty, "User does not belong to group ovsdb-client.%s",
                VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    vty_out(vty,"Changing password for user %s %s", pw->pw_name, VTY_NEWLINE);
    oldpassword = get_password("Enter old password: ");
    vty_out(vty, "%s", VTY_NEWLINE);

    passwd = get_password("Enter new password: ");
    vty_out(vty, "%s", VTY_NEWLINE);

    if (strcmp(passwd,"") == 0)
    {
        vty_out(vty, "Entered empty password.%s", VTY_NEWLINE);
        goto cleanup;
    }

    cp = get_password("Confirm new password: ");
    vty_out(vty, "%s", VTY_NEWLINE);
    if (strcmp(passwd,cp) != 0)
    {
        vty_out(vty,"Passwords did not match. Password unchanged.%s",
                VTY_NEWLINE);
        goto cleanup;
    }
    else {
        send_credential_to_passwd_server(pw->pw_name, NULL, oldpassword, passwd,
                PASSWD_MSG_CHG_PASSWORD);
    }

cleanup:
    if (oldpassword!=NULL)
    {
        memset(oldpassword, 0, strlen(oldpassword));
        free(oldpassword);
    }
    if (passwd!=NULL)
    {
        memset(passwd, 0, strlen(passwd));
        free(passwd);
    }
    if (cp!=NULL)
    {
        memset(cp, 0, strlen(cp));
        free(cp);
    }

    return CMD_SUCCESS;

}

#ifdef ENABLE_OVSDB
DEFUN (vtysh_passwd,
       vtysh_passwd_cmd,
       "password",
       "Change user password \n")
{
    return set_user_passwd();
}
#endif


static int
get_group_index(const char *group, int ops)
{
    static char *display_grp[MAX_OPS_GROUP] = {"admin",
                                               "netop"
                                              };
    static char *ops_grp[MAX_OPS_GROUP] = {"ops_admin",
                                           "ops_netop"
                                          };
    if (group == NULL)
    {
        return -1;
    }
    for (int i = 0; i < MAX_OPS_GROUP; i++)
    {
        if (ops)
        {
            if ((ops_grp[i] !=NULL) && !strcmp(ops_grp[i], group))
                return i;
        }
        else
        {
            if ((display_grp[i] !=NULL) && !strcmp(display_grp[i], group))
                return i;
        }
    }
    return -1;
}

static int
get_user_list(user_list *p_users)
{
    int           j = 0;
    int           group_index = 0;
    int           ngroups = MAX_GROUPS_USED;
    gid_t         *groups;
    struct passwd *p_user;
    struct group  *gr;

    groups = malloc(ngroups * sizeof(gid_t));

    if (groups == NULL)
    {
        VLOG_ERR("malloc failed. Function = %s, Line =%d",__func__, __LINE__);
        return 0; //Failure
    }

    /* Rewind to the beginning of the password database. */
    setpwent();

    /* Get the first record from the password database. */
    p_user = getpwent();
    while (p_user != NULL)
    {
        ngroups = MAX_GROUPS_USED;
        memset(groups, 0, ngroups * sizeof(gid_t));
        /* Retrieve all the groups of p_user. */
        if (getgrouplist(p_user->pw_name, p_user->pw_gid,groups,
                         &ngroups) != -1)
        {
            for (j = 0; j < ngroups; j++)
            {
                gr = getgrgid(groups[j]);
                /* Populate if p_user belongs to ops-group. */
                group_index = get_group_index(gr->gr_name, OPS_GRP);
                if ((gr != NULL) && (group_index != -1))
                {
                    p_users->usr_grp_tuple[group_index * MAX_USERS_PER_GROUP
                    + p_users->user_count[group_index]].uid = p_user->pw_uid;

                    p_users->usr_grp_tuple[group_index * MAX_USERS_PER_GROUP
                    + p_users->user_count[group_index]].gid = gr->gr_gid;

                    p_users->user_count[group_index] += 1;
                    break;
                }
            }
        }
        else
        {
            VLOG_ERR("Retrieving group-list failed for %s, ngroups: %d",
                      p_user->pw_name, ngroups);
        }
        /* Get the next record from the password database. */
        p_user = getpwent();
    }
    free(groups);
    /* Close the password database. */
    endpwent();
    return 1; //Success
}

/* Function to create new user with password and add it to the ovsdb-cliet group*/
static int
create_new_vtysh_user(const char *user, const char *group)
{
    struct crypt_data data;
    data.initialized = 0;
    char *password = NULL;
    char *passwd = NULL;
    char *cp = NULL;
    user_list users;
    int group_index = 0;

    if (!strcmp(user, "root")) {
        vty_out(vty, "Permission denied. Cannot add the root user.%s",
                VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    if (strcmp(group, "admin") && strcmp(group, "netop")) {
        vty_out(vty, "%s is not a valid group name.%s", group, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    for (int i = 0; i < MAX_OPS_GROUP; i++)
    {
        users.user_count[i] = 0;
    }
    get_user_list(&users);
    group_index = get_group_index(group, DISPLAY_GRP);
    if ((group_index != -1) && (users.user_count[group_index] >= MAX_USERS_PER_GROUP))
    {
        vty_out(vty, "Maximum number of users for group %s has been reached.%s", group, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }
    vty_out(vty,"Adding user %s%s", user, VTY_NEWLINE);
    passwd = get_password("Enter password: ");
    if (!passwd)
    {
        vty_out(vty, "%s", VTY_NEWLINE);
        vty_out(vty, "Entered empty password");
    }
    vty_out(vty, "%s", VTY_NEWLINE);
    cp = get_password("Confirm password: ");
    if (!cp)
    {
        vty_out(vty, "%s", VTY_NEWLINE);
        vty_out(vty,"Entered empty password");
    }
    if (strcmp(passwd,cp) != 0) {
        vty_out(vty, "%s", VTY_NEWLINE);
        vty_out(vty,"Passwords do not match. ");
        vty_out(vty,"User %s not added.%s", user, VTY_NEWLINE);
        free(cp);
        free(passwd);
        return CMD_ERR_NOTHING_TODO;
    }
    password = crypt_r(passwd,"ab",&data);
    if (!password)
    {
        vty_out(vty,"Failed to create new user.%s", VTY_NEWLINE);
        free(cp);
        free(passwd);
        return CMD_ERR_NOTHING_TODO;
    }

    send_credential_to_passwd_server(user, group, NULL, passwd, PASSWD_MSG_ADD_USER);

    free(cp);
    free(passwd);
    return CMD_SUCCESS;
}

/*
 * TODO: THis command maybe re used later once RBAC CLI infra comes up
 */
DEFUN(vtysh_user_add,
       vtysh_user_add_cmd,
       "user add WORD group WORD",
       "User account\n"
       "Adding a new user account\n"
       "User name to be added\n"
       "Adding user to the group\n"
       "User group to which user will be added")
{
    return create_new_vtysh_user(argv[0], argv[1]);

}

/* Delete user account. */
static int
delete_user(const char *user)
{
    if (!strcmp(user, "root")) {
        vty_out(vty, "Permission denied. Cannot remove the root user.%s",
                VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    send_credential_to_passwd_server(user, NULL, NULL, NULL, PASSWD_MSG_DEL_USER);

    return CMD_SUCCESS;
}

/*
 * TODO: THis command maybe re used later once RBAC CLI infra comes up
 */
DEFUN(vtysh_user_del,
       vtysh_user_del_cmd,
       "user remove WORD",
       "User account\n"
       "Delete a user account\n"
       "User name to be deleted\n")
{
    return delete_user(argv[0]);
}

/*
 * Converts ops group name to displayable name.
 * For example "ops_admin" to "admin".
 */
static int
convert_to_ops_group(int group_index, char *display_grp_name)
{
    static char *group_name[MAX_OPS_GROUP] = {"admin",
                                              "netop"
                                             };
    if (group_index >= MAX_OPS_GROUP)
    {
        return -1;
    }
    else
    {
        strncpy(display_grp_name, group_name[group_index], MAX_GRP_NAME_SIZE);
        return 1;
    }
}

DEFUN(vtysh_user_list,
      vtysh_user_list_cmd,
      "show user-list",
      SHOW_STR
      "Displays the list of local users\n")
{
    struct group   * gr;
    struct passwd  *pw;
    user_list      users;
    int            group_index = 0;
    char           group_name[MAX_GRP_NAME_SIZE];

    vty_out(vty, "%-32s %-32s%s", "USER", "GROUP", VTY_NEWLINE);
    vty_out(vty, "---------------------------------------%s", VTY_NEWLINE);
    for (int i = 0; i < MAX_OPS_GROUP; i++)
    {
        users.user_count[i] = 0;
    }
    if (!get_user_list(&users))
    {
        return CMD_ERR_NOTHING_TODO;
    }
    for (int i = 0; i < MAX_OPS_GROUP; i++)
    {
        for (int j = 0; j < users.user_count[i]; j++)
        {
            pw = getpwuid(users.usr_grp_tuple[i * MAX_USERS_PER_GROUP + j].uid);
            gr = getgrgid(users.usr_grp_tuple[i * MAX_USERS_PER_GROUP + j].gid);
            group_index = get_group_index(gr->gr_name, OPS_GRP);
            if ((group_index != -1) &&
                convert_to_ops_group(group_index, group_name))
            {
                vty_out(vty, "%-32s %-32s%s", pw->pw_name
                                            , group_name
                                            , VTY_NEWLINE);
            }
        }
    }
    return CMD_SUCCESS;
}

void
cli_pre_init(void)
{
    /* parse yaml file to be used by 'password' command */
    passwd_srv_path_manager_init();
}

void
cli_post_init(void)
{
   /* get the logged in user info and install cli accordingly*/
   struct passwd *pw = NULL;
   pw = getpwuid( getuid());
   install_element (ENABLE_NODE, &vtysh_passwd_cmd);
   if(check_user_group(pw->pw_name, ADMIN_GROUP))
   {
       install_element (ENABLE_NODE, &vtysh_user_add_cmd);
       install_element (ENABLE_NODE, &vtysh_user_del_cmd);
       install_element (ENABLE_NODE, &vtysh_user_list_cmd);
   }
   return;
}