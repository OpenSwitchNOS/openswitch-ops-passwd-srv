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
#include <sys/types.h>
#include <sys/stat.h>
#include <crypt.h> /* TODO: investigation needed to replace it with openssl */
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <grp.h>
#include <sys/socket.h>
#include <dirent.h>

#include "openvswitch/vlog.h"
#include "passwd_srv_pri.h"
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

VLOG_DEFINE_THIS_MODULE(passwd_srv_util);

/*
 *  Generate salt of size salt_size.
 */
#define MAX_SALT_SIZE 16
#define MIN_SALT_SIZE 8

#define MAGNUM(array,ch) (array)[0]=(array)[2]='$',(array)[1]=(ch),(array)[3]='\0'

static char *crypt_method = NULL;

/*
 * RNG function to generate seed to make salt
 *
 * @param reset whether API needs to re-seed
 */
static
void create_seed (int reset)
{
    struct timeval time_value;
    static int seeded = 0;

    seeded = (reset) ? 0 : seeded;

    if (!seeded)
    {
        gettimeofday (&time_value, NULL);
        srandom (time_value.tv_sec ^ time_value.tv_usec ^ getgid ());
        seeded = 1;
    }
}

/*
 * make salt based on size provided by caller
 *
 * @param salt_size size of salt
 * @return salt generated, or NULL if error happens
 */
static
const char *generate_salt (size_t salt_size)
{
    static char salt[32];

    salt[0] = '\0';

    if(! (salt_size >= MIN_SALT_SIZE &&
            salt_size <= MAX_SALT_SIZE))
    {
        return NULL;
    }
    create_seed (0);
    strcat (salt, l64a (random()));
    do {
        strcat (salt, l64a (random()));
    } while (strlen (salt) < salt_size);

    salt[salt_size] = '\0';

    return salt;
}

/*
 * Generate RSA public / private key pair
 * @return RSA * object containing RSA key pair. Must be deallocated using
 * RSA_free() when you are done with it.
*/
RSA *generate_RSA_keypair() {
    RSA *rsa = NULL;
    /* to hold the keypair to be generated */
    BIGNUM *bne = NULL;
    /* public exponent for RSA key generation */
    int ret, key_generate_failed=0;
    unsigned long e = RSA_F4;
    BIO *bp_public = NULL;
    /* BIO - openssl type, stands for Basic Input Output, serves as a wrapper
     * for a file pointer in many openssl functions */
    struct group *ovsdb_client_grp;
    char *pub_key_path = NULL;

    /*
     * Get public key location from yaml
     */
    if (NULL == (pub_key_path = get_file_path(PASSWD_SRV_YAML_PATH_PUB_KEY)))
    {
        VLOG_ERR("Failed to get the location of public key storage");
        goto cleanup;
    }

    /* seed random number generator */
    RAND_poll();

    rsa = RSA_new();
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret == 0) {
        VLOG_ERR("Failed to generate private/public key");
        key_generate_failed = 1;
        goto cleanup;
    }

    /* generate a key of key_len length, after generation this will be equal to
     * RSA_size(rsa), this is the maximum length that an encrypted message can
     * be including padding. This is also the size that the decrypted message
     * will be after decryption */
    RSA_generate_key_ex(rsa, PASSWD_SRV_PUB_KEY_LEN, bne, NULL);
    if (ret != 1)
    {
        VLOG_ERR("Failed to generate private/public key");
        key_generate_failed = 1;
        goto cleanup;
    }

    /* save public key to a file in PEM format */
    bp_public = BIO_new_file(pub_key_path, "wx");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
    if (ret != 1)
    {
        VLOG_ERR("Failed to save public key");
        key_generate_failed = 1;
        goto cleanup;

    }

cleanup:
    BIO_free_all(bp_public);
    BN_clear_free(bne);

    if (key_generate_failed)
    {
        /* it seems that the desirable behaviour if this happens is to exit, but
         * if the --monitor argument is used the process may continually
         * respawn */
        exit(1);
    }

    /* make the file readable by owner and group */
    umask(S_IRUSR | S_IWUSR | S_IRGRP);
    if ((ovsdb_client_grp = getgrnam("ovsdb-client")))
    {
        /* if group is not found, skip setting gid */
        VLOG_INFO("Couldn't set the public key to ovsdb-client group");
        chown(pub_key_path, getuid(), ovsdb_client_grp->gr_gid);
    }

    /* Calling function must do RSA_free(rsa) when it is done with resource */
    return rsa;
}

/*
 * Return the salt size.
 * The size of the salt string is between 8 and 16 bytes for the SHA crypt
 * methods.
 */
static size_t SHA_salt_size ()
{
    double rand_size;
    create_seed (0);
    rand_size = (double) 9.0 * random () / RAND_MAX;
    return (size_t) (8 + rand_size);
}

/**
 * Search thru login.defs file and return value string that found.
 *
 * @param target string to search in login.defs
 * @return value found from searching string, NULL if target string is not
 *          found
 */
static
char *search_login_defs(const char *target)
{
    char line[1024], *value, *temp;
    FILE *fpLogin;

    /* find encrypt_method and assign it to static crypt_method */
    if (NULL == (fpLogin = fopen(PASSWD_LOGIN_FILE, "r")))
    {
        /* cannot open login.defs file for read */
        return NULL;
    }

    while (fgets(line, sizeof(line), fpLogin))
    {
        if ((0 == memcmp(line, target, strlen(target))) &&
            (' ' == line[strlen(target)]))
        {
            /* found matching string, find next token and return */
            temp = &(line[strlen(target) + 1]);
            value = strdup(temp);
            value[strlen(value)] = '\0';

            fclose(fpLogin);
            return value;
        }
    } /* while */

    fclose(fpLogin);
    return NULL;
}

/**
 * Create a user using useradd program
 *
 * @param username username to add
 * @param useradd  add if true, deleate otherwise
 */
static
struct spwd *create_user(const char *username, int useradd)
{
    char useradd_comm[512];
    struct spwd *passwd_entry = NULL;

    memset(useradd_comm, 0, sizeof(useradd_comm));

    if (useradd)
    {
        snprintf(useradd_comm, sizeof(useradd_comm),
            "%s -g %s -G %s -s %s %s", USERADD, NETOP_GROUP, OVSDB_GROUP,
            VTYSH_PROMPT, username);
    }
    else
    {
        snprintf(useradd_comm, sizeof(useradd_comm),
                    "%s %s", USERDEL, username);
    }

    if (0 > system(useradd_comm))
    {
        memset(useradd_comm, 0, sizeof(useradd_comm));
        return NULL;
    }

    /* make sure that user has been created */
    if (useradd && NULL == (passwd_entry = find_password_info(username)))
    {
        memset(useradd_comm, 0, sizeof(useradd_comm));
        return NULL;
    }

    memset(useradd_comm, 0, sizeof(useradd_comm));
    return passwd_entry;
}

/**
 * Look into login.defs file to find encryption method
 *  If encrypt_method is not found, hashing algorighm
 *  falls back to MD5 or DES.
 */
static
void find_encrypt_method()
{
    char *method = NULL;

    /* search login.defs to get method */
    method = search_login_defs("ENCRYPT_METHOD");

    if (NULL == method)
    {
        /* couldn't find encrypt_method, search for md5 */
        method = search_login_defs("MD5_CRYPT_ENAB");

        if (NULL == method || 0 == strncmp(method, "no", strlen(method)))
        {
            crypt_method = strdup("DES");
        }
        else
        {
            crypt_method = strdup("MD5");
        }

        if (method)
        {
            free(method);
        }

        return;
    }

    crypt_method = strdup(method);

    free(method);
}

/**
 * Create new salt to be used to create hashed password
 */
static
char *create_new_salt()
{
    /* Max result size for the SHA methods:
     *  +3      $5$
     *  +17     rounds=999999999$
     *  +16     salt
     *  +1      \0
     */
    static char result[40];
    size_t salt_len = 8;

    /* notify seed RNG to reset its seeded value to seeding again */
    create_seed(1);

    /* TODO: find a way to handle login.defs file change */
    if (NULL == crypt_method)
    {
        /* find out which method to use */
        find_encrypt_method();
    }

    if (0 == strncmp (crypt_method, "MD5", strlen("MD5")))
    {
        MAGNUM(result, '1');
    }
    else if (0 == strncmp (crypt_method, "SHA256", strlen("SHA256")))
    {
        MAGNUM(result, '5');
        salt_len = SHA_salt_size();
    }
    else if (0 == strncmp (crypt_method, "SHA512", strlen("SHA512")))
    {
        MAGNUM(result, '6');
        salt_len = SHA_salt_size();
    }
    else if (0 != strncmp (crypt_method, "DES", strlen("DES")))
    {
        result[0] = '\0';
    }
    else
    {
        return NULL;
    }

    /*
     * Concatenate a pseudo random salt.
     */
    strncat (result, generate_salt (salt_len),
         sizeof (result) - strlen (result) - 1);

    return strdup(result);
}

/**
 * verify user based on group information
 *
 * @user username
 * @group_name group which user must be the part of it
 * @return true if user is in the specified group
 */
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

/**
 * Using inode information retrieved by calling kernel via netlink,
 * get a pid of the socket client connected to the password server
 *
 * @param passwd_srv_peer peer inode information
 * @return pid of the client, 0 if none found
 */
static int
get_client_pid_info(int passwd_srv_peer)
{
    DIR *proc_dir, *sub_dir;
    struct dirent *proc_dir_entry, *fd_dir_entry;
    int pid, fd;
    char fd_dir_name[PASSWD_SRV_MAX_STR_SIZE], trailing_ch;
    char sub_name[PASSWD_SRV_MAX_STR_SIZE+PASSWD_USERNAME_SIZE];

    const char *pattern = "socket:[";
    unsigned int peer_ino;
    char lnk[PASSWD_SRV_MAX_STR_SIZE];
    ssize_t link_len;

    /* open /proc directory to search files in fd */
    if ((proc_dir = opendir("/proc/")) == NULL)
    {
        VLOG_ERR("Failed to open /proc/");
        return 0;
    }

    while ((proc_dir_entry = readdir(proc_dir)) != NULL) {

        if (sscanf(proc_dir_entry->d_name, "%d%c", &pid, &trailing_ch) != 1){
            /* we only care about directory named after pid */
            continue;
        }

        snprintf(fd_dir_name, PASSWD_SRV_MAX_STR_SIZE-1, "/proc/%d/fd", pid);

        if ((sub_dir = opendir(fd_dir_name)) == NULL) {
            /*/proc/pid/fd directory cannot be opened, move onto next one */
            VLOG_DBG("Cannot open %s", fd_dir_name);
            continue;
        }

        while ((fd_dir_entry = readdir(sub_dir)) != NULL) {

            fd = 0;
            link_len = 0;
            peer_ino = 0;
            memset(lnk, 0, PASSWD_SRV_MAX_STR_SIZE);

            if (sscanf(fd_dir_entry->d_name, "%d%c", &fd, &trailing_ch) != 1)
            {
                /* we only care about socket inode which is integer number */
                continue;
            }

            snprintf(sub_name, PASSWD_SRV_MAX_STR_SIZE+PASSWD_USERNAME_SIZE-1,
                    "/proc/%d/fd/%d", pid, fd);

            /*
             * file found is a socket inode description which is symlinked
             */
            link_len = readlink(sub_name, lnk, PASSWD_SRV_MAX_STR_SIZE-1);

            if (link_len == -1)
            {
                VLOG_DBG("Failed to get link info for %s", sub_name);
                continue;
            }

            /* append null terminator to symlink string */
            lnk[link_len] = '\0';

            if (strncmp(lnk, pattern, strlen(pattern)))
            {
                /* file in fd folder is not socket inode, move onto the next */
                continue;
            }

            sscanf(lnk, "socket:[%u]", &peer_ino);

            if (peer_ino == passwd_srv_peer)
            {
                /* found the peer inode */
                closedir(sub_dir);
                closedir(proc_dir);
                return pid;
            }
        }

        closedir(sub_dir);
    }
    closedir(proc_dir);
    return 0;
}

/**
 * Get socket inode of the password server which is connected with the client
 *
 * @param client_socket socket fd returned via accept() call
 * @return socket inode of the password server, 0 if none found
 */
static int
get_server_ino_info(int client_socket)
{
    int len = 0, inode = 0;
    char fd_content[1024] = {0};
    char fd_location[1024] = {0};

    snprintf(fd_location, 1023, "/proc/%d/fd/%d", getpid(), client_socket);

    if ((len = readlink(fd_location, fd_content, 1023)) <= 0)
    {
        return 0;
    }

    sscanf(fd_content, "socket:[%u]", &inode);

    return inode;
}

/**
 * Get the username of connected client
 *
 * @param pid process ID of the running process connected via a socket
 * @return username of the process, NULL if user is not known
 */
static char*
get_client_username(int pid)
{
    char stat_string[PASSWD_USERNAME_SIZE];
    struct stat u_stat;
    struct passwd *user;

    snprintf(stat_string, PASSWD_USERNAME_SIZE - 1, "/proc/%d/stat", pid);

    stat(stat_string, &u_stat);

    if ((user = getpwuid(u_stat.st_uid)) == NULL) {
        VLOG_ERR("Cannot stat %s stat_string", stat_string);
        return NULL;
    }

    return strdup(user->pw_name);
}

/*
 * Update password for the user. Search for the username in /etc/shadow and
 * update password string with on passed onto it.
 *
 * @param user username to find
 * @param pass password to store
 * @return SUCCESS if updated, error code if fails to update
 */
int store_password(char *user, char *pass)
{
    FILE *fpShadow;
    long int cur_pos = 0;
    struct spwd *cur_user;
    int cur_uname_len, uname_len;
    char newpass[512];
    int err = PASSWD_ERR_PASSWD_UPD_FAIL;

    memset(newpass, 0, sizeof(newpass));
    memcpy(newpass, pass, strlen(pass));

    uname_len = strlen(user);

    /* lock shadow file */
    if (0 != lckpwdf())
    {
        return PASSWD_ERR_FATAL;
    }

    if (NULL == (fpShadow = fopen(PASSWD_SHADOW_FILE, "r+a")))
    {
        return PASSWD_ERR_FATAL;
    }

    /* save file position */
    cur_pos = ftell(fpShadow);

    while((cur_user = fgetspent(fpShadow)))
    {
        cur_uname_len = strlen(cur_user->sp_namp);

       if ( (cur_uname_len == uname_len) &&
               (0 == strncmp(cur_user->sp_namp, user, strlen(user))) )
       {
           /* found the match, set file pointer to current user location */
           fsetpos(fpShadow, (const fpos_t*)&cur_pos);

           cur_user->sp_pwdp = newpass;

           /* update password info */
           putspent(cur_user, fpShadow);

           err = PASSWD_ERR_SUCCESS;
           break;
       }

       /* save file position */
       cur_pos = ftell(fpShadow);
    }

    /* unlock shadow file */
    ulckpwdf();
    fclose(fpShadow);

    return err;
}

/*
 * Create salt/password to update password in /etc/shadow
 *
 * @param client target client to update password
 * @return SUCCESS if password updated, error code otherwise
 */
int create_and_store_password(passwd_client_t *client)
{
    char *salt = NULL;
    char *password, *newpassword;
    int  err = 0;

    if ((NULL == client) || (NULL == client->passwd))
    {
        return PASSWD_ERR_INVALID_PARAM;
    }

    salt = create_new_salt();
    password = strdup(client->msg.newpasswd);

    /*
     * generate new password using crypt
     *
     * TODO: replace crypt() with openssl.
     *       - investigate to implement logic with openssl to support
     *          any encryption method defined in logins.def file
     *          i.e. SHA512 is not supported by 'openssl passwd'
     */
    newpassword = crypt(password, salt);

    /* store it to shadow file */
    err = store_password(client->msg.username, newpassword);

    memset(newpassword, 0, strlen(newpassword));
    memset(password, 0, strlen(password));
    memset(salt, 0, strlen(salt));
    free(salt);
    free(password);

    return err;
}

/**
 * Find username of the connected client
 *
 * @param socket_client socket FD connected to the client
 * @return username
 */
char *
get_connected_username(int socket_client)
{
    int passwd_srv_ino = 0, passwd_srv_peer = 0, pid = 0;
    char *username = NULL;

    /* find matching process for ino */
    if ((passwd_srv_ino = get_server_ino_info(socket_client)) == 0)
    {
        VLOG_ERR("Cannot find socket inode (s=%d)", socket_client);
        return NULL;
    }

    // passwd_srv_peer = get_peer_ino_info(passwd_srv_ino);
    if ((passwd_srv_peer = find_connected_client_inode(passwd_srv_ino)) == 0)
    {
        VLOG_ERR("Cannot find socket inode of connected peer ");
        return NULL;
    }

    /* get pid of connected client */
    if ((pid = get_client_pid_info(passwd_srv_peer)) == 0)
    {
        VLOG_ERR("Cannot find PID of connected peer ");
        return NULL;
    }

    /* get username based on pid */
    if ((username = get_client_username(pid)) == NULL)
    {
        VLOG_ERR("Cannot find username for pid=%d", pid);
        return NULL;
    }

    return username;
}

/**
 * validate user information using socket descriptor and passwd file
 *
 * @param client    client structure entry
 *
 * @return 0 if client is ok to update pasword
 */
int validate_user(int opcode, char *client)
{
    if (NULL == client)
    {
        return PASSWD_ERR_INVALID_USER;
    }

    if ((strlen(client) == strlen("root")) && (strcmp(client, "root")) == 0)
    {
        /* connected client is root */
        return PASSWD_ERR_SUCCESS;
    }

    /* verify that client has privilege */
    switch(opcode)
    {
    case PASSWD_MSG_CHG_PASSWORD:
    {
        if (!check_user_group(client, OVSDB_GROUP) != PASSWD_ERR_SUCCESS)
        {
            return PASSWD_ERR_INVALID_USER;
        }
        break;
    }
    case PASSWD_MSG_ADD_USER:
    case PASSWD_MSG_DEL_USER:
    {
        if (!check_user_group(client, ADMIN_GROUP) != PASSWD_ERR_SUCCESS)
        {
            return PASSWD_ERR_INVALID_USER;
        }
        break;
    }
    default:
    {
        /* operation is not supported */
        return PASSWD_ERR_INVALID_OPCODE;
    }
    }

    return PASSWD_ERR_SUCCESS;
}

/**
 * validate password by using crypt function
 *
 * @param client
 * @return 0 if passwords are matched
 */
int validate_password(passwd_client_t *client)
{
    char *crypt_str = NULL;
    int  err = 0;

    /*
    * TODO: replace crypt() with openssl.
    *       - investigate to implement logic with openssl to support
    *          any encryption method defined in logins.def file
    *          i.e. SHA512 is not supported by 'openssl passwd'
    *       - hashed password is in following format: $<method>$<salt>$<hashed string>
    *       - investigate to use openssl to produce same hashed string
    */
    if ((NULL == (crypt_str = crypt(client->msg.oldpasswd,
            client->passwd->sp_pwdp))) ||
        (0 != strncmp(crypt_str, client->passwd->sp_pwdp,
                strlen(client->passwd->sp_pwdp))))
    {
        err = PASSWD_ERR_FATAL;
    }

    if (NULL != crypt_str)
    {
        memset(crypt_str, 0, strlen(crypt_str));
    }
    return err;
}

/**
 * Find password info for a given user in /etc/shadow file
 *
 * @param  username[in] username to search
 * @return password     parsed shadow entry
 */
struct spwd *find_password_info(const char *username)
{
    struct spwd *password = NULL;
    FILE *fpShadow;
    int uname_len, cur_uname_len, name_len;

    if (NULL == username)
    {
        return NULL;
    }

    /* lock /etc/shadow file to read */
    if (0 != lckpwdf())
    {
        VLOG_ERR("Failed to lock /usr/shadow file");
        return NULL;
    }

    /* open shadow file */
    if (NULL == (fpShadow = fopen(PASSWD_SHADOW_FILE, "r")))
    {
        VLOG_ERR("Failed to open /usr/shadow file");
        return NULL;
    }

    uname_len = strlen(username);

    /* loop thru /etc/shadow to find user */
    while(NULL != (password = fgetspent(fpShadow)))
    {
        cur_uname_len = strlen(password->sp_namp);
        name_len = (cur_uname_len >= uname_len) ? cur_uname_len : uname_len;

        if (0 == memcmp(password->sp_namp, username, name_len))
        {
            /* unlock shadow file */
            if (0 != ulckpwdf())
            {
                VLOG_DBG("Failed to unlock /usr/shadow file");
            }
            fclose(fpShadow);
            return password;
        }
    }

    /* unlock shadow file */
    if (0 != ulckpwdf())
    {
       VLOG_DBG("Failed to unlock /usr/shadow file");
    }

    fclose(fpShadow);
    return NULL;
}

/**
 * Process received MSG from client.
 *
 * @param client received MSG from client
 * @return if processed it successfully, return 0
 */
int process_client_request(passwd_client_t *client)
{
    int error = PASSWD_ERR_FATAL;

    if (NULL == client)
    {
        return -1;
    }

    switch(client->msg.op_code)
    {
    case PASSWD_MSG_CHG_PASSWORD:
    {
        /* proceed to change password for the user */
        if (NULL == (client->passwd = find_password_info(client->msg.username)))
        {
            /* logging error */
            VLOG_INFO("User %s cannot be found in password file",
                    client->msg.username);
            return PASSWD_ERR_USER_NOT_FOUND;
        }

        /* validate old password */
        if (0 != validate_password(client))
        {
            return PASSWD_ERR_PASSWORD_NOT_MATCH;
        }

        if (PASSWD_ERR_SUCCESS == (error = create_and_store_password(client)))
        {
            VLOG_INFO("Password updated successfully for %s",
                    client->msg.username);
        }
        else
        {
            VLOG_INFO("Password was not updated successfully [error=%d]", error);
        }
        break;
    }
    case PASSWD_MSG_ADD_USER:
    {
        /* make sure username does not exist */
        if (NULL != (client->passwd = find_password_info(client->msg.username)))
        {
            VLOG_ERR("User %s already exists", client->msg.username);
            return PASSWD_ERR_USER_EXIST;
        }

        /* add user to /etc/passwd file */
        if (NULL == (client->passwd = create_user(client->msg.username, TRUE)))
        {
            /* failed to create user or getting information from /etc/passwd */
            VLOG_ERR("Failed to create a user");
            return PASSWD_ERR_USERADD_FAILED;
        }

        /* now add password for the user */
        if (PASSWD_ERR_SUCCESS == (error = create_and_store_password(client)))
        {
            VLOG_INFO("User was added successfully");
        }
        else
        {
            VLOG_INFO("User was not added successfully [error=%d]", error);
            /* delete user since it failed to add password */
            create_user(client->msg.username, FALSE);
        }
        break;
    }
    case PASSWD_MSG_DEL_USER:
    {
        /* make sure username does not exist */
        if (NULL == (client->passwd = find_password_info(client->msg.username)))
        {
            VLOG_INFO("User %s does not exist to delete", client->msg.username);
            return PASSWD_ERR_USER_NOT_FOUND;
        }

        /* delete user from /etc/passwd file */
        if (NULL != (client->passwd = create_user(client->msg.username, FALSE)))
        {
            VLOG_INFO("Failed to remove user %s", client->msg.username);
            return PASSWD_ERR_USERDEL_FAILED;
        }

        error = PASSWD_ERR_SUCCESS;
        break;
    }
    default:
    {
        /* wrong op-code */
        return PASSWD_ERR_INVALID_OPCODE;
    }
    }
    return error;
}
