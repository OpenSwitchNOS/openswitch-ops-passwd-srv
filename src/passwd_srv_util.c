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
#include <crypt.h>
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

#include "passwd_srv_pri.h"
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

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
    RSA *rsa;
    /* to hold the keypair to be generated */
    BIGNUM *bne;
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
        /* TODO: log about the failure */
        goto cleanup;
    }

    /* seed random number generator */
    RAND_poll();

    rsa = RSA_new();
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret == 0) {
        /* TODO: logging */
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
        /* TODO: logging */
        key_generate_failed = 1;
        goto cleanup;
    }

    /* save public key to a file in PEM format */
    bp_public = BIO_new_file(pub_key_path, "wx");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
    if (ret != 1)
    {
        /* TODO: logging */
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
    ovsdb_client_grp = getgrnam("ovsdb-client");
    chown(pub_key_path, getuid(), ovsdb_client_grp->gr_gid);

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
    char line[1024], *value;
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
            char *temp = &(line[strlen(target) + 1]);
            value = strdup(temp);
            value[strlen(value)] = '\0';

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
        return NULL;
    }

    /* make sure that user has been created */
    if (useradd && NULL == (passwd_entry = find_password_info(username)))
    {
        return NULL;
    }

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

    /* generate new password using crypt */
    newpassword = crypt(password, salt);

    /* store it to shadow file */
    err = store_password(client->msg.username, newpassword);

    memset(newpassword, 0, strlen(newpassword));
    memset(salt, 0, strlen(salt));
    free(salt);

    return err;
}

/**
 * validate user information using socket descriptor and passwd file
 *
 * @param sockaddr  sockaddr structure for client connection
 * @param client    client structure entry
 *
 * @return 0 if client is ok to update pasword
 */
int validate_user(struct sockaddr_un *sockaddr, passwd_client_t *client)
{
    struct stat     c_stat;
    struct passwd   *user = NULL;

    if (NULL == client)
    {
        return PASSWD_ERR_INVALID_USER;
    }

    memset(&c_stat, 0, sizeof(c_stat));

    /* user is found, compare with client info */
    if (0 == strncmp(user->pw_name, client->msg.username,
            strlen(client->msg.username)))
    {
        /* sender is user who wants to change own password */
        return 0;
    }
    else if (0 == strncmp(user->pw_name, "ops", strlen("ops")))
    {
        /* sender is ops who wants to change user password */
        return 0;
    }

    return PASSWD_ERR_INVALID_USER;
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
        /* TODO: logging for failure */
        return NULL;
    }

    /* open shadow file */
    if (NULL == (fpShadow = fopen(PASSWD_SHADOW_FILE, "r")))
    {
        /* TODO: logging for failure */
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
                /* TODO: logging for failure */
            }
            fclose(fpShadow);
            return password;
        }
    }

    /* unlock shadow file */
    if (0 != ulckpwdf())
    {
       /* TODO: logging for failure */
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
            return PASSWD_ERR_USER_NOT_FOUND;
        }

        /* validate old password */
        if (0 != validate_password(client))
        {
            return PASSWD_ERR_PASSWORD_NOT_MATCH;
        }

        if (PASSWD_ERR_SUCCESS == (error = create_and_store_password(client)))
        {
            printf("Password updated successfully for user\n");
        }
        else
        {
            printf("Password was not updated successfully [error=%d]\n", error);
        }
        break;
    }
    case PASSWD_MSG_ADD_USER:
    {
        /* make sure username does not exist */
        if (NULL != (client->passwd = find_password_info(client->msg.username)))
        {
            /* TODO: logging error */
            return PASSWD_ERR_USER_EXIST;
        }

        /* add user to /etc/passwd file */
        if (NULL == (client->passwd = create_user(client->msg.username, TRUE)))
        {
            /* failed to create user or getting information from /etc/passwd */
            return PASSWD_ERR_USERADD_FAILED;
        }

        /* now add password for the user */
        if (PASSWD_ERR_SUCCESS == (error = create_and_store_password(client)))
        {
            printf("User was added successfully\n");
        }
        else
        {
            printf("User was not added successfully [error=%d]\n", error);
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
            /* TODO: logging error */
            return PASSWD_ERR_USER_NOT_FOUND;
        }

        /* delete user from /etc/passwd file */
        if (NULL != (client->passwd = create_user(client->msg.username, FALSE)))
        {
            /* failed to create user or getting information from /etc/passwd */
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
