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
#include <sys/errno.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "openvswitch/vlog.h"
#include "passwd_srv_pri.h"

#include <pwd.h>

VLOG_DEFINE_THIS_MODULE(passwd_srv_conn);

static int fdSocket = 0, socket_client = 0;

/*
 * Using socket provided, send MSG back to client. MSG going back is the status
 * of password update.
 *
 * @param client_socket socket to send MSG
 * @param msg           error code to send back
 * @return SUCCESS if sent it
 */
static int
send_msg_to_client(int client_socket, int msg)
{
    char *msgBuf = NULL;
    int  err = PASSWD_ERR_SEND_FAILED;

    /*
     * MSG size is not big as expected,
     * send error MSG to client
     */
    msgBuf = (char *)calloc(1, sizeof(int));
    if (msgBuf)
    {
        *msgBuf = msg;

        if (0 > (err =
                send(client_socket, msgBuf, sizeof(int), MSG_DONTROUTE)))
        {
            VLOG_ERR("Failed to send message to the client");
            return PASSWD_ERR_SEND_FAILED;
        }

        free(msgBuf);
        return PASSWD_ERR_SUCCESS;
    }

    return PASSWD_ERR_FATAL;
}

/**
 * Listen on created socket for new connection request from client.
 *  If connection is available, process request according to MSG's opCode
 *
 *  @param socket_server socket descriptor created to listen
 */
void listen_socket(RSA *keypair)
{
    struct sockaddr_un unix_sockaddr;
    struct sockaddr_un client_sockaddr;
    int                err = -1;
    int                ret;
    int                size = 0, storage_size = 0, fmode = 0;
    struct sockaddr_storage sock_storage;
    char   filemode[] = "0766";
    char   *sock_file = NULL;
    unsigned char *enc_msg;
    unsigned char *dec_msg;
    passwd_client_t client;

    /* allocate buffers which will hold the incoming encrypted message from
     * clients and the resulting decrypted message */
    enc_msg = (unsigned char *)malloc(RSA_size(keypair));
    dec_msg = (unsigned char *)malloc(RSA_size(keypair));
    if (!(enc_msg && dec_msg)) /* both mallocs must be succesful to proceed */
    {
        VLOG_ERR("Memory allocation failure");
        exit(PASSWD_ERR_FATAL);
    }

    memset(&unix_sockaddr, 0, sizeof(unix_sockaddr));
    memset(&client, 0, sizeof(client));

    /* get the socket location from yaml */
    if (NULL == (sock_file = get_file_path(PASSWD_SRV_YAML_PATH_SOCK)))
    {
        /* couldn't find socket location from yaml */
        VLOG_ERR("Cannot find socket descriptor location");
        exit(PASSWD_ERR_FATAL);
    }

    /* setup sockaddr to create socket */
    unix_sockaddr.sun_family = AF_UNIX;
    strncpy(unix_sockaddr.sun_path, sock_file, strlen(sock_file));

    /* create a socket */
    if (0 > (fdSocket = socket(AF_UNIX, SOCK_STREAM, 0)))
    {
        VLOG_ERR("Cannot find socket descriptor location");
        return;
    }

    /* bind socket to socket descriptor */
    size = sizeof(struct sockaddr_un);
    unlink(unix_sockaddr.sun_path);

    if (0 > (err = bind(fdSocket, (struct sockaddr *)&unix_sockaddr, size)))
    {
        VLOG_ERR("Cannot bind to socket %s", unix_sockaddr.sun_path);
        return;
    }

    fmode = strtol(filemode, 0, 8);
    chmod(sock_file, fmode);
    storage_size = sizeof(sock_storage);

    memset(&client_sockaddr, 0, sizeof(client_sockaddr));

    /* initiate the socket listen */
    if (0 > (err = listen(fdSocket, 3)))
    {
        VLOG_ERR("Failed to initiate a socket listen");
        return;
    }

    /* waiting to accept the connection */
    /* TODO: if needed, change to use select() instead of accept() */
    for(;;)
    {
        /* zero out our buffers before each use */
        memset(enc_msg, 0, RSA_size(keypair));
        memset(dec_msg, 0, RSA_size(keypair));

        if (0 > (socket_client =
                accept(fdSocket, (struct sockaddr *)&client_sockaddr,
                (socklen_t *)&size)))
        {
            VLOG_ERR("Fail to connect with the client");
            exit(PASSWD_ERR_FATAL);
        }

        /* get client-socket information */
        memset(&sock_storage, 0, sizeof(sock_storage));
        getpeername(socket_client, (struct sockaddr*)&sock_storage,
                (socklen_t *)&storage_size);
        memcpy(&client_sockaddr, &sock_storage, sizeof(client_sockaddr));

        /*
         * we get here if connection is made between client and server
         * - make sure connected client has password-update privilege
         * - get MSG from connected client
         **/

        if (-1 == recv(socket_client, enc_msg, RSA_size(keypair), MSG_PEEK))
        {
            VLOG_ERR("Failed to retrieve the message from the client");
            send_msg_to_client(socket_client, PASSWD_ERR_RECV_FAILED);
            shutdown(socket_client, SHUT_WR);
            close(socket_client);
            continue;
        }

        /* from RSA_private decrypt() man page:
         * RSA_PKCS1_OAEP_PADDING
         *  EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty
         *  encoding parameter. This mode is recommended for all new
         *  applications */
        ret = RSA_private_decrypt(RSA_size(keypair), enc_msg, dec_msg, keypair,
                                  RSA_PKCS1_OAEP_PADDING);
        if (ret == -1) {
            /* ERR_print_errors to provide details of the decryption failure,
             * this will produce an error number that can be understood using
             * 'openssl errstr' at the command line */
            ERR_print_errors_fp(stderr);
            /* TODO: move error to log */
            send_msg_to_client(socket_client, PASSWD_ERR_DECRYPT_FAILED);
            shutdown(socket_client, SHUT_WR);
            close(socket_client);
            continue;
        }

        memcpy(&client.msg, dec_msg, sizeof(passwd_srv_msg_t));
        client.socket = socket_client;
        err = process_client_request(&client);

        send_msg_to_client(socket_client, err);
        shutdown(socket_client, SHUT_WR);
        close(socket_client);

        /* clean up */
        memset(&client, 0, sizeof(client));
        socket_client = 0;
    }
}

/**
 * Close all UNIX socket used by the password server
 * - this function gets called when SIGTERM is sent
 */
void socket_uninit()
{
    if (socket_client > 0)
    {
        /* client has a opened socket connected to the password server */
        shutdown(socket_client, SHUT_WR);
        close(socket_client);
    }

    if (fdSocket > 0)
    {
        /* UNIX socket is used by the password server */
        shutdown(fdSocket, SHUT_WR);
        close(fdSocket);
    }
}
