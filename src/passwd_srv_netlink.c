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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <linux/rtnetlink.h>

#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <linux/netlink_diag.h>

#include "openvswitch/vlog.h"
#include "passwd_srv_pri.h"

#define NETLINK_MSG_SIZE 8196

VLOG_DEFINE_THIS_MODULE(passwd_srvd_netlink);

/**
 * Parse attributes message sent by kernel into 2D array for easy access
 *
 * @param table             2D array to store parsed entries
 * @param max_entry         maximum number of entry
 * @param msg_from_kernel   message recv'd from kernel
 * @param msg_len           length of recv'd message
 * @param flags             mask to determine type of UNIX_DIAG entry
 * @returns SUCESS if parsed and stored ok
 */
static int
parse_socket_attributes(struct rtattr *table[], struct rtattr *msg_from_kernel,
        int msg_len, unsigned short flags)
{
    unsigned short type;

    if ((table == NULL) || (msg_from_kernel == NULL))
    {
        VLOG_ERR("Invalid parameter to parse socket attributes");
        return PASSWD_ERR_FATAL;
    }

    memset(table, 0, sizeof(struct rtattr *) * (UNIX_DIAG_MAX + 1));

    /* parse attribute sent by kernel into 2D-array */
    while (RTA_OK(msg_from_kernel, msg_len)) {

        /*
         * find type of entry
         * we are interested in NAME, PEER, and RQLEN
         */
        type = msg_from_kernel->rta_type & ~flags;

        if ((type <= UNIX_DIAG_MAX) && (!table[type])) {
            /* type is determined, stored it */
            table[type] = msg_from_kernel;
        }
        msg_from_kernel = RTA_NEXT(msg_from_kernel,msg_len);
    }

    return PASSWD_ERR_SUCCESS;
}

/**
 * Get u32 value from 2D array provided
 *
 * @param table UNIX_DIAG entry container
 * @return value extracted from container
 */
static unsigned int
get_attribute_from_array(const struct rtattr *table)
{
    if (table == NULL) {
        VLOG_ERR("netlink attribute table is empty. nothing to retrieve");
        return 0;
    }
    return *(unsigned int  *)RTA_DATA(table);
}

/**
 * Based on attribute recv'd from kernel. find connected client's peer inode
 *
 * @param msg_hdr MSG recv'd
 * @param passwd_srv_ino  inode number of a socket from the password server
 * @return peer inode number if found one, otherwise, 0
 */
static int
get_peer_inode(struct nlmsghdr *msg_hdr, int passwd_srv_ino)
{
    struct unix_diag_msg *u_diag_msg;
    struct rtattr *attr_table[UNIX_DIAG_MAX+1];
    int peer_ino;

    if (msg_hdr == NULL)
    {
        VLOG_ERR("Invalid param: message header is NULL");
        return 0;
    }

    /* get diag_msg from msg */
    u_diag_msg = NLMSG_DATA(msg_hdr);

    /* parse the attributes sent by the kernel */
    parse_socket_attributes(attr_table, (struct rtattr*)(u_diag_msg+1),
            msg_hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*u_diag_msg)), 0);

    if (passwd_srv_ino != u_diag_msg->udiag_ino) {
        /* inode is not matched, keep looking */
        return 0;
    }

    /* get inode of connected client (peer) */
    if (attr_table[UNIX_DIAG_PEER]) {
        peer_ino = (int)get_attribute_from_array(attr_table[UNIX_DIAG_PEER]);
    }
    else {
        peer_ino = 0;
    }

    return peer_ino;
}

/**
 * Send and recv messages using netlink. request of getting unix socket info
 * is sent to kernel.  once message is received by the kernel, search thru
 * entries to find peer inode which is connected to the password server
 *
 * @param req               MSG to send
 * @param size              size of the message
 * @param get_peer_ino_ptr  function pointer to find peer inode
 * @param passwd_srv_ino    password server inode
 * @return peer inode from calling get_peer_ino_ptr
 */
static int
send_and_recv_via_netlink(struct nlmsghdr *req, size_t size,
                  int (* get_peer_ino_ptr)(struct nlmsghdr *, int),
                  int passwd_srv_ino)
{
    int fd, msg_seq_num = 0, recv_failed = 0, peer_ino = 0, status = 0;
    int recv_attempt = 20;
    char    msg_buf[NETLINK_MSG_SIZE];
    struct  nlmsghdr *msg_hdr;
    struct  sockaddr_nl nladdr;
    socklen_t slen = sizeof(nladdr);

    /* open netlink to communicate with the server */
    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0)
    {
        VLOG_ERR("Cannot connect to kernel via netlink");
        return 0;
    }

    /* send request to the kernel */
    if (send(fd, req, size, 0) < 0) {
        VLOG_ERR("Cannot send a request to kernel via netlink");
        close(fd);
        return 0;
    }

    /* make sure sequence number is set */
    msg_seq_num = getpid();
    slen = sizeof(nladdr);

    while (TRUE) {

        memset(&nladdr, 0, sizeof(nladdr));
        memset(msg_buf, 0, NETLINK_MSG_SIZE);

        status = recvfrom(fd, msg_buf, sizeof(msg_buf), 0,
                  (struct sockaddr *) &nladdr, &slen);

        if (status < 0) {
            if (status != EINTR) {
                /* recvfrom was interrupted for some reason try it again */
                VLOG_WARN("Recv via netlink was interrupted");
            }
            /* couldn't get the message, try it again */
            recv_failed++;

            if (recv_failed > recv_attempt)
            {
                /* tried to get message from kernel, but couldn't */
                VLOG_ERR("Too many recv failure from netlink");
                goto close_and_exit;
            }
            continue;
        }

        if (status == 0) {
            VLOG_ERR("netlink closed unexpectedly");
            goto close_and_exit;
        }

        msg_hdr = (struct nlmsghdr*)msg_buf;

        /*
         * when message is received via netlink from kernel, it contains the
         * list of unix socket information. Below will iterate entries from
         * the message to find the matching inode of the password server
         * to retrieve peer inode.
         *
         * This is needed since kernel is not designed to return specific
         * entry for the inode provided in the request. instead, kernel sends
         * the list of unix socket which reside on /proc/<password server pid>/net/unix
         */
        while (NLMSG_OK(msg_hdr, status)) {

            if (msg_hdr->nlmsg_seq != msg_seq_num) {
                goto skip_it;
            }

            if (msg_hdr->nlmsg_type == NLMSG_DONE) {
                goto close_and_exit;
            }

            if (msg_hdr->nlmsg_type == NLMSG_ERROR) {
                VLOG_ERR("NLMSG failure");
                goto close_and_exit;
            }

            /* try to get peer inode information */
            peer_ino = get_peer_ino_ptr(msg_hdr, passwd_srv_ino);

            if (peer_ino > 0) {
                VLOG_DBG("Socket peer found (s=%d)(p=%d)",
                        passwd_srv_ino, peer_ino);
                goto close_and_exit;
            }
skip_it:
            recv_failed = 0;
            peer_ino = 0;
            msg_hdr = NLMSG_NEXT(msg_hdr, status);
        }
    }

close_and_exit:
    close(fd);
    return peer_ino;
}

/**
 * Find connected client whom made the request to use the password server
 *
 * @param passwd_srv_ino socket inode connected to the client
 * @return inode of the client
 */
int find_connected_client_inode(int passwd_srv_ino)
{
    /*
     * packing two structures. some of linux application (i.e. ss) uses
     * this scheme to send message via netlink
     */
    struct {
        struct nlmsghdr nlh;
        struct unix_diag_req r;
    } req;

    memset(&req, 0, sizeof(req));

    /*
     * prepare message header to send
     */
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    req.nlh.nlmsg_seq = getpid();

    req.r.sdiag_family = AF_UNIX;
    /*
     * request to get unix socket information based on inode provided is not
     * working as expected; thus, the password server must iterate the list of
     * unix socket entries returned by the kernel
     * see comment in send_and_recv_via_netlink() for more information
     */
    req.r.udiag_ino = passwd_srv_ino;
    req.r.udiag_states = 0xffffffff;
    req.r.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER ;

    return send_and_recv_via_netlink(&req.nlh, sizeof(req), get_peer_inode,
            passwd_srv_ino);
}
