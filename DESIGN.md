OPS-PASSWD-SRV
=====

##Contents
- [High level design of Password Server](#high-level-design-of-password-server)
- [Responsibilities](#responsibilities)
- [Design choices](#design-choices)
- [Relationships to external OpenSwitch entities](#relationships-to-external-openswitch-entities)
- [Internal structure](#internal-structure)

##High level design of password server

This document describes the design of the password server.

Password server is a daemon that runs as root which serves as the entry point to change
the /etc/shadow file upon receiving a request to update password.

Password server uses a UNIX domain socket as IPC and public/private keys to encrypt
a message required to update the password. The format of the message is
username, old-password, and new-password.

Password will be encrypted on the client-side using a public key.  The password server
decrypts the cipher-text using a private key. Both private/public keys are
created during the initialization of password server.

##Responsibilities

The main responsibilities of the Password Server are:

* Update user password in the /etc/shadow file
* Create private/public keys for password encryption/decryption
* Create and maintain socket to connect with clients
* Provide password validation

##Design choices

IPC is done via UNIX domain socket.  A stream socket is used to initiate
the connection-oriented socket between client and password server.

To securely transmit the password from the client to the password server ,
public/private keys are used to send user information.

During password server initialization, public/private keys are generated using
the openssl library.  The public key is stored in the file system which used
by the client to encrypt the conversation.

The password hashing is done by a crypto function.  The password server selects
the encryption method from the system's login.defs file to be consistent with
other programs used to create hashed passwords - i.e. useradd and passwd.

##Relationships to external OpenSwitch entities

There is no media which allows external openswitch entities to interact with
password server directly.  Only internal programs can interact with password
server using a UNIX domain socket.

##Internal structure

Upon start of password server, it
- generates private/public keys
  - The key generation happen at the ops-passwd-srv daemon startup. After
    daemonize_complete() is done, the password server creates and listens on
    the socket.  Key generation must happen prior to the socket operation.
- stores public key in the filesystem
  - the password server stores public key to /tmp/ops-passwd-srv-pub.pem
- creates the socket and starts to listen on the socket for incoming connections

Noted that the private key is not stored in filesystem since a key is generated
at run-time. The password server stores a private key in its memory.

Below describes the client to password server conversation:
1. Client daemon gets user information
   - client also creates a file which will be used by password server for
     authentication
   - message contains {username, old password, new password, file path }
2. Retrieve the public key and encrypt user information
3. Create the socket and connect to the password server
4. Send cipher text via socket
5. Wait for the status of password update from the server
6. Upon receiving the status, notify user

Below depicts how the password server handles password update requests:
1. Upon successful connection with the client, retrieve the message sent by the client
2. Using private key, decrypt cipher text message
3. Validate the client and old-password
   - validate the user of file included in message
   - validate old-password for the user
4. Create salt and password
5. Update the user password in /etc/shadow
6. Send status back to the client and close the connection

          Clients (CLI/REST)                      Password Server
+-----------------------------+     +-------------------------------+
|  +-----------------------+  |     |  +-----------------------+    |
|  |   Get user info       |  |     |  |  create public/       |    |
|  +---------+-------------+  |     |  |   private key         |    |
|            |                |     |  +---------+-------------+    |
|  +---------v-------------+  |     |            |                  |
|  |   Load public key     |  |     |  +---------v-------------+    |
|  +---------+-------------+  |     |  |  save public key      |    |
|            |                |     |  +---------+-------------+    |
|  +---------v-------------+  |     |            |                  |
|  |   encrypt user info(1)|  |     |  +---------v-------------+    |
|  +---------+-------------+  |     |  |    create socket      |    |
|            |                |     |  +---------+-------------+    |
|            |                |     |            |                  |
|            |                |     |  +---------v-------------+    |
|            |                |     |  |   listen on socket    |    |
|            |                |     |  +-----------------------+    |
|            |                |     |            |                  |
|  +---------v-------------+  |     |  +---------v-------------+    |
|  |   connect to server   |--|-----|->|   accept connection   |<-+ |
|  +---------+-------------+  |     |  +-----------------------+  | |
|            |                |     |            |                | |
|  +---------v-------------+  |     |  +---------v-------------+  | |
|  |    send user info     |--|-----|->|   receive user info   |  | |
|  +---------+-------------+  |     |  +---------+-------------+  | |
|            |                |     |            |                | |
|            |                |     |  +---------v-------------+  | |
|            |                |     |  |   decrypt user info   |  | |
|            |                |     |  +---------+-------------+  | |
|            |                |     |            |                | |
|            |                |     |  +---------v-------------+  | |
|            |                |     |  | validate user info(2) |  | |
|            |                |     |  +---------+-------------+  | |
|            |                |     |            |                | |
|            |                |     |  +---------v-------------+  | |
|            |                |     |  | update shadow file    |  | |
|            |                |     |  |  with new password    |  | |
|            |                |     |  +---------+-------------+  | |
|            |                |     |            |                | |
|  +---------v-------------+  |     |  +---------v-------------+  | |
|  |   receive status      |<-|-----|--|  send update status   |  | |
|  +---------+-------------+  |     |  |    update password    |  | |
|            |                |     |  +---------+-------------+  | |
|  +---------v-------------+  |     |            |                | |
|  |   log(print) status   |  |     |  +---------v-------------+  | |
|  +---------+-------------+  |     |  |    close socket       |--+ |
|            |                |     |  +---------+-------------+    |
|  +---------v-------------+  |     +-------------------------------+
|  |    close socket       |  |
|  +---------+-------------+  |
+-----------------------------+

(1) client creates a file and add the file path
(2) The password server validates a sender of the cipher text (CLI or restd).
    Old-password is validated using a crypto function.