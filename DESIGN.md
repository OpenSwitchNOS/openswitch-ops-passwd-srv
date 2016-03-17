OPS-PASSWD-SRV
=====

##Contents
- [High level design of Password Server](#high-level-design-of-password-server)
- [Responsibilities](#responsibilities)
- [Design choices](#design-choices)
- [Relationships to external OpenSwitch entities](#relationships-to-external-openswitch-entities)
- [Internal structure](#internal-structure)
- [Message format] (#message format)

##High level design of password server

This document describes the design of the password server.

Password server is a daemon that runs as root which serves as the entry point to change
the /etc/shadow file upon receiving a request to update password.

Password server uses a UNIX domain socket as IPC and public/private keys to encrypt
a message required to update the password. The format of the message is
username, old-password, and new-password.

The password is encrypted on the client-side using a public key.  The password server
decrypts the cipher-text using a private key. Both private/public keys are
created during the initialization of password server.

##Responsibilities

The main responsibilities of the Password Server are:

* Update user password in the /etc/shadow file
* Create private/public keys for the password encryption/decryption
* Create and maintain socket to connect with clients
* Create ini file to store global variables
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
the password server directly.  Only internal programs can interact with
the password server using a UNIX domain socket.

##Internal structure

Upon start of the password server, it
- generates private/public keys
  - The key generation happens at the ops-passwd-srv daemon startup. After
    daemonize_complete() is done, the password server creates and listens on
    the socket.  Key generation must happen prior to the socket operation.
- stores a public key in the filesystem
   - The location of public key is defined in a public header as
     PASSWD_SRV_PUB_KEY_LOC.
   - a public key is stored as an immutable file which only root user can
     delete or move after a immutable bit is unset
- stores a private key within the password server memory
  - no other program needs to access a private key. it is decided to store
     a private key in the password server
- creates the socket and starts to listen on the socket for incoming connections
   - The location of socket decriptor is defined in public header as
     PASSWD_SRV_SOCK_FD.
- creates /etc/ops-passwd-srv.ini to store global variables defined in public
  header file. This allows programs that don't have access to the public header
  file to retrieve global variables.

Below describes the client to password server conversation:
1. Client daemon gets user information
   - the information contains {username, old password, new password}
2. Retrieve the public key and encrypt user information
3. Create the socket and connect to the password server
4. Send cipher text via socket
5. Wait for the status of password update from the server
6. Upon receiving the status, notify user

Below depicts how the password server handles password update requests:
1. Upon successful connection with the client, retrieve the message sent by the client
2. Using private key, decrypt cipher text message
3. Validate the client and old-password
   - validate user using the old-password provided
4. Create a salt and the hashed password
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
|  |   encrypt user info   |  |     |  +---------v-------------+    |
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
|            |                |     |  | validate user info(1) |  | |
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

(1) The password server validates the user with old password provided.

##message format

The client connected to the password server via socket should use following
message format to send user information:

 +--------------------------------------------------------+
 |         MSG field name                 |  size (bytes) |
 +--------------------------------------------------------+
 |          operation code (opcode)       |   4           |
 +--------------------------------------------------------+
 |          username                      |   50          |
 +--------------------------------------------------------+
 |          old password                  |   50          |
 +--------------------------------------------------------+
 |          new password                  |   50          |
 +--------------------------------------------------------+

 The password server sends the status about the password server update in
 following message format:

 +--------------------------------------------------------+
 |         MSG field name                 |  size (bytes) |
 +--------------------------------------------------------+
 |          status code (error code)      |   4           |
 +--------------------------------------------------------+