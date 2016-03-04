OPS-PASSWD-SRV
=====

##Contents
- [High level design of Password Server](#high-level-design-of-password-server)
- [Responsibilities](#responsibilities)
- [Design choices](#design-choices)
- [Relationships to external OpenSwitch entities](#relationships-to-external-openswitch-entities)
- [Internal structure](#internal-structure)
- [Message format] (#message format)
- [Opcode]  (#operation-code)
- [Error code format] (#error-code-format)
- [Location of socket/pub key] (#socket-descriptor-and-public-key-location)

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

When the message is being encrypted/decrypted, RSA_PKCS1_OAEP_PADDING is used to
provide the padding while a server/client is performing the message encryption
or decryption.

##Responsibilities

The main responsibilities of the Password Server are:

* Update user password in the /etc/shadow file
* Create private/public keys for the password encryption/decryption
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
the password server directly.  Only internal programs can interact with
the password server using a UNIX domain socket.

##Internal structure

Upon start of the password server, it
- generates private/public keys
  - The key generation happens at the ops-passwd-srv daemon startup. After
    daemonize_complete() is done, the password server creates and listens on
    the socket.  Key generation must happen prior to the socket operation.
- stores a public key in the filesystem
   - The location of public key is defined in a YAML file specified in
     the section 'Location of socket/pub key'
   - a public key is stored as an immutable file which only root user can
     delete or move after a immutable bit is unset
- stores a private key within the password server memory
  - no other program needs to access a private key. it is decided to store
     a private key in the password server
- creates the socket and starts to listen on the socket for incoming connections
   - The location of socket decriptor is defined in public header as
     PASSWD_SRV_SOCK_FD.
- read '/etc/ops-passwd-srv/ops-passwd-srv.yaml' to know the file path
   - YAML file contains socket descriptor and public key location
   - both the public key storage and socket descriptor location are retrieved
   		during password server boot-time

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

##operation code
Operation code (opcode) is used by both a client and the password server.
The password server performs the password related action based on the opcode.

The opcode is 4 byte integer value. Below is the list of opcodes:
 +-----------------------------------------------------------------------------+
 | opcode name             | opcode | Description                              |
 +-----------------------------------------------------------------------------+
 | PASSWD_MSG_CHG_PASSWORD | 1      | change password for a given user         |
 +-----------------------------------------------------------------------------+
 | PASSWD_MSG_ADD_USER     | 2      | create a new user                        |
 +-----------------------------------------------------------------------------+
 | PASSWD_MSG_DEL_USER     | 3      | delete a given user                      |
 +-----------------------------------------------------------------------------+

## error code format
After the password server processes a request from the client, it sends an error
code back to the client to inform about the operation status.

The error code is 4 byte integer value and below describes the error code definition:

 +-----------------------------------------------------------------------------+
 | error code name               | opcode | Description                        |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_FATAL              | -1     | fatal error                        |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_SUCCESS            |  0     | operation is successfully done     |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_USER_NOT_FOUND     |  1     | a given user is not found          |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_PASSWORD_NOT_MATCH |  2     | invalid old password               |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_SHADOW_FILE        |  3     | cannot access shadow file          |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_INVALID_MSG        |  4     | invalid message format             |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_INSUFFICIENT_MEM   |  5     | out of memory error                |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_RECV_FAILED        |  6     | receive message failed             |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_INVALID_OPCODE     |  7     | unknown opcode                     |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_INVALID_USER       |  8     | invalid user info                  |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_INVALID_PARAM      |  9     | invalid parameter is used          |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_PASSWD_UPD_FAIL    | 10     | password update failed             |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_SEND_FAILED        | 11     | fail to send message to the client |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_USERADD_FAILED     | 12     | fail to add a user                 |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_USER_EXIST         | 13     | a given user already exists        |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_USERDEL_FAILED     | 14     | fail to delete user                |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_DECRYPT_FAILED     | 15     | fail to decrypt the message        |
 +-----------------------------------------------------------------------------+
 | PASSWD_ERR_YAML_FILE          | 16     | cannot access YAML file            |
 +-----------------------------------------------------------------------------+

## socket descriptor and public key location
For the client to communicate with the password server, it needs to open a UNIX
socket and send an encrypted message (using public key provided).

To get the information about the socket descriptor and public key location,
the client program must parse the YAML file to extract such information.
YAML file contains the location of socket descriptor and public key.

YAML formatted file is stored in /etc/ops-password-srv/ops-passwd-srv.yaml.

YAML file contains following information:
 +--------------------------------------------------------+
 | Field name      |  Description                         |
 +--------------------------------------------------------+
 | type            | the describes a type of file         |
 |                 | - SOCKET  : UNIX socket descriptor   |
 |                 | - PUB_KEY : public key               |
 +--------------------------------------------------------+
 | path            | file location in the filesystem      |
 +--------------------------------------------------------+
 | description     | description of file                  |
 +--------------------------------------------------------+

 The type 'SOCKET' depicts the socket descriptor which is used by the client
 to create a connection with the password server using UNIX socket.

 The type 'PUB_KEY' stores the location of a public key which the password server
 generates at start-up.  The public key is used by the client to encrypt a
 request.