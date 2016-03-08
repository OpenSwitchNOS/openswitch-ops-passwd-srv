OPS-PASSWD-SRV
=====

##Contents
- [High level design of Password Server](#high-level-design-of-password-server)
- [Responsibilities](#responsibilities)
- [Design choices](#design-choices)
- [Relationships to external OpenSwitch entities](#relationships-to-external-openswitch-entities)
- [Internal structure](#internal-structure)

##High level design of password server

This documents describes the design of the password server.

Password server is a daemon runs as a root which serves as entry point to change
/etc/shadow file upon receiving a request to update password.

Password server uses UNIX domain socket as IPC and public/private key to encrypt
 message require to update password - username, old-password, and new-password.

Password will be encrypted on client-side using public key.  Password server
decrypts cipher-text using private key. Both private/public keys are
created during the initialization of password server.

##Responsibilities

The main responsibilities of the Password Server are:

* Update user password in /etc/shadow file
* Create private/public keys for password encryption/decryption
* Create and maintain socket to connect with clients
* Provide password validation

##Design choices

IPC is done via UNIX domain socket.  Stream socket is used to initiate
connection-oriented socket between client and password server.

To secure password transfer from client to password server, public/private
keys are used to send user information.

During password server initialization, public/private keys are generated using
openssl library.  Then public key is stored in file system which client uses it
to encryption conversation.

Password hashing is done by crypto function.  Password server selects
encryption method from system's login.defs file. Programs like useradd and passwd
determine hashing algorithm by reading login.defs, we decided to use same scheme
to align password server with other programs to create hashed password.

##Relationships to external OpenSwitch entities

There is no media which allows external openswitch entity to interact with 
password server directly.  Only internal programs can interact with password 
server using UNIX domain socket.

##Internal structure

Upon start of password server, it
- generates private/public keys
- stores public key in filesystem
- creates socket and starts to listen on socket for incoming connection

Below describes client to password server conversation:
1. Client daemon gets user information
   - client also creates a file which will be used by password server for
      authentication
   - message contains {username, old password, new password, file path }
2. Retrieve public key and encrypt user information
3. Create socket and connect to password server
4. Send cipher text via socket
5. Waiting for the status of password update from the server
6. Upon receiving the status, notify user

Below depicts how password server handles pasword update request:
1. Upon successful connection with client, retrieve message sent by client
2. Using private key, decrypt cipher text message
3. Validate client and old-password
   - validate user of file included in message
   - validate old-password for the user
4. Create salt and password
5. Update user password in /etc/shadow
6. Send status back to client and close connection

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

(1) client creates a file and add file path
(2) validation includes client validation peeking at file stat and old-password
     validation.  Either fails, password server returns error code to the client.