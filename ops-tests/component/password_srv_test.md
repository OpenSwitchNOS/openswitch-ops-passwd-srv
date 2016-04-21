# Password Server Test Cases

## Contents
- [Verify password server daemon](#check-password-server-daemon)
- [Verify socket descriptor installation](#check-socket-fd-file)
- [Verify YAML file installation](#check-YAML-file)
- [Verify public key storage](#check-pub-key-file)
- [Verify shared object installation](#check-shared-library)

## Check password server daemon
### Objective
After switch is boot, `/usr/bin/ops-passwd-srv` must be in running state.
Objective of this test is to ensure that ops-passwd-srv is
running on OpenSwitch.

### Requirements
The requirements for this test case are:

- OpenSwitch

#### Setup
#### Topology diagram
```ditaa
+---------------+
|               |
|  OpenSwitch   |
|               |
+---------------+
```

### Description
At switch boot, the instance of `/usr/bin/ops-passwd-srv` must be started.

#### Steps

1. Open bash shell for OpenSwitch instance
2. Run bash command
  ```bash
  ps aux | grep ops-passwd-srv
  ```
3. Examine the output to make sure that ops-passwd-srv is running with proper
   arguments
   expected: `/usr/bin/ops-passwd-srv --detach --pidfile -vSYSLOG:INFO`

### Test result criteria
#### Test pass criteria
- After step 2, expected output must contain
    `/usr/bin/ops-passwd-srv --detach --pidfile -vSYSLOG:INFO`

#### Test fail criteria
- After step 2, expected output is not showing.

## Check socket fd file
### Objective
Ensure the password is listening on socket by verifying whether
socket descriptor is created under `/var/run/ops-passwd-srv/`

### Requirements
The requirements for this test case are:

- OpenSwitch

#### Setup
#### Topology diagram
```ditaa
+---------------+
|               |
|  OpenSwitch   |
|               |
+---------------+
```

### Description
Password server must create a socket and listening on it.

#### Steps

1. Open bash shell for OpenSwitch instance
2. Run bash command
  ```bash
  ls -l /var/run/ops-passwd-srv/ops-passwd-srv.sock
  ```
3. Make sure a file exists in the filesystem

### Test result criteria
#### Test pass criteria
- After step 2, output must contain `srwxrwxrwx 1 root ovsdb-client`.
- **s** in the begining of output indicates that it is a socket descriptor

#### Test fail criteria
- After step 2, expected output is not showing.

## Check YAML file
### Objective
Ensure that YAML file used by the password server and other program is stored
in designated location `/etc/ops-passwd-srv/ops-passwd-srv.yaml`

### Requirements
The requirements for this test case are:

- OpenSwitch

#### Setup
#### Topology diagram
```ditaa
+---------------+
|               |
|  OpenSwitch   |
|               |
+---------------+
```

### Description
YAML file must be installed for the password server to open a socket and
create/store a public key.

#### Steps

1. Open bash shell for OpenSwitch instance
2. Run command ```ls -l /etc/ops-passwd-srv/ops-passwd-srv.yaml```
3. Make sure a file exists in the filesystem

### Test result criteria
#### Test pass criteria
- After step 2, output must contain `-rw-r--r--` which gives permission to read
for everyone but no rights to write or execute.

#### Test fail criteria
- After step 2, expected output is not showing.

## Check pub key file
### Objective
Ensure that public key is stored in the designated location.  The direcotry
stores a public key must have a permission to execute which allows the client
to read a public key file.

### Requirements
The requirements for this test case are:

- OpenSwitch

#### Setup
#### Topology diagram
```ditaa
+---------------+
|               |
|  OpenSwitch   |
|               |
+---------------+
```

### Description
Password server must generate a public key and store it in the filesystem.
Which then used by the client to encrypt the message.

#### Steps

1. Open bash shell for OpenSwitch instance
2. Run command ```ls -l /var/run/ | grep ops-passwd-srv```
3. Make sure a directory exists with **execute** permission
2. Run command ```ls -l /var/run/ops-passwd-srv/ops-passwd-srv-pub.pem```
3. Make sure a file exists in the filesystem

### Test result criteria
#### Test pass criteria
- After step 2, output must contain `-rw-r--r--` which gives permission to read
for everyone but no rights to write or execute.

#### Test fail criteria
- After step 2, expected output is not showing.

## Check shared library
### Objective
Ensure that password server shared object is stored in the designated location.

### Requirements
The requirements for this test case are:

- OpenSwitch

#### Setup
#### Topology diagram
```ditaa
+---------------+
|               |
|  OpenSwitch   |
|               |
+---------------+
```

### Description
During the build, the password server builds *libpasswd_srv.so.0.1.0* which can
be used by other programs to parse a YAML file.

#### Steps

1. Open bash shell for OpenSwitch instance
2. Run command ```ls -l /usr/lib/libpasswd_srv.so.0.1.0```
3. Make sure a file exists in the filesystem

### Test result criteria
#### Test pass criteria
- After step 2, output must contain `-rwxr-xr-x` which gives permission to read
for everyone but no rights to write or execute.

#### Test fail criteria
- After step 2, expected output is not showing.