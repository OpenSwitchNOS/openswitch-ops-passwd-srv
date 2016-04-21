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
  stat --printf="%U %F\n" /var/run/ops-passwd-srv/ops-passwd-srv.sock
  ```
3. Make sure a file exists in the filesystem

### Test result criteria
#### Test pass criteria
- After step 2, the output of stat must give 2 entries - <user> <type>
- verify user is **root** and type is **socket**
  - i.e. `root socket`

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
2. Run command ```stat --printf="%U" /etc/ops-passwd-srv/ops-passwd-srv.yaml```
3. Make sure a file exists in the filesystem
4. Run command ```cat /etc/ops-passwd-srv/ops-passwd-srv.yaml```
5. Verify that YAML file has the expected contents.

### Test result criteria
#### Test pass criteria
- After step 2, output must have ***root*** as user and ***root*** as group
  - i.e. `root root`
- After step 4, the output must have the location of UNIX socket and a public
  key location.
  - socket location: `/var/run/ops-passwd-srv/ops-passwd-srv.sock`
  - public key location: `/var/run/ops-passwd-srv/ops-passwd-srv-pub.pem`
#### Test fail criteria
- After step 2 or 4, expected output is not showing.

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
2. Run command to get a directory information
```bash
stat --printf="%U %A %F\n" /var/run/ops-passwd-srv/
```
3. Make sure a directory exists with a execution permission
4. Run command to get a public key stat
```bash
stat --printf="%U %G\n" /var/run/ops-passwd-srv/ops-passwd-srv-pub.pem
```
5. Make sure a file exists in the filesystem

### Test result criteria
#### Test pass criteria
- After step 2, output must contain `root drw-r-x--- directory`
  - user set to **root**
  - permission set to **drw-r-x--**
  - type is **directory**
- After step 4, output must contain ***root ovsdb-client***
  - user set to **root**
  - group is set to **ovsdb-cleint**

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
2. Run command to verify a shared object exists in the filesystem
```bash
stat --printf="%U %G %A\n" /usr/lib/libpasswd_srv.so.0.1.0
```
3. Make sure a file exists in the filesystem

### Test result criteria
#### Test pass criteria
- After step 2, output must contain `root root`
  - user is set to **root**
  - group is set to **root**
  - permission set to **-rwxr-xr-x**

#### Test fail criteria
- After step 2 or 4, expected output is not showing.