# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch Test for the password server
"""

from pytest import mark

TOPOLOGY = """
# +-------+
# |       |
# |ops1   |
# |       |
# +-------+

# Nodes
# [image="genericx86-64:latest" type=openswitch name="OpenSwitch 1"] ops1
[type=openswitch name="OpenSwitch 1"] ops1
# Links
"""


@mark.platform_incompatible(['ostl'])
def test_passwd_srv_daemon(topology):
    """
    Ensure ops-passwd-srv is running on OpenSwitch instance

    Using bash shell from the switch
    1. run 'ps aux | grep ops-passwd-srv'
    2. make sure output has the information about ops-passwd-srv
    """

    ops1 = topology.get('ops1')
    comm = "ps aux | grep ops-passwd-srv"
    matches = ['/usr/bin/ops-passwd-srv --detach --pidfile -vSYSLOG:INFO']

    assert ops1 is not None

    print("Get bash shell")
    bash_shell = ops1.get_shell('bash')

    print("Execute shell command")
    assert bash_shell.send_command(comm, matches) is 0

    print("ops-passwd-srv is running as expected")
    print("Test test_passwd_srv_daemon PASSED")


@mark.platform_incompatible(['ostl'])
def test_passwd_sock_fd(topology):
    """
    Ensure the password is listening on socket by verifying whether
     socket descriptor is created under '/var/run/ops-passwd-srv/'

    Using bash shell from the switch
    1. run 'ls -l /var/run/ops-passwd-srv/ops-passwd-srv.sock'
    2. make sure output has the information about permission and the owner
       of the file
    """

    ops1 = topology.get('ops1')
    comm = "ls -l /var/run/ops-passwd-srv/ops-passwd-srv.sock"
    matches = ['srwxrw-rw- 1 root ovsdb-client']

    assert ops1 is not None

    print("Get bash shell")
    bash_shell = ops1.get_shell('bash')

    print("Execute shell command")
    assert bash_shell.send_command(comm, matches) is 0

    print("ops-passwd-srv.sock is created as expected")
    print("Test test_passwd_sock_fd PASSED")


@mark.platform_incompatible(['ostl'])
def test_passwd_yaml_file(topology):
    """
    Ensure yaml file is located at '/etc/ops-passwd-srv/'

    Using bash shell from the switch
    1. run 'ls -l /etc/ops-passwd-srv/ops-passwd-srv.yaml'
    2. make sure output has the information about permission and the owner
       of the file
    """

    ops1 = topology.get('ops1')
    comm = "ls -l /etc/ops-passwd-srv/ops-passwd-srv.yaml"
    matches = ['-rw-r--r-- 1 root root']

    yaml_local = ['#', 'OpenSwitch', 'password', 'server', 'configuration',
                  'file', '---', 'files:', '-', 'type:', 'SOCKET', 'path:',
                  "'/var/run/ops-passwd-srv/ops-passwd-srv.sock'",
                  'description:', "'File", 'path', 'for', 'password', 'server',
                  "socket'", '-', 'type:', 'PUB_KEY', 'path:',
                  "'/var/run/ops-passwd-srv/ops-passwd-srv-pub.pem'",
                  'description:', "'Public", 'key', 'location', 'to',
                  'encrypt', "message'"]

    assert ops1 is not None

    print("Get bash shell")
    bash_shell = ops1.get_shell('bash')

    print("Execute shell command")
    assert bash_shell.send_command(comm, matches) is 0

    print("Get YAML file contents from OpenSwitch")
    comm = "cat /etc/ops-passwd-srv/ops-passwd-srv.yaml"
    ops1(comm, shell="bash")
    yaml_sw = ops1(comm, shell="bash").split()

    print("Check the content of YAML file")
    assert yaml_local == yaml_sw is not 0

    print("ops-passwd-srv.yaml is installed as expected")
    print("Test test_passwd_yaml_file PASSED")


@mark.platform_incompatible(['ostl'])
def test_passwd_pub_key_file(topology):
    """
    Ensure public key file is located at '/var/run/ops-passwd-srv/'

    Using bash shell from the switch
    1. run 'ls -l /var/run/ops-passwd-srv/ops-passwd-srv-pub.pem'
    2. make sure output has the information about permission and the owner
       of the file
    """

    ops1 = topology.get('ops1')
    assert ops1 is not None

    print("Get bash shell")
    bash_shell = ops1.get_shell('bash')

    comm = "ls -l /var/run/ | grep ops-passwd-srv"
    matches = ['drw-r-x---  2 root ovsdb-client']

    print("Execute shell command")
    assert bash_shell.send_command(comm, matches) is 0

    print("/var/run/ has ops-passwd-srv directory")

    comm = "ls -l /var/run/ops-passwd-srv/ops-passwd-srv-pub.pem"
    matches = ['-rw-r--r-- 1 root ovsdb-client']

    print("Execute shell command")
    assert bash_shell.send_command(comm, matches) is 0

    print("ops-passwd-srv-pub.pem is created as expected")
    print("Test test_passwd_pub_key_file PASSED")


@mark.platform_incompatible(['ostl'])
def test_passwd_lib_file(topology):
    """
    Ensure library file is located at '/usr/lib/'

    Using bash shell from the switch
    1. run 'ls -l /var/run/ops-passwd-srv/ops-passwd-srv-pub.pem'
    2. make sure output has the information about permission and the owner
       of the file
    """

    ops1 = topology.get('ops1')
    comm = "ls -l /usr/lib/libpasswd_srv.so.0.1.0"
    matches = ['-rwxr-xr-x 1 root root']

    assert ops1 is not None

    print("Get bash shell")
    bash_shell = ops1.get_shell('bash')

    print("Execute shell command")
    assert bash_shell.send_command(comm, matches) is 0

    print("libpasswd_srv.so file is installed as expected")
    print("Test test_passwd_lib_file PASSED")
