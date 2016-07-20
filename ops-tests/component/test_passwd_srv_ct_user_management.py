# -*- coding: utf-8 -*-
# (C) Copyright 2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
##########################################################################

"""
OpenSwitch Test for user management related configurations.
"""


TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
"""


def user_add(ops1, step):
    vtysh_shell = ops1.get_shell('vtysh')

    step('### Test to verify user add command ###')
    # Add user to admin group.
    matches = ['Enter password:']
    assert vtysh_shell.send_command("user add test1 group admin", matches) is 0
    matches = ['Confirm password:']
    assert vtysh_shell.send_command("pass123", matches) is 0
    matches = ['User add executed successfully.']
    assert vtysh_shell.send_command("pass123", matches) is 0, "User "\
        "add command failed while adding an admin user."

    # Add user to netop group.
    matches = ['Enter password:']
    assert vtysh_shell.send_command("user add test2 group netop", matches) is 0
    matches = ['Confirm password:']
    assert vtysh_shell.send_command("pass123", matches) is 0
    matches = ["#"]
    assert vtysh_shell.send_command("pass123", matches) is 0, "User "\
        "add command failed while adding a netop user."

    # Verify added admin and netop user is displayed in
    # 'show user-list' command.
    lines = ops1("show user-list", shell='vtysh').splitlines()
    lines = [line.replace(' ', '') for line in lines]
    out = ''.join(lines)
    assert 'test1admin' in out and 'test2netop' in out, "user add failed"
    step('### user add command successful ###')


def user_add_root(ops1, step):
    step('### Test to verify user add blocks adding root user ###')
    out = ops1("user add root group admin")
    assert 'Permission denied. Cannot add the root user.' in out, "Test " \
        "failed: root user was added using user add command."
    step('### Test to verify user add blocks adding root user passed ###')


def user_add_invalid_group(ops1, step):
    step('### Test to verify user add blocks adding user to invalid group ###')
    out = ops1("user add test group group123")
    assert 'group123 is not a valid group name.' in out, "Test failed: " \
        "Invalid group was added using user add command."
    step('### Test user add blocks adding user to invalid group passed ###')


def user_add_existing_user(ops1, step):
    vtysh_shell = ops1.get_shell('vtysh')

    step('### Test to verify user add blocks adding existing user ###')
    matches = ['Enter password:']
    assert vtysh_shell.send_command("user add test1 group netop", matches) is 0
    matches = ['Confirm password:']
    assert vtysh_shell.send_command("pass123", matches) is 0
    matches = ["#"]
    assert vtysh_shell.send_command("pass123", matches) is 0, "Test " \
        "failed: Existing user was added using user add command."
    lines = ops1("show user-list", shell='vtysh').splitlines()
    lines = [line.replace(' ', '') for line in lines]
    out = ''.join(lines)
    assert 'test1netop' not in out, "user add failed"
    step('### Test user add blocks adding existing user passed ###')


def user_remove(ops1, step):
    step('### Test to verify user remove command ###')
    ops1("user remove test1")
    ops1("user remove test2")
    lines = ops1("show user-list").splitlines()
    lines = [line.replace(' ', '') for line in lines]
    out = ''.join(lines)
    assert 'test1admin' not in out and 'test2netop' not in out, "user "\
        "remove failed"


def check_max_users_in_group(ops1, step):
    step('### Test to verify max users in a group ###')
    vtysh_shell = ops1.get_shell('vtysh')
    for i in range(1, 9):
        if i == 8:
            matches = ['Maximum number of users for group admin has been'
                       'reached']
        else:
            matches = ['Enter password:']
        cmd = "user add test"+str(i)+" group admin"
        assert vtysh_shell.send_command(cmd, matches) is 0, "Max users per" \
            "group test failed."
        if i != 8:
            matches = ['Confirm password:']
            assert vtysh_shell.send_command("pass123", matches) is 0
            matches = ['#']
            assert vtysh_shell.send_command("pass123", matches) is 0
    matches = ['#']
    vtysh_shell.send_command("\n", matches) is 0
    # Remove configured users
    for i in range(1, 8):
        cmd = "user remove test"+str(i)
        ops1(cmd)


def test_vtysh_ct_user_management(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None

    user_add(ops1, step)
    user_add_root(ops1, step)
    user_add_invalid_group(ops1, step)
    user_add_existing_user(ops1, step)
    user_remove(ops1, step)
    check_max_users_in_group(ops1, step)
