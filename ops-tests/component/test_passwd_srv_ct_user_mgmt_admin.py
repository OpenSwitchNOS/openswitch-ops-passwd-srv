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

from pytest import mark

TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
"""

'''
TODO: Enable login as admin user when topology
framework function is ready
'''


def check_admin_access(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None

    # login as admin user
    # ops1(login='admin', password='admin')
    step('### Test to verify admin should not have bash access ###')
    result = ops1("ls", shell='bash')
    assert "Permission denied" not in result, "admin should not have" \
        "bash access."


def add_user_as_admin(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None

    # login as admin user
    # ops1(login='admin', password='admin')
    step('### Test to verify admin can add users ###')
    vtysh_shell = ops1.get_shell('vtysh')
    # Add user to admin group.
    matches = ['Enter password:']
    assert vtysh_shell.send_command("user add test1 group admin", matches) is 0
    matches = ['Confirm password:']
    assert vtysh_shell.send_command("pass123", matches) is 0
    matches = ["#"]
    assert vtysh_shell.send_command("pass123", matches) is 0
    # Verify added admin and netop user is displayed in
    # 'show user-list' command.
    lines = ops1("show user-list").splitlines()
    lines = [line.replace(' ', '') for line in lines]
    out = ''.join(lines)
    assert 'test1admin' in out, "Admin could not add user"


def remove_user_as_admin(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None

    # login as admin user
    # ops1(login='admin', password='admin')
    step('### Test to verify admin can remove users ###')
    ops1("user remove test1")
    lines = ops1("show user-list").splitlines()
    lines = [line.replace(' ', '') for line in lines]
    out = ''.join(lines)
    assert 'test1admin' not in out, "Admin could not remove user"


@mark.skipif(True, reason="Waiting for API to login as admin")
def test_ct_user_management_admin(topology, step):
    check_admin_access(topology, step)
    add_user_as_admin(topology, step)
    remove_user_as_admin(topology, step)
