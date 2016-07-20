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


def login_as_netop(ops1, step):
    step("### Login as netop ###")
    ssh_as_netop = "ssh -o StrictHostKeyChecking=no netop@localhost"
    matches = ['password:']
    password = "netop"
    bash_shell = ops1.get_shell('bash')
    assert bash_shell.send_command(ssh_as_netop, matches) is 0
    matches = ['#']
    assert bash_shell.send_command(password, matches) is 0, "Login" \
        " as netop failed."


def add_user_as_netop(ops1, step):
    step('### Test to verify netop cannot add users ###')
    output = ops1("user add test1 group admin")
    assert "% Unknown command." in output, "netop should not have" \
        " access to user add CLI."


def remove_user_as_netop(ops1, step):
    step('### Test to verify netop cannot remove users ###')
    output = ops1("user remove admin")
    assert "% Unknown command." in output, "netop should not have" \
        " access to user remove CLI."


@mark.platform_incompatible(['docker'])
def test_ct_user_management_netop(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None
    login_as_netop(ops1, step)
    add_user_as_netop(ops1, step)
    remove_user_as_netop(ops1, step)
