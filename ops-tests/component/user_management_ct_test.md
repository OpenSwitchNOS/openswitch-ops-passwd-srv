# User Management CLI Tests


## Contents

- [Topology diagram](#topology diagram)
- [Test cases](#test-cases)
  - [Verify users can be added through the user add CLI](#verify-users-can-be-added-through-the-user-add-cli)
  - [Verify root user cannot be added through the user add CLI](#verify-root-user-cannot-be-added-through-the-user-add-cli)
  - [Verify a user cannot be added to invalid group through the user add CLI](#verify-a-user-cannot-be-added-to-invalid-group-through-the-user-add-cli)
  - [Verify existing user cannot be added through the user add CLI](#verify-existing-user-cannot-be-added-through-the-user-add-cli)
  - [Verify users can be deleted through the user remove CLI](#verify-users-can-be-deleted-through-the-user-remove-cli)
  - [Verify default users cannot be deleted through user remove CLI](#verify-default-users-cannot-be-deleted-through-user-remove-cli)
  - [Verify only a maximum of eight users can be configured in a group](#verify-only-a-maximum-of-eight-users-can-be-configured-in-a-group)

## Topology diagram
```
  [s1]
```

## Test cases

### Verify users can be added through the user add CLI
#### Description
1. Add user "test1" to group "admin" through the `user add` CLI command.
2. Add user "test2" to group "netop" through the `user add` CLI command.
3. Verify the existence of the two users added using the the `show user-list`
CLI command.

#### Test result criteria
##### Pass criteria
Added users are listed in the `show user-list` output.
##### Fail criteria
Added users are not listed in the `show user-list` output.

### Verify root user cannot be added through the user add CLI
#### Description
1. Add user "root" through the `user add` CLI command.
2. Verify that the `user add` command displays the "Permission Denied" error
message.

#### Test result criteria
##### Pass criteria
The "Permission denied. Cannot add the root user." error message is displayed by the
`user add` command.
##### Fail criteria
The "Permission denied. Cannot add the root user." error message was not displayed
by the `user add` command.

### Verify a user cannot be added to invalid group through the user add CLI
#### Description
1. Add user "test" to invalid group "group123" through the `user add`
CLI command.
2. Verify that the `user add` command displays "group123 is not a valid
group name.".

#### Test result criteria
##### Pass criteria
The "group123 is not a valid group name." message is displayed by the `user add`
command.
##### Fail criteria
The "group123 is not a valid group name." is not displayed by the `user add`
command.

### Verify existing user cannot be added through the user add CLI
#### Description
1. Add user "test1" to group "netop" through the `user add` CLI command.
2. Verify that the `show user-list` CLI command does not display test1 as part
of group netop.

#### Test result criteria
##### Pass criteria
The `show user-list` command does not display test1 as part of group netop.
##### Fail criteria
The `show user-list` command displays test1 as part of group netop.

### Verify users can be deleted through the user remove CLI
#### Description
1. Remove user "test1" from group "admin" through the `user remove`
CLI command.
2. Remove user "test2" from group "netop" through the `user remove`
CLI command.
3. Verify that the deleted users are not present in the `show user-list`
CLI command.

#### Test result criteria
##### Pass criteria
Deleted users are not listed in the `show user-list` command.
##### Fail criteria
Deleted users are listed in the `show user-list` command.

### Verify default users cannot be deleted through user remove CLI
#### Description
1. Remove default users "root", "admin", and "netop" through the `user remove`
CLI command.
3. Verify that "Permission denied" message is displayed when
trying to remove the default users.

#### Test result criteria
##### Pass criteria
"Permission denied" message is displayed when trying to remove the default
users.
##### Fail criteria
"Permission denied" message is not displayed when trying to remove the default
users.

### Verify only a maximum of eight users can be configured in a group
#### Description
1. Add eight users to a group "admin" through the `user add` CLI command.
2. Add the nineth user to the group "admin" through the `user add` CLI command.
3. Verify that the "Maximum number of users for group admin has been reached"
message is displayed when trying to add the nineth user.

#### Test result criteria
##### Pass criteria
The "Maximum number of users for group admin has been reached" message was
displayed when trying to add the nineth user to the "admin" group.
##### Fail criteria
The "Maximum number of users for group admin has been reached" message was
not displayed when trying to add the nineth user to the "admin" group.
