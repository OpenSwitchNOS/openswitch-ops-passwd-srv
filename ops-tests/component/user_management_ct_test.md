# User Management CLI Tests


## Contents

- [Test cases](#test-cases)
  - [Verify users can be added through user add CLI](#verify-users-can-be-added-through-user-add-CLI)
  - [Verify root user cannot be added through user add CLI](#verify-root-user-cannot-be-added-through-user-add-CLI)
  - [Verify user cannot be added to invalid group through user add CLI](#verify-user-cannot-be-added-to-invalid-group-through-user-add-CLI)
  - [Verify existing user cannot be added through user add CLI ](#verify-existing-user-cannot-be added-through-user-add-CLI)
  - [Verify users can be deleted through user remove CLI](#verify-users-can-be-deleted-through-user-remove-CLI)
  - [Verify only a maximum of 8 users can be configured in a group](#Verify-only-a-maximum-of-8-users-can-be-configured-in-a-group)

## Topology diagram
```
  [s1]
```

## Test cases

### Verify users can be added through user add CLI
#### Description
1. Add user 'test1' to group 'admin' through the `user add` CLI command.
2. Add user 'test2' to group 'netop' through the `user add` CLI command.
3. Verify the existence of the two users added using the the `show user-list`
CLI command.
#### Test result criteria
##### Pass criteria
Added users are listed in the `show user-list` CLI output.
##### Fail criteria
Added users are not listed in the `show user-list` CLI output.

### Verify root user cannot be added through user add CLI
#### Description
1. Add user 'root' through the `user add` CLI command.
2. Verify that the `user add` CLI command displays 'Permission Denied' error
message.
#### Test result criteria
##### Pass criteria
'Permission denied. Cannot add the root user.' error message was displayed by
`user add` CLI command.
##### Fail criteria
'Permission denied. Cannot add the root user.' error message was not displayed
by `user add` CLI command.

### Verify user cannot be added to invalid group through user add CLI
#### Description
1. Add user 'test' to invalid group 'group123' through the `user add`
CLI command.
2. Verify that the `user add` CLI command displays 'group123 is not a valid
group name.'.
#### Test result criteria
##### Pass criteria
'group123 is not a valid group name.' was displayed by the `user add`
CLI command.
##### Fail criteria
'group123 is not a valid group name.' was not displayed by the `user add`
CLI command.

### Verify existing user cannot be added through user add CLI
#### Description
1. Add user 'test1' to group 'netop' through the `user add` CLI command.
2. Verify that the `show user-list` CLI command does not display test1 as part
of group netop.
#### Test result criteria
##### Pass criteria
`show user-list` CLI command does not display test1 as part of group netop.
##### Fail criteria
`show user-list` CLI command displays test1 as part of group netop.

### Verify users can be deleted through user remove CLI
#### Description
1. Remove user 'test1' from group 'admin' through the `user remove`
CLI command.
2. Remove user 'test2' from group 'netop' through the `user remove`
CLI command.
3. Verify that the deleted users are not present in the `show user-list`
CLI command.
#### Test result criteria
##### Pass criteria
Deleted users are not listed in the `show user-list` command.
##### Fail criteria
Deleted users are listed in the `show user-list` command.

### Verify only a maximum of 8 users can be configured in a group
#### Description
1. Add 8 users to a group 'admin' through the `user add` CLI command.
2. Add the 9th user to the group 'admin' through the `user add` CLI command.
3. Verify that 'Maximum number of users for group admin has been reached'
message is displayed when trying to add the 9th user.
#### Test result criteria
##### Pass criteria
'Maximum number of users for group admin has been reached' message was
displayed when trying to add the 9th user to the 'admin' group.
##### Fail criteria
'Maximum number of users for group admin has been reached' message was
not displayed when trying to add the 9th user to the 'admin' group.
