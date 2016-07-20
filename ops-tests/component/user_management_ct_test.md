# User Management CLI Tests


## Contents

- [Test cases](#test-cases)
  - [Verify users can be added through user add CLI](#verify-users-can-be-added-through-user-add-CLI)
  - [Verify root user cannot be added through user add CLI](#verify-root-user-cannot-be-added-through-user-add-CLI)
  - [Verify user cannot be added to invalid group through user add CLI](#verify-user-cannot-be-added-to-invalid-group-through-user-add-CLI)
  - [Verify existing user cannot be added through user add CLI ](#verify-existing-user-cannot-be added-through-user-add-CLI)
  - [Verify users can be deleted through user remove CLI](#verify-users-can-be-deleted-through-user-remove-CLI)

## Topology diagram
```
  [s1]
```

## Test cases

### Verify users can be added through user add CLI
#### Description
1. Add user 'test1' to group 'admin' through `user add` CLI command.
2. Add user 'test2' to group 'netop' through `user add` CLI command.
3. Verify the existence of the two users added using the `show user-list` CLI command.
#### Test result criteria
##### Pass criteria
Added users are listed in the `show user-list` CLI output.
##### Fail criteria
Added users are not listed in the `show user-list` CLI output.

### Verify root user cannot be added through user add CLI
#### Description
1. Add user 'root' through `user add` CLI command.
2. Verify that `user add` CLI command displays 'Permission Denied' error message.
#### Test result criteria
##### Pass criteria
'Permission denied. Cannot add the root user.' error message was displayed by `user add` CLI command.
##### Fail criteria
'Permission denied. Cannot add the root user.' error message was not displayed by `user add` CLI command.

### Verify user cannot be added to invalid group through user add CLI
1. Add user 'test' to invalid group 'group123' through `user add` CLI command.
2. Verify that `user add` CLI command displays 'group123 is not a valid group name.'.
#### Test result criteria
##### Pass criteria
'group123 is not a valid group name.' was displayed by `user add` CLI command.
##### Fail criteria
'group123 is not a valid group name.' was not displayed by `user add` CLI command.

### Verify existing user cannot be added through user add CLI
1. Add user 'test1' to group 'netop' through `user add` CLI command.
2. Verify that `show user-list` CLI command does not display test1 as part of group netop.
#### Test result criteria
##### Pass criteria
`show user-list` CLI command does not display test1 as part of group netop.
##### Fail criteria
`show user-list` CLI command displays test1 as part of group netop.

### Verify users can be deleted through user remove CLI
1. Remove user 'test1' from group 'admin' through `user remove` CLI command.
2. Remove user 'test2' from group 'netop' through `user remove` CLI command.
3. Verify that the deleted users are not present in `show user-list` command.
#### Test result criteria
##### Pass criteria
Deleted users are not listed in the `show user-list` command.
##### Fail criteria
Deleted users are listed in the `show user-list` command.
