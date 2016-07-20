# User Management CLI Tests as admin user


## Contents

- [Test cases](#test-cases)
  - [Verify admin user can add users through user add CLI command](#verify-admin-user-can-add-users-through-user-add-CLI-command)
  - [Verify admin user can remove users through user remove CLI command](#verify-admin-user-can-remove-users-through-user-remove-CLI-command)

## Topology diagram
```
  [s1]
```

## Test cases
### Verify admin user can add users through user add CLI command
#### Description
1. Login as 'admin' user.
2. Add a user 'test1' to group 'admin' through the 'user add' CLI command.
3. Verify that user 'test1' is added to group 'admin' through the 'show user-list' CLI command.
#### Test result criteria
##### Pass criteria
User 'test1' in group 'admin' is displayed through the 'show user-list' CLI command.
##### Fail criteria
User 'test1' in group 'admin' is not displayed through the 'show user-list' CLI command.

### Verify admin user can add users through user add CLI command
#### Description
1. Login as 'admin' user.
2. Remove the user 'test1' through the 'user add' CLI command.
3. Verify that user 'test1' is not displayed through the 'show user-list' CLI command.
#### Test result criteria
##### Pass criteria
User 'test1' is not displayed through the 'show user-list' CLI command.
##### Fail criteria
User 'test1' is displayed through the 'show user-list' CLI command.
