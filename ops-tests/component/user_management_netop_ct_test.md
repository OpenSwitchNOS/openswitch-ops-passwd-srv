# User Management CLI Tests as netop user


## Contents

- [Topology diagram](#topology-diagram)
- [Test cases](#test-cases)
  - [Verify netop user cannot add users through the user add CLI command](#verify-netop-user-cannot-add-users-through-the-user-add-cli-command)
  - [Verify netop user cannot remove users through the user remove CLI command](#verify-netop-user-cannot-remove-users-through-the-user-remove-cli-command)


## Topology diagram
```
  [s1]
```

## Test cases
### Verify netop user cannot add users through the user add CLI command
#### Description
1. Log in as "netop" user.
2. Add a user "test1" to group "admin" through the `user add` CLI command.
3. Verify that "% Unknown command." is displayed.

#### Test result criteria
##### Pass criteria
"% Unknown command." is displayed.
##### Fail criteria
"% Unknown command." is not displayed.

### Verify netop user cannot remove users through the user remove CLI command
#### Description
1. Log in as "netop" user.
2. Remove user "admin" through the `user remove` CLI command.
3. Verify that "% Unknown command." is displayed.
#### Test result criteria
##### Pass criteria
'% Unknown command.' is displayed.
##### Fail criteria
'% Unknown command.' is not displayed.
