# assumerole

Assume AWS role and auto refresh tokens.

# Caveat

Botocore doesn't display stderr, so in case the MFA is needed, the aws cli will not display the message, but still expect an input.
To get the message to display, apply this patch: https://github.com/boto/botocore/pull/1349/files

# Example config.

NOTE: This tool expects the non-standard `_role_arn` as the CLI will not call the credential_process if it finds the role_`arn_key`.

```ini
# file: ~/.aws/config

[DEFAULT]
source_profile     = creack
region             = us-east-1
credential_process = assumerole
mfa_serial         = arn:aws:iam::12342:mfa/creack
output             = json
cli_pager          = cat

[profile creack-base]
# Voluntary left blank with a profile name distinct from the static credentials.
# Allows to use the IAM user itself with 2FA without assuming a different role.

[profile dev]
_role_arn = arn:aws:iam::1234200:role/devrole

[profile prod]
_role_arn = arn:aws:iam::1234201:role/prodrole
```

```ini
# file: ~/.aws/credentials
[creack]
aws_access_key_id     = foo
aws_secret_access_key = bar
```
