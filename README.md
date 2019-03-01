# assumerole

Assume AWS role and auto refresh tokens.

# Caveat

Botocore doesn't display stderr, so in case the MFA is needed, the aws cli will not display the message, but still expect an input.
To get the message to display, apply this patch: https://github.com/boto/botocore/pull/1349/files

# Example config.

```
# file: ~/.aws/config

[DEFAULT]
source_profile     = creack
region             = us-east-1
credential_process = assumerole
mfa_serial         = arn:aws:iam::12342:mfa/creack

[profile dev]
_role_arn = arn:aws:iam::1234200:role/devrole

[profile prod]
_role_arn = arn:aws:iam::1234201:role/prodrole
```

```
# file: ~/.aws/credentials
[creack]
aws_access_key_id     = foo
aws_secret_access_key = bar
```
