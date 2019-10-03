# PwPoSh
Password-related scriptlets module to help with account provisioning or password resets, more useful in bulk operations
Started as a way to automate using [Peter Giacomo Lombardo](https://github.com/pglombardo)'s [PasswordPusher](https://github.com/pglombardo/PasswordPusher) to generate password links (better than sending passwords in plain text).

## New-Password
Generates random password with multiple configuration options. Currently not using CryptoRNG for simplicity and speed.

## Publish-Password
Pushes the generated (or any other) to https://pwpush.com or a privately hosted instance.

## Get-Password
Retieves the password using the link in https://pwpush.com/p/asdfghjkrwqwd format.
Currently a stub function, as the API retrieves payload in Base64-encoded encrypted form.

## Unpublish-Password
Deletes the password from the server using the link in https://pwpush.com/p/asdfghjkrwqwd format.
Current build of pwpusher returns HTTP/500 on successful `DELETE` operation, the function captures and mentions that in the output.