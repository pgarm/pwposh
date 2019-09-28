# PwPoSh
Password-related scriptlets module to help with account provisioning or password resets, more useful in bulk operations
Started as a way to automate using [Peter Giacomo Lombardo](https://github.com/pglombardo)'s [PasswordPusher](https://github.com/pglombardo/PasswordPusher) to generate password links (better than sending passwords in plain text).

## New-Password
Generates random password with multiple configuration options. Currently not using CryptoRNG for simplicity and speed.

## Push-Password
Pushes the generated (or any other) to https://pwpush.com or a privately hosted instance.
