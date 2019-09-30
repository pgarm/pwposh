# PwPoSh
Password-related scriptlets module to help with account provisioning or password resets, more useful in bulk operations
Started as a way to automate using [Peter Giacomo Lombardo](https://github.com/pglombardo)'s [PasswordPusher](https://github.com/pglombardo/PasswordPusher) to generate password links (better than sending passwords in plain text).

## New-Password
Generates random password with multiple configuration options. Currently not using CryptoRNG for simplicity and speed.

## Push-Password
Pushes the generated (or any other) to https://pwpush.com or a privately hosted instance.

## To-Do
- [ ] Pull-Password function to retrieve the password from the server
- [ ] Kill-Password function to forcibly remove the password from the server (if allowed by deleteable_by_user)
- [ ] Add $Server/URL validation to make sure it's in proper format and can be reached over port 443/80 based on protocol prefix if supplied or other explicit port
