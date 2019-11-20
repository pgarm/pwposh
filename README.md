# PwPoSh
Password-related scriptlets module to help with account provisioning or password resets, more useful in bulk operations
Started as a way to automate using [Peter Giacomo Lombardo](https://github.com/pglombardo)'s [PasswordPusher](https://github.com/pglombardo/PasswordPusher) to generate password links (better than sending passwords in plain text).

## New-Password
Generates random password with multiple configuration options. Currently not using CryptoRNG for simplicity and speed.

## Publish-Password
Pushes the generated (or any other) to https://pwpush.com or a privately hosted instance.
Was named Push-Password before. Renamed to match PowerShell verb convention.

## Get-Password
Retieves the password using the link in https://pwpush.com/p/asdfghjkrwqwd format.

## Unpublish-Password
Deletes the password from the server using the link in https://pwpush.com/p/asdfghjkrwqwd format.
Older build of pwpusher return HTTP/500 on successful `DELETE` operation, the function captures and mentions that in the output.
Newer builds properly respond with HTTP/200.

## Get-PasswordWeb
A function to work around limitation of older pwpusher builds on password retrieval via REST - will send a generic web request and parse it.
Deprecated as pwpusher is updated for REST to work properly.

## To-Do
- [X] Get-Password function to retrieve the password from the server. Implemented as stub function until the reply from service includes decryted password
- [X] Add secondary password retrieve method (over generic web request) to work around encryption in REST response.
- [X] Unpublish-Password function to forcibly remove the password from the server (if allowed by deleteable_by_user)
- [ ] Add $Server/URL validation to make sure it's in proper format and can be reached over port 443/80 based on protocol prefix if supplied or other explicit port
