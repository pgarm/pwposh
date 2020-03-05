# PwPoSh
Password-related scriptlets module to help with account provisioning or password resets, more useful in bulk operations
Started as a way to automate using [Peter Giacomo Lombardo](https://github.com/pglombardo)'s [PasswordPusher](https://github.com/pglombardo/PasswordPusher) to generate password links (better than sending passwords in plain text).

Available on PowerShell Gallery at https://www.powershellgallery.com/packages/PwPoSh/
```powershell
Install-Module -Name PwPoSh
```

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
Moved to Issues