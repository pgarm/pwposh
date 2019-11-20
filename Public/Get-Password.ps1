function Get-Password {
    <#
    .SYNOPSIS
    Pulls the password from public pwpush.com or a private instance of Password Pusher by using a full link or a combination of server and password.
    .DESCRIPTION
    This complements Peter Giacomo Lombardo's genius idea of sending a temporary link to password instead of plaintext (https://github.com/pglombardo/PasswordPusher).
    By default will work against publicly hosted instance at https://pwpush.com, but can use your privately hosted instance by specifying the target as script parameter.
    .NOTES
    Mostly useful in automation deferred password auth/use, e.g. domain join of prestaged computers.
    .PARAMETER Link
    Link to retrieve password from in full https://pwpush.com/p/a1b2c3d4e5f6g7h8 form. Will append .json automatically.
    Can be aliased as -l
    .PARAMETER Kill
    Delete the password from database (if allowed by pusher originally), False by default
    Can be aliased as -k
    .EXAMPLE 
    $pwdlink | Get-Password

    Pulls the password from the specified link.
    #>

    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][Alias("l")]
            [ValidatePattern("^(http[s]?)(?:\:\/\/)([\w_-]+(?:(?:\.[\w_-]+)+))(?:\/p\/)([\w]+)")]$Uri,
        [Alias("k")][switch]$Kill
    )

    # Pull the password
    try {
        $Reply = Invoke-RestMethod -Method 'Get' -Uri "$Uri.json"
    } catch {
        Write-Error "Unable to get the response from service"
    }

    switch ($Reply.expired + $Reply.deleted) {
        2 {Write-Error "Password can't be retrieved as it had been explicitly deleted"}
        1 {Write-Error "Password can't be retrieved as it had expired already"}
        Default {
            if ($Reply.payload -match "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$") {
                Write-Error "The password retrieved is Base64-encoded/encrypted, so you're probably using an old build of pwpusher.`n" `
                + "Please update from https://github.com/pglombardo/PasswordPusher to a build incorporating pull request #113`n" `
                + "In the meantime you can use Get-PasswordWeb function"
            } else {
                if ($Kill.IsPresent) {
                    Unpublish-Password -Uri $Uri
                }
                return (ConvertTo-SecureString $Reply.payload -AsPlainText -Force)    
            }
        }
    }
}

New-Alias gpwd Get-Password