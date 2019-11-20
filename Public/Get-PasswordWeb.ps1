function Get-PasswordWeb {
    <#
    .SYNOPSIS
    DEPRECATED as the PasswordPusher had been updated to properly return password over API.
    Pulls the password from public pwpush.com or a private instance of Password Pusher by using a full link.
    Uses generic HTTP web request for compatibility with older builds of pwpusher
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
    $pwdlink | Get-PasswordWeb

    Pulls the password from the specified link.
    #>

    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][Alias("l")]
            [ValidatePattern("^(http[s]?)(?:\:\/\/)([\w_-]+(?:(?:\.[\w_-]+)+))(?:\/p\/)([\w]+)")]$Uri,
        [Alias("k")][switch]$Kill
    )

    # Pull the password
    try {
        $Reply = Invoke-WebRequest -Uri $Uri
    } catch {
        Write-Error "Unable to get the response from service"
    }

    # Parse the response if received - is the password deleted, expired or retrieved successfully
    if ($Reply.Content -match "<p>\nThis secret link was manually expired by one of its viewers and the password has been deleted from the PasswordPusher database.\n</p>") {
        Write-Error "Password can't be retrieved as it had been explicitly deleted"
    } elseif ($Reply.Content -match "<div class='payload'>\nThis secret link has expired.\n</div>") {
        Write-Error "Password can't be retrieved as it had expired already"
    } elseif ($Reply.Content -match "(?:\<div class\=\'payload spoiler\' id\=\'pass\'\>)(.+)(?:\<\/div\>)") {
        # Delete the password from database if requested
        if ($Kill.IsPresent) {
            Unpublish-Password -Uri $Uri
        }
        return (ConvertTo-SecureString $Matches[1] -AsPlainText -Force)
    } else {
        Write-Error "Unable to retrieve the password"
    }
}

New-Alias gpwdweb Get-PasswordWeb