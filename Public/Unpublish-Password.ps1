function Unpublish-Password {
    <#
    .SYNOPSIS
    Removes the password from public pwpush.com or a private instance of Password Pusher by using a full link or a combination of server and password.
    .DESCRIPTION
    This complements Peter Giacomo Lombardo's genius idea of sending a temporary link to password instead of plaintext (https://github.com/pglombardo/PasswordPusher).
    By default will work against publicly hosted instance at https://pwpush.com, but can use your privately hosted instance by specifying the target as script parameter.
    .NOTES
    Mostly useful in automation with deferred password auth/use, e.g. domain join of prestaged computers.
    .PARAMETER Link
    Link to remove password from in full https://pwpush.com/p/a1b2c3d4e5f6g7h8 form. Will append .json automatically.
    Can be aliased as -l
    .EXAMPLE 
    $pwdlink | Unpublish-Password

    Removes the password from the specified link.
    #>

    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][Alias("l")]
            [ValidatePattern("^(http[s]?)(?:\:\/\/)([\w_-]+(?:(?:\.[\w_-]+)+))(?:\/p\/)([\w]+)")]$Uri
    )

    # Kill the password
    try {
        $Reply = Invoke-RestMethod -Method 'Delete' -Uri "$Uri.json"
        # There's a bug currently in the older builds of API that returns DELETE result as HTTP/500, generating an error - we catch that in the next block
        # WIn the newer builds, the next line would eval deletion
        if ($Reply.deleted) {Write-Host "Unpublished the password successfully from $Uri (or it had been deleted already)"}
    } catch {
        if ($_.Exception -notmatch '500') {
            Write-Error "Error removing the password"
        } elseif ((ConvertFrom-Json $_.ErrorDetails).deleted) {
            # Catching the HTTP/500 response
            Write-Host "Unpublished the password successfully from $Uri (or it had been deleted already)"
            Write-Host -ForegroundColor Yellow "You seem to be using an outdated version of pwpusher that returns successful deletion as HTTP/500 error.`n" +`
                                               "Please update from https://github.com/pglombardo/PasswordPusher to a build incorporating pull request #115"
        }
    }
}

New-Alias ubpwd Unpublish-Password