function Push-Password {
    <#
    .SYNOPSIS
    Pushes the password to public pwpush.com or a private instance of Password Pusher and retrieves the link.
    .DESCRIPTION
    This complements Peter Giacomo Lombardo's genius idea of sending a temporary link to password instead of plaintext (https://github.com/pglombardo/PasswordPusher).
    By default will work against publicly hosted instance at https://pwpush.com, but can use your privately hosted instance by specifying the target as script parameter.
    .NOTES
    You can still any function you like to generate and submit the password as SecureString (recommended) or in plaintext (you should never do that in production).
    Some options include:
        [System.Web.Security.Membership]::GeneratePassword(16,2) will generate a 16-character-long password with at least two symbols in it as plaintext (requires System.Web assembly to be loaded, not supported in .Net/PoSh Core)
        A custom New-Password function included as part of this module
    .PARAMETER Password
    Password to push. If no value is provided, random password will be generated.
    Should be specified as SecureString, anything else will be cast to String and force-converted to SecureString for processing.
    Using plain-text passwords should be avoided wherever possible.
    Can be aliased as -p
    .PARAMETER Days
    Number of days before the link expires. Default value is 7 days. Permitted range is dependent on service configuration, generally 1-90 days.
    Can be aliased as -d
    .PARAMETER Views
    Number of views before the link expires. Default value is 5 views. Permitted range is dependent on service configuration, generally 1-100 views.
    Can be aliased as -v
    .PARAMETER Server
    Specifies server/service to use, assumes https:// protocol prefix so only need FQDN.
    Defaults to public pwpush.com
    Can ba aliased as -s
    .PARAMETER KillSwitch
    Allows the anyone accessing the link to delete it before it expires, False by default
    Can be aliased as -k
    .PARAMETER FirstView
    Tells the server to use the "First view" experience (that's not counted towards maximum views).
    Due to a current bug/deficiency in pwpush the API ignores the switch if supplied in the REST call and the option is always on.
    So, for the time being, it's emulated by using HTTP GET against the URL if the switch is not specified in the command.
    Can be aliased as -f
    .EXAMPLE 
    $SecurePass | Push-Password

    Pushes the password stored in [SecureString]$SecurePass to https://pwpush.com with default settings.
    .EXAMPLE
    Push-Password -Password P@ssw0rd -Days 3 -Views 10

    Pushes password "P@ssw0rd" to https://pwpush.com, expiring after 3 days or 10 views, whichever comes first.
    Will throw a warning about using plain-text password.
    #>

    param (
        # First parameter below generates a warning in most PoSh IDEs, flagging it as unsecure password storage.
        # To mitigate this but still allow for flexibility in custom scripts we force-convert it at the start.
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)][Alias("p")]$Password,
        [Alias("d")][int]$Days=7,
        [Alias("v")][int]$Views=5,
        [Alias("s")][string]$Server="pwpush.com",
        [Alias("k")][switch]$KillSwitch,
        [Alias("f")][switch]$FirstView
    )

    # If the password is supplied as anything but SecureString, throw a warning and force-convert it
    if ($Password -isnot [securestring]) {
        Write-Host -ForegroundColor Yellow "You should use SecureString type to process passwords in scripts. Converting now..."
        [securestring]$Password = ConvertTo-SecureString ([string]$Password) -AsPlainText -Force
    }

    $Url = "https://$Server/p.json"
    $Body = @{
        # Even though it's not perfectly secure, the API only accepts plaintext password so we have to recover it from SecureString type
        'password[payload]' = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        'password[expire_after_days]' = $Days
        'password[expire_after_views]' = $Views
    }
    if ($KillSwitch) {$Body.Add('password[deletable_by_viewer]',"True")}
    # if ($FirstView) {$Body.Add('password[first_view]',"True")}
    # When the API begins to properly handle first_view flag in the request, uncomment above

    $Reply = Invoke-RestMethod -Method 'Post' -Uri $url -Body $body
    # Clean up the decoded password from memory 
    $Body.Remove('password[payload]'); [System.GC]::Collect()

    if ($Reply.url_token) {
        # Emulating the first_view = false; can be removed when the API starts handling it properly
        if (!$FirstView) {Invoke-WebRequest ("https://$Server/p/" + $Reply.url_token)}
        return ("https://$Server/p/" + $Reply.url_token)
    } else {
        ThrowError "Unable to get URL from service"
    }
}

New-Alias pwpush Push-Password