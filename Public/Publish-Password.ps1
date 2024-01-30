function Publish-Password {
    <#
    .SYNOPSIS
    Pushes the password to public pwpush.com or a private instance of Password Pusher and retrieves the link.
    .DESCRIPTION
    This complements Peter Giacomo Lombardo's genius idea of sending a temporary link to password instead of plaintext (https://github.com/pglombardo/PasswordPusher).
    By default will work against publicly hosted instance at https://pwpush.com, but can use your privately hosted instance by specifying the target as script parameter.
    .NOTES
    You can still use any function you like to generate and submit the password as SecureString (recommended) or in plaintext (you should never do that in production).
    Some options include:
        [System.Web.Security.Membership]::GeneratePassword(16,2) will generate a 16-character-long password with at least two symbols in it as plaintext (requires
            System.Web assembly to be loaded, not supported in .Net/PoSh Core)
        A custom New-Password function included as part of this module
    .PARAMETER Link
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
    Specifies server/service to use in FQDN format, assumes https:// protocol prefix and default port 443.
    Defaults to public pwpush.com
    Can be aliased as -s
    .PARAMETER DeletableByViewer
    Allows anyone accessing the link to delete it before it expires, False by default
    Can be aliased as -k
    .PARAMETER FirstView
    Tells the server to use the "First view" experience (that's not counted towards maximum views).
    Due to a current bug/deficiency in pwpush the API ignores the switch if supplied in the REST call and the option is always on.
    So, for the time being, it's emulated by using HTTP GET against the URL if the switch is not specified in the command.
    Can be aliased as -f
    .PARAMETER Wipe
    Wipe the password object from memory using Dispose() method after successful publishing, False by default
    Can be aliased as -k
    .EXAMPLE
    $SecurePass | Publish-Password

    Pushes the password stored in [SecureString]$SecurePass to https://pwpush.com with default settings.
    .EXAMPLE
    Publish-Password -Password P@ssw0rd -Days 3 -Views 10

    Pushes password "P@ssw0rd" to https://pwpush.com, expiring after 3 days or 10 views, whichever comes first.
    Will throw a warning about using plain-text password.
    #>

    param (
        # First parameter below generates a warning in most PoSh IDEs, flagging it as unsecure password storage.
        # To mitigate this but still allow for flexibility in custom scripts we force-convert it at the start.
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)][Alias("p")]$Password,
        [Alias("d")][int]$Days = 7,
        [Alias("v")][int]$Views = 1,
        [Alias("s")][string]$Server = "pwpush.com",
        [SecureString] $Passphrase = $null,
        [ValidateSet("ca","cs","da","de","en","es","eu","fi","fr","hi","hu","id","is","it","ja","ko","lv","nl","no","pl","pt-br","pt-pt","ro","ru","sr","sv","th","uk","ur","zh-cn")]
        [String] $Language,
        [Alias("k", "KillSwitch")][switch]$DeletableByViewer,
        [Alias("f", "FirstView")][switch] $RetrievalStep,
        [Alias("w")][switch]$Wipe,
        [PSCredential] $Creds
    )

    # If the password is supplied as anything but SecureString, throw a warning and force-convert it
    if ($Password -isnot [securestring]) {
        Write-Host -ForegroundColor Yellow "You should use SecureString type to process passwords in scripts. Converting now..."
        [securestring] $Password = ConvertTo-SecureString ([string]$Password) -AsPlainText -Force
    }

    # Push the password, retrieve the response
    $Body = [Ordered] @{
        "password[payload]"            = ConvertFrom-SecurePassword $Password
        "password[expire_after_days]"  = $Days
        "password[expire_after_views]" = $Views
    }
    If ($DeletableByViewer) {
        $Body.Add('password[deletable_by_viewer]', "1")
    }
    If ($RetrievalStep) {
        $Body.Add('password[retrieval_step]', "1")
    }
    If ($Passphrase) {
        $Body.Add('password[passphrase]', (ConvertFrom-SecurePassword $Passphrase))
    }
    $Headers = @{}
    If ($Creds) {
        $Headers.Add('X-User-Email', $Creds.UserName)
        $Headers.Add('X-User-Token', $Creds.GetNetworkCredential().Password)
    }
    #$Body
    Try {
        $IwrParams = @{
            Method          = "POST"
            URI             = "https://$Server/p.json"
            #ContentType = 'application/x-www-form-urlencoded'
            ContentType     = 'application/x-www-form-urlencoded;charset=UTF-8'
            Headers         = $Headers
            Body            = $Body
            UseBasicParsing = $true
        }
        If ($Env:HTTP_PROXY -or $Env:HTTPS_PROXY) {
            $IwrParams.Add('Proxy', $(If ($Env:HTTPS_PROXY) { $ENV:HTTPS_PROXY } else { $ENV:ALLUSERSPROFILE }))
        }
        $Reply = Invoke-WebRequest @IwrParams
    }
    Catch {
        $LastError = $Error[0]
        Write-Error ("An error occured: " + $LastError)
        return $null
    }
    $url_token = $Reply.Content | ConvertFrom-Json | Select-Object -ExpandProperty url_token
    if ($url_token) {
        # Emulating the first_view = false; Current builds of pwpusher handle the switch properly, but for older ones we'll keep the emulation in place and throw a warning
        # Triggered if returned first_view is True and requested is False (only case where boolean can be greater than)
        <#
        if ($Reply.first_view -gt $FirstView.IsPresent) {
            Invoke-RestMethod -Method 'Get' -Uri "https://$Server/p/$($Reply.url_token).json" | Out-Null
            Write-Host -ForegroundColor Yellow "The version of PasswordPusher you're using is outdated and doesn't properly support FirstView switch`n" +`
            "Please update to a build that includes pull request #112"
        }
        #>
        # Dispose of secure password object - note it's the original object, not a function-local copy
        if ($Wipe) { $Password.Dispose() }
        If ($Language) {
            return "https://$Server/$Language/p/$($url_token)"
        } Else {
            return "https://$Server/p/$($url_token)"
        }
    }
    else {
        Write-Error "Unable to get URL from service"
    }
}

If (-not (Get-Alias pbpwd -ErrorAction SilentlyContinue)) { New-Alias pbpwd Publish-Password }