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
    Specifies server/service to use in FQDN format, assumes https:// protocol prefix and default port 443.
    Defaults to public pwpush.com
    Can be aliased as -s

    .PARAMETER DeletableByViewer
    Allows anyone accessing the link to delete it before it expires, False by default
    Can be aliased as -k

    .PARAMETER RetrievalStep
    Tells the server to use the 1-click retrieval step. Helps to avoid chat systems and URL scanners from eating up the views.

    .PARAMETER Wipe
    Wipe the password object from memory using Dispose() method after successful publishing, False by default
    Can be aliased as -w

    .PARAMETER APICreds
    Provide credentials to use the Pwpush.com authenticated API. Username is the email address registered on pwpush.com. Password is the API token given on pwpush.com > Account

    .PARAMETER Passphrase
    Require recipients to enter a passphrase to view this push

    .PARAMETER Language
    Language to use on the password retrieval page.

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
        [Alias("v")][int]$Views = 5,
        [Alias("s")][string]$Server = "pwpush.com",
        [SecureString] $Passphrase = $null,
        [ValidateSet("ca", "cs", "da", "de", "en", "es", "eu", "fi", "fr", "hi", "hu", "id", "is", "it", "ja", "ko", "lv", "nl", "no", "pl", "pt-br", "pt-pt", "ro", "ru", "sr", "sv", "th", "uk", "ur", "zh-cn")]
        [String] $Language,
        [Alias("k", "KillSwitch")][switch]$DeletableByViewer,
        [Alias("f", "FirstView")][switch] $RetrievalStep,
        [Alias("w")][switch]$Wipe,
        [PSCredential] $APICreds
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
    If ($APICreds) {
        $Headers.Add('X-User-Email', $APICreds.UserName)
        $Headers.Add('X-User-Token', $APICreds.GetNetworkCredential().Password)
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
            $IwrParams.Add('Proxy', $(If ($Env:HTTPS_PROXY) { $ENV:HTTPS_PROXY } else { $ENV:HTTP_PROXY }))
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
        # Dispose of secure password object - note it's the original object, not a function-local copy
        if ($Wipe) { $Password.Dispose() }

        $LanguageStr = ""
        If ($Language) {
            $LanguageStr = "/$Language"
        }

        $RetrievalStepStr = ""
        If ($RetrievalStep) {
            $RetrievalStepStr = "/r"
        }

        return "https://{0}{1}/p/{2}{3}" -f $Server, $LanguageStr, $url_token, $RetrievalStepStr
    }

    else {
        Write-Error "Unable to get URL from service"
    }
}

If (-not (Get-Alias pbpwd -ErrorAction SilentlyContinue)) { New-Alias pbpwd Publish-Password }