function New-Password {
    <#
    .SYNOPSIS
    Generates a new password as SecureString.
    .DESCRIPTION
    Another take on the basic function frequently required in automation. Generates a random enough password with some options to make it easily usable and readable if needed.
    .NOTES
    I've previously used [System.Web.Security.Membership]::GeneratePassword(), but it's no longer supported in .Net/PoSh Core so had to build a custom function from scratch.
    Another benefit is I now get my passwords as SecreString that can be used with most Microsoft commandlets directly.
    Only uses ANSI character table for compatibility with recipient systems (no national alphabets etc).
    There would always be at least one lowercase letter in the password, and if the requested composition of capitals + digits + symbols is longer than requested length
    after allowing for the lowercase, the length would be dynamically expanded.
    .PARAMETER Length
    Length of password required. 8 characters by default. Allowed range 4-64
    Also can be aliased as -n
    .PARAMETER Capitals
    Minimum number of capital Latin letters in the resulting password. By default 1/4 of total length.
    Setting to 0 will ensure no capital letters are used in password generation. Allowed range 0-64
    Can be aliased as -c
    .PARAMETER Digits
    Minimum number of digits 0-9 in the resulting password. By default 1/6 of total length.
    Setting to 0 will ensure no numeric characters are used in password generation. Allowed range 0-64
    Can be aliased as -d
    .PARAMETER Symbols
    Minimum number of symbols in the resulting password. By default 1/8 of total length.
    Setting to 0 will ensure no symbols are used in password generation. Allowed range 0-64
    Can be aliased as -s
    .PARAMETER Lowers
    Minimum number of lowercase Laten letters in the resulting password. By default 1/2 of total length remaining after allocating caps, digits and symbols with a minimum of 1.
    Setting to 0 will ensure no lowercase letters are used in password generation. Allowed range 0-64
    Can be aliased as -l
    .PARAMETER Simple
    Sets complexity to off (generates an all-lowercase password). A shortcut for
        New-Password -Capitals 0 -Digits 0 -Symbols 0
    Can be aliased as -a
    .PARAMETER Pin
    Forces generation of an all-numeric PIN.A shortcut for
        New-Password -Capitals 0 -Lowers 0 -Symbols 0
    Can be aliased as -p
    .PARAMETER ExcludeHard
    Removes most ambiguous characters from available pool to make sure password is still legible even if written by hand on paper.
    Can be aliased as -h
    .PARAMETER ExcludeSoft
    Removes some ambiguous characters from available pool to make sure password is fully readable on screen regardless of font and
    accepted by most applications that have restrictions due to database limitations.
    Can be aliased as -o
    .PARAMETER ExcludeChars
    Specifies custom list of characters to exclude from available pool to adapt to specific requirements.
    Can be aliased as -x
    .PARAMETER Entropy
    Specifies minimum entropy value. Would be reduced in processing if set above the thoretical maximum. Default value is 3 (max for 8-character string)
    Can be aliased as -e
    .EXAMPLE 
    New-Password

    Generates a random password 8 characters long with full printable charset.
    .EXAMPLE
    New-Password -Length 16 -Simple

    Generates a 16-character lowercase password.
    #>

    [CmdletBinding(DefaultParameterSetName="Full")]
    param (
        [Parameter(Position=0)][ValidateRange(4,64)][Alias("n")][int]$Length=8,
        [ValidateRange(2,6)][Alias("e")][decimal]$Entropy=3,
        [Parameter(ParameterSetName="Hard")][Parameter(ParameterSetName="Soft")][Parameter(ParameterSetName="Full")][Parameter(ParameterSetName="Custom")]
            [Alias("c")][int][ValidateRange(0,64)]$Capitals=[System.Math]::Floor($Length/4),
        [Parameter(ParameterSetName="Hard")][Parameter(ParameterSetName="Soft")][Parameter(ParameterSetName="Full")][Parameter(ParameterSetName="Custom")]
            [Alias("d")][int][ValidateRange(0,64)]$Digits=[System.Math]::Floor($Length/6),
        [Parameter(ParameterSetName="Hard")][Parameter(ParameterSetName="Soft")][Parameter(ParameterSetName="Full")][Parameter(ParameterSetName="Custom")]
            [Alias("s")][int][ValidateRange(0,64)]$Symbols=[System.Math]::Floor($Length/8),
        [Parameter(ParameterSetName="Hard")][Parameter(ParameterSetName="Soft")][Parameter(ParameterSetName="Full")][Parameter(ParameterSetName="Custom")]
            [Alias("l")][int][ValidateRange(0,64)]$Lowers=[System.Math]::max(([System.Math]::Ceiling(($Length - ($Capitals + $Digits + $Symbols)) / 2)),1),
        [Parameter(ParameterSetName="Simple")][Alias("a")][switch]$Simple,
        [Parameter(ParameterSetName="Pin")][Alias("p")][switch]$Pin,
        [Parameter(ParameterSetName="Hard")][Alias("Hard","h")][switch]$ExcludeHard,
        [Parameter(ParameterSetName="Soft")][Alias("Soft","o")][switch]$ExcludeSoft,
        [Parameter(ParameterSetName="Custom")][Alias("Exclude","x")][string]$ExcludeChars
    )
    
    # If composition requested is 0 for all character sets, fail utterly (we can't possibly generate a password with no characters in it)
    if (($Lowers + $Capitals + $Digits + $Symbols) -eq 0) {Write-Error "New-Password : Couldn't determine character composition with all 0s requested" -ErrorAction Stop}

    # If the requested Entropy is higher than theoretical maximum for length, reduce it to a resonable value
    if ($Entropy -gt [math]::Log($Length,2)) {
        $Entropy = [math]::Log($Length,2) * .95
        Write-Host "Requested entropy was too high, reducing to $Entropy"
    }

    $DigList = "0123456789"
    $LowList = "abcdefghijklmnopqrstuvwxyz"
    $CapList = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $SymList = "!`"#$%&'()*+,-./:;<=>?@[\]^_{|}~ "
    
    switch ($psCmdlet.ParameterSetName) {
        "Simple" {
            $Capitals,$Digits,$Symbols = 0
            $Lowers = $Length
        }
        "Pin" {
            $Capitals,$Lowers,$Symbols = 0
            $Digits = $Length
        }
        Default {
            # Remove requested characters from available set
            switch ($psCmdlet.ParameterSetName) {
                "Hard" {$SkipList = (("0OQDB86G&5S`$2?Z1lI!|/\-_`"'(){}[]<>.,:;%XuvUV9g ").ToCharArray() | ForEach-Object {[regex]::Escape($_)}) -join "|"}
                "Soft" {$SkipList = (("0OB81lI|```"'.,:;").ToCharArray() | ForEach-Object {[regex]::Escape($_)}) -join "|"}
                "Custom" {$SkipList = ($ExcludeChars.ToCharArray() | ForEach-Object {[regex]::Escape($_)}) -join "|"}
                Default {$SkipList = ""}
            }
            $DigList = $DigList -replace $SkipList,""
            $LowList = $LowList -replace $SkipList,""
            $CapList = $CapList -replace $SkipList,""
            $SymList = $SymList -replace $SkipList,""
            
            # Establish password composition
            if ($Length -lt ($Lowers + $Capitals + $Digits + $Symbols)) {
                $Length = $Capitals + $Digits + $Symbols + $Lowers
                Write-Host -ForegroundColor Yellow "Requested character composition exceeds requested password length, extending to acommodate"
            } else {
                if ($Lowers -gt 0) {$WhiList = $LowList}
                if ($Digits -gt 0) {$WhiList += $DigList}
                if ($Capitals -gt 0) {$WhiList += $CapList}
                if ($Symbols -gt 0) {$WhiList += $SymList}
            }
        }
    }

    # Generate password of at least the desired strength (in terms of entropy, defaulting to 3)
    do {
        # Set disposable counters so that re-run is easy to do
        $WorkSet = [pscustomobject]@{
            Length = $Length
            Lowers = $Lowers
            Capitals = $Capitals
            Digits = $Digits
            Symbols = $Symbols
        }

        $SecPwd = New-Object -TypeName securestring
        ($WorkSet.Length)..1 | ForEach-Object {
            switch (Get-Random ($_)) {
                {$_ -lt ($WorkSet.Lowers)} {$SecPwd.AppendChar(($LowList.ToCharArray() | Get-Random)); $WorkSet.Lowers += -1; $WorkSet.Length += -1; break}
                {$_ -lt ($WorkSet.Lowers + $WorkSet.Capitals)} {$SecPwd.AppendChar(($CapList.ToCharArray() | Get-Random)); $WorkSet.Capitals += -1; $WorkSet.Length += -1; break}
                {$_ -lt ($WorkSet.Lowers + $WorkSet.Capitals + $WorkSet.Digits)} {$SecPwd.AppendChar(($DigList.ToCharArray() | Get-Random)); $WorkSet.Digits += -1; $WorkSet.Length += -1; break}
                {$_ -lt ($WorkSet.Lowers + $WorkSet.Capitals + $WorkSet.Digits + $WorkSet.Symbols)} {$SecPwd.AppendChar(($SymList.ToCharArray() | Get-Random)); $WorkSet.Symbols += -1; $WorkSet.Length += -1; break}
                Default {$SecPwd.AppendChar(($WhiList.ToCharArray() | Get-Random)); $WorkSet.Length += -1; break}
            }
        }
    } while (([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecPwd)) | Get-StringEntropy) -lt $Entropy)

    return $SecPwd
}

New-Alias npwd New-Password