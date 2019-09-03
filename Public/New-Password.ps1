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
    Length of password required. 8 characters by default.
    Also can be aliased as -l
    .PARAMETER Capitals
    Minimum number of capital Latin letters in the resulting password. By default 1/4 of total length.
    Can be aliased as -c
    .PARAMETER Digits
    Minimum number of digits 0-9 in the resulting password. By default 1/6 of total length.
    Can be aliased as -d
    .PARAMETER Symbols
    Minimum number of symbols in the resulting password. By default 1/8 of total length.
    Can be aliased as -s
    .PARAMETER Simple
    Sets complexity to off (generates an all-lowercase password).
    Can be aliased as -x
    .PARAMETER Hard
    Removes most ambiguous characters from available pool to make sure password is still legible even if written by hand on paper.
    Can be aliased as -h
    .PARAMETER Soft
    Removes some ambiguous characters from available pool to make sure password is fully readable on screen regardless of font and
    accepted by most applications that have restrictions due to database limitations.
    Can be aliased as -o
    .PARAMETER Exclude
    Specifies custom list of characters to exclude from available pool to adapt to specific requirements.
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
        [Parameter(Position=0)][Alias("l")][int]$Length=8,
        [Parameter(ParameterSetName="Hard")][Parameter(ParameterSetName="Soft")][Parameter(ParameterSetName="Full")][Parameter(ParameterSetName="Custom")]
            [Alias("c")][int]$Capitals=[System.Math]::Floor($Length/4),
        [Parameter(ParameterSetName="Hard")][Parameter(ParameterSetName="Soft")][Parameter(ParameterSetName="Full")][Parameter(ParameterSetName="Custom")]
            [Alias("d")][int]$Digits=[System.Math]::Floor($Length/6),
        [Parameter(ParameterSetName="Hard")][Parameter(ParameterSetName="Soft")][Parameter(ParameterSetName="Full")][Parameter(ParameterSetName="Custom")]
            [Alias("s")][int]$Symbols=[System.Math]::Floor($Length/8),
        [Parameter(ParameterSetName="Simple")][Alias("x")][switch]$Simple,
        [Parameter(ParameterSetName="Hard")][Alias("Hard","h")][switch]$ExcludeHard,
        [Parameter(ParameterSetName="Soft")][Alias("Soft","o")][switch]$ExcludeSoft,
        [Parameter(ParameterSetName="Custom")][Alias("Exclude","e")][string]$ExcludeChars
    )
    
    $DigList = "0123456789"
    $LowList = "abcdefghijklmnopqrstuvwxyz"
    $CapList = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $SymList = "!`"#$%&'()*+,-./:;<=>?@[\]^_``{|}~ "
    
    switch ($psCmdlet.ParameterSetName) {
        "Simple" {
            $Capitals,$Digits,$Symbols = 0
            $Lowers = $Length
        }
        Default {
            if ($Length -le ($Capitals + $Digits + $Symbols)) {
                $Lowers = 1; $Length = $Capitals + $Digits + $Symbols + $Lowers
                Write-Host -ForegroundColor Yellow "Requested character composition exceeds requested password length, extending to acommodate"
            } else {
                $Lowers = [System.Math]::Ceiling(($Length - ($Capitals + $Digits + $Symbols)) / 2)
                $WhiList = $DigList + $LowList + $CapList + $SymList
            }
            switch ($psCmdlet.ParameterSetName) {
                "Hard" {$SkipList = (("0OQDB86G&5S`$2?Z1lI!|/\-_```"'(){}[]<>.,:;%XuvUV9g ").ToCharArray() | ForEach-Object {[regex]::Escape($_)}) -join "|"}
                "Soft" {$SkipList = (("0OB81lI|```"'.,:;").ToCharArray() | ForEach-Object {[regex]::Escape($_)}) -join "|"}
                "Custom" {$SkipList = ($ExcludeChars.ToCharArray() | ForEach-Object {[regex]::Escape($_)}) -join "|"}
                Default {$SkipList = ""}
            }
            $DigList = $DigList -replace $SkipList,""
            $LowList = $LowList -replace $SkipList,""
            $CapList = $CapList -replace $SkipList,""
            $SymList = $SymList -replace $SkipList,""
        }
    }

    $SecPwd = New-Object -TypeName securestring
    $Length..1 | ForEach-Object {
        switch (Get-Random ($_)) {
            {$_ -lt ($Lowers)} {$SecPwd.AppendChar(($LowList.ToCharArray() | Get-Random)); $Lowers += -1; $Length += -1; break}
            {$_ -lt ($Lowers + $Capitals)} {$SecPwd.AppendChar(($CapList.ToCharArray() | Get-Random)); $Capitals += -1; $Length += -1; break}
            {$_ -lt ($Lowers + $Capitals + $Digits)} {$SecPwd.AppendChar(($DigList.ToCharArray() | Get-Random)); $Digits += -1; $Length += -1; break}
            {$_ -lt ($Lowers + $Capitals + $Digits + $Symbols)} {$SecPwd.AppendChar(($SymList.ToCharArray() | Get-Random)); $Symbols += -1; $Length += -1; break}
            Default {$SecPwd.AppendChar(($WhiList.ToCharArray() | Get-Random)); $Length += -1; break}
        }
    }

    return $SecPwd
}

New-Alias newpw New-Password