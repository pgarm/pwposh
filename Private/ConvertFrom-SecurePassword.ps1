function ConvertFrom-SecurePassword {
    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)][SecureString]$Password
    )
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
}