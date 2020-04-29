function ConvertFrom-SecurePassword {
    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)][SecureString]$Password
    )
    return [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
}