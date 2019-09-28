function Get-StringEntropy
{
    Param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)][ValidateNotNullOrEmpty()][string]$Val
    )
 
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Val)

    $FrequencyTable = @{}
    foreach ($Byte in $Bytes) {
        $FrequencyTable[$Byte]++
    }
    $Entropy = 0.0
 
    foreach ($Byte in 0..255)
    {
        $ByteProbability = ([Double]$FrequencyTable[[Byte]$Byte])/$Bytes.Length
        if ($ByteProbability -gt 0)
        {
            $Entropy += -$ByteProbability * [Math]::Log($ByteProbability, 2)
        }
    }
    return $Entropy
}