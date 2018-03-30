function Get-LastSavedComputerName{
    [CmdletBinding()]
    param()
    $function = $($MyInvocation.MyCommand.Name)
    $ret = $null
    try{
        $RegPath = 'HKLM:\SYSTEM\ControlSet001\Control\ComputerName\ComputerName'
        if(Test-Path $RegPath){
            $ret = Get-ItemPropertyValue $RegPath -Name ComputerName -ErrorAction Stop
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

$CurrentComputerName   = $env:COMPUTERNAME
$LastSavedComputerName = Get-LastSavedComputerName -Verbose

if ($CurrentComputerName -ne $LastSavedComputerName){
    @{ChangedComputerName="From $LastSavedComputerName to $CurrentComputerName"}
}
