# SomeStuff

## LoggedOnUser
Check if LoggedOnUser is memberOf local Admin
````$Computername   = $env:COMPUTERNAME   
$LoggedOnUsers  = (Get-CimInstance Win32_LoggedOnUser).antecedent.name | Select-Object -Unique   
$Administrators = Get-LocalGroupMember -SID S-1-5-32-544  
foreach($item in $LoggedOnUsers){   
    if($Administrators.Name -match "$Computername\\$item"){   
        $true   
    }   
    else{   
        $false   
    }   
}
````

## Hostname
````
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
    Write-Host "Current ComputerName: $CurrentComputerName, Last ComputerName: $LastSavedComputerName" -ForegroundColor Red
}
else{
    Write-Host "Current ComputerName is equal to Last ComputerName: $LastSavedComputerName" -ForegroundColor Green
}
````
