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
Check the ComputerName not changed
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

## Certificate
Check expired Root Certificates
````
Get-ChildItem Cert:\LocalMachine\Root | Where-Object NotAfter -lt (Get-Date) | Select-Object FriendlyName,DnsNameList,NotBefore,NotAfter
````
## Eventlogs

````
$ret = @()
[DateTime]$now    = Get-Date
[DateTime]$after  = $now.AddDays(-30)
[DateTime]$before = $now

# Get Unexpected Shutdowns 6008 or System Crashes 1001 of the las 30 days
$Logname          = 'System'
try{
    Get-EventLog $Logname -InstanceId 1001, 6008 -EntryType Error -After $after -Before $before -ErrorAction SilentlyContinue | %{
        $obj = [PSCustomObject]@{
            Logname       = $Logname
            TimeGenerated = $_.TimeGenerated
            EventID       = $_.EventID
            EntryType     = $_.EntryType
            Message       = $_.Message
        }
        $ret += $obj
    }
}
catch{
    $Error.Clear()
}

# Get all Errors of the las 30 days
$Logname          = 'System'
try{
    Get-EventLog $Logname -EntryType Error -After $after -Before $before -ErrorAction SilentlyContinue | %{
        $obj = [PSCustomObject]@{
            Logname       = $Logname
            TimeGenerated = $_.TimeGenerated
            EventID       = $_.EventID
            EntryType     = $_.EntryType
            Message       = $_.Message
        }
        $ret += $obj
    }
}
catch{
    $Error.Clear()
}

$Logname          = 'Application'
try{
    Get-EventLog $Logname -EntryType Error -After $after -Before $before -ErrorAction SilentlyContinue | %{
        $obj = [PSCustomObject]@{
            Logname       = $Logname
            TimeGenerated = $_.TimeGenerated
            EventID       = $_.EventID
            EntryType     = $_.EntryType
            Message       = $_.Message
        }
        $ret += $obj
    }
}
catch{
    $Error.Clear()
}

$ret | Sort-Object TimeGenerated | Format-Table -AutoSize
````
