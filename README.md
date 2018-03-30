# SomeStuff

## CheckIsLoggedOnUserAdmin
Check if LoggedOnUser is memberOf local Admin.   

## CheckIsHostnameChanged
Check if the ComputerName is not changed.   

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
