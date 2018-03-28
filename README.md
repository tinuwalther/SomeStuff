# SomeStuff

## LoggedOnUser
Check if LoggedOnUser is memberOf local Admin
````$Computername   = $env:COMPUTERNAME   
$LoggedOnUsers  = (Get-CimInstance Win32_LoggedOnUser).antecedent.name | Select-Object -Unique   
$Administrators = Get-LocalGroupMember -Group Administrators   
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
(Get-ChildItem HKLM:\SYSTEM\ControlSet001\Control\ComputerName)
(Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName)
````
