# Get Services with StartMode Automatic (Trigger or Delayed Start)
$Services = Get-WmiObject -Class Win32_Service -Filter { 
    State != 'Running' and StartMode = 'Auto' 
}            
foreach ($Service in $Services.Name) { 
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Service" | 
    #StartMode Automatic (without delayed)
    #Where-Object {$_.Start -eq 2 -and $_.DelayedAutoStart -ne 1} | 
    #StartMode Automatic (with Delayed or Trigger Start)
    Where-Object {$_.Start -eq 2} | 
    Select-Object -Property @{label='ServiceName';expression={$_.PSChildName}} | 
    Get-Service | Select Status,StartMode,Name,DisplayName
} 
