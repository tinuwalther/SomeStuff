# WSUS Client side settins

#https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc708449(v=ws.10)

Get-Item 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'

TargetGroup
WUServer   
WUStatusServer



# Using the Windows Update Agent API
#https://docs.microsoft.com/de-ch/windows/win32/wua_sdk/using-the-windows-update-agent-api

$AutoUpdates = New-Object -ComObject "Microsoft.Update.AutoUpdate"
$AutoUpdates.Results

<#
    LastSearchSuccessDate       : 17.08.2019 08:20:09
    LastInstallationSuccessDate : 17.08.2019 08:20:27
#>

$AutoUpdates.DetectNow() 

$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$UpdateSearcher.ServerSelection = 3
$UpdateSearcher.ServiceID = "7971F918-A847-4430-9279-4A52D1EFE18D"
$WUPacks = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
$WUPacks | Select-Object Title, LastDeploymentChangeTime


Get-Command -Module UpdateServices
