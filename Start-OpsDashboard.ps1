<#
    Remote Operating runs as an ASP.NET web service on http://localhost:20001
#>

#region PowerShell Modules
if(Get-Module UniversalDashboard.Community -ListAvailable){
    if(!(Get-Module UniversalDashboard.Community)){
        Import-Module UniversalDashboard.Community
    }    
}else{
    "PowerShell Module UniversalDashboard.Community not found, Install-Module -Name UniversalDashboard.Community"
    exit -1
}

if(Get-Module PsNetTools -ListAvailable){
    if(!(Get-Module PsNetTools)){
        Import-Module PsNetTools
    }
}else{
    "PowerShell Module PsNetTools not found, download it from https://github.com/tinuwalther/PsNetTools/releases/download/v0.7.5/PsNetTools.zip"
    exit -1
}

if(Get-Module PowervRA -ListAvailable){
    if(!(Get-Module PowerVRA)){
        Import-Module PowerVRA
    }
}else{
    "PowerShell Module PowerVRA not found, Install-Module -Name PowerVRA"
}

if(Get-Module psPAS -ListAvailable){
    if(!(Get-Module psPAS)){
        Import-Module psPAS
    }
}else{
    #"PowerShell Module psPAS not found, Install-Module -Name psPAS"
}
#endregion

#region functions

function Send-RemoteOperatingMail{
    [CmdletBinding()]
    param(
        $MailMessage
    )
    #$Sender      = 'user01@swisscom.com' -> kann nicht dynamisch ausgelesen werden
    $Receipient  = 'martin.walther@swisscom.com'
    switch($Computername){
        'admin' {$SmtpServer  = "psrvcm02mxr0001.sccloudinfra.net"} #Service Tier 2
        default {$SmtpServer  = "psrvcm02mxr0002.sccloudinfra.net"} #Service Tier 1
    }
    $Subject     = $UDTitle
    $BodyMessage = "
Hello

This is a Mail-Notification from $($Computername):

$MailMessage

Regards
$($Sender)
   "
    #Send-MailMessage -From $Sender -To $Receipient -SmtpServer $SmtpServer -Subject $Subject -Body $BodyMessage
}

function Get-SccmAgent{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $SoftwareName
    )
    $ScriptBlockContent = {
        Param($SoftwareName)
        $Software = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*) | Where-Object DisplayName -match $SoftwareName
        if([String]::IsNullOrEmpty($software)){
            [PSCustomObject]@{}
        }else{
            [PSCustomObject]@{
                Name             = $Software.DisplayName
                Version          = $Software.DisplayVersion
                Publisher        = $Software.Publisher
                InstallDate      = $Software.InstallDate
            }
        }
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $SoftwareName
}

function Get-SccmService{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $ServiceName
    )
    $ScriptBlockContent = {
        Param($ServiceName)
        Get-CimInstance win32_service | Where-Object Name -match $ServiceName | Select-Object ProcessId,Name,DisplayName,Description,StartMode,State,Status,PathName,StartName
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $ServiceName
}

function Get-SccmWUAHandlerLog{
    [CmdletBinding()]
    param(
        $RemoteSession
    )
    
    $ScriptBlockContent = {

        $FoundUpdate     = 'Update \(Missing\)\:\D+'
        $InstallStated   = 'Async installation of updates started\D+'
        $InstallFinished = 'Installation of updates completed\D+'
        
        $UpdateRegex     = '(?<=^\<\!\[LOG\[\d\.\sUpdate \(Missing\)\:\s)(.*)(?=\]LOG\]\!\>)'
        $LogRegex        = '(?<=^\<\!\[LOG\[)(.*)(?=\]LOG\]\!\>)'
        $TimeRegex       = '(?<=\<time=")(.*)(?=" date)'
        $DateRegex       = '(?<=date=")(.*)(?=" component)'

        $wulog = Get-Content -Path "C:\Windows\CCM\Logs\WUAHandler.log"
        
        $wulog | Where-Object {$_ -match $FoundUpdate} | ForEach-Object {
            $_ -match $UpdateRegex | Out-Null
            $Log = $Matches[0]

            $_ -match $DateRegex | Out-Null
            $Date = $Matches[0]
    
            $_ -match $TimeRegex | Out-Null
            $Time = $Matches[0]

            $DateTime = "$($Date) $($Time)"
    
            [PSCustomObject]@{
                Message  = $Log
                DateTime = $DateTime
            }
        }

        $wulog | Where-Object {$_ -match $InstallStated} | ForEach-Object {
            $_ -match $LogRegex | Out-Null
            $Log = $Matches[0]

            $_ -match $DateRegex | Out-Null
            $Date = $Matches[0]
    
            $_ -match $TimeRegex | Out-Null
            $Time = $Matches[0]
    
            $DateTime = "$($Date) $($Time)"

            [PSCustomObject]@{
                Message  = $Log
                DateTime = $DateTime
            }
        }

        $wulog | Where-Object {$_ -match $InstallFinished} | ForEach-Object {
            $_ -match $LogRegex | Out-Null
            $Log = $Matches[0]

            $_ -match $DateRegex | Out-Null
            $Date = $Matches[0]
    
            $_ -match $TimeRegex | Out-Null
            $Time = $Matches[0]
    
            $DateTime = "$($Date) $($Time)"

            [PSCustomObject]@{
                Message  = $Log
                DateTime = $DateTime
            }
        }

    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent
}

function Get-CyberArkPassword{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]$VaultSafe,

        [Parameter(Mandatory=$false)]
        [String]$VaultUser
    )
    if(!(Get-Module -Name psPAS)){Import-Module psPAS}

    if(Get-Module -Name psPAS){

        #https://pspas.pspete.dev/commands

        $VaultUserName    = $env:username -replace 'SCIS-'
        $VaultCredentials = Get-Credential -Message 'Enter the Credentials for CyberArk' -UserName $VaultUserName
        if($VaultCredentials){
            $token = New-PASSession -Credential $VaultCredentials -BaseURI https://ss010656.itoper.local
            $Vault = $token | Get-PASAccount -Keywords $VaultUser -Safe $VaultSafe | Get-PASAccountPassword
            $token | Close-PASSession
        }
    }
    return (ConvertTo-SecureString $Vault.Password -AsPlainText -Force)
}

function Get-WsusServer{
    [CmdletBinding()]
    param(
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        $config = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUServer' -ErrorAction SilentlyContinue
        $Status = (Invoke-WebRequest -UseBasicParsing -Uri "$($config.WUServer)/SimpleAuthWebService/SimpleAuth.asmx")
        $temp = $config.WUServer -split ':'
        [PSCustomObject]@{
            URI        = $config.WUServer
            ServerName = ($temp[1] -replace '//')
            TcpPort    = $temp[2]
            Status     = $Status.StatusDescription
        }
    }

}

function Get-SCSServices{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $State
    )
    $ScriptBlockContent = {
        Param($State)
        if($State -eq 'All'){
            Get-CimInstance win32_service | Select-Object ProcessId,Name,DisplayName,Description,StartMode,State,Status,PathName,StartName
        }else{
            Get-CimInstance win32_service | Where-Object State -eq $State | Select-Object ProcessId,Name,DisplayName,Description,StartMode,State,Status,PathName,StartName
        }
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $State
    #Invoke-Command -ScriptBlock $ScriptBlockContent -ArgumentList $State

}

function Get-SCSProcesses{
    [CmdletBinding()]
    param(
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        Get-CimInstance win32_process | Select-Object ProcessId,Name,WorkingSetSize,VirtualSize,Path,CommandLine
    }

}

function Get-InstalledUpdates{
    [CmdletBinding()]
    param(
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        Get-HotFix | Select-Object HotFixID,InstalledOn,Description | Sort-Object InstalledOn -Descending
    }

}

function Get-FileProperties{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $File
    )

    $ScriptBlockContent = {
        Param($File)
        Get-Item -Path $File
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $File
}

function Get-SCSWindowsFeature{
    [CmdletBinding()]
    param(
        $RemoteSession
    )
    $ScriptBlockContent = {
        $WindowsFeature = Get-WindowsFeature | Where-Object {$_.Installed -match $True} | Select-Object DisplayName,Name,DependsOn 
        foreach($feature in $WindowsFeature){
            
            $DependsOn = $null
            foreach($item in $feature.DependsOn){
                $DependsOn = "$($item), $($DependsOn)"
            }
            if(!([String]::IsNullOrEmpty($DependsOn))){
                $DependsOn = $DependsOn.TrimEnd(', ')
            }

            [PSCustomObject]@{
                DisplayName = $feature.DisplayName
                Name        = $feature.Name
                DependsOn   = $DependsOn
            }

        }
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent
}

function Get-FileContent{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $File
    )

    $ScriptBlockContent = {
        Param($File)
        #Get-Content -Path $File -ReadCount 5000
        $i = 0
        [System.IO.File]::ReadLines($File) | ForEach-Object {
            
            if(!([String]::IsNullOrEmpty($_))){
                [PSCustomObject]@{
                    Line = $i
                    Text = $_
                }
            }
            $i ++
        }
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $File
}

function Get-MissingUpdates{
    [CmdletBinding()]
    param(
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $search_result = $searcher.Search("IsInstalled = 0")
        foreach ($update in $search_result.Updates) {
            $categories = @()
            foreach ($category in $update.Categories) {
                $categories += "$($category.Name) - $($category.CategoryID)"
            }
            $kbs = @()
            foreach ($kb in $update.KBArticleIDs) {
                $kbs += $kb
            }
            [PSCustomObject]@{
                Categories = $categories
                Description = $update.Description
                #Hidden = $update.IsHidden
                Id = $update.Identity.UpdateID
                KBs = $kbs
                Mandatory = $update.IsMandatory
                Present = $update.IsPresent
                Title = $update.Title
            }
        }
    }

}

function Get-WindowsUpdateClientLog{
    [CmdletBinding()]
    param(
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        Get-WinEvent -MaxEvents 200 -FilterHashtable @{
            Logname   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
            StartTime = (get-date).AddDays(-5)
            EndTime   = get-date
        } -ErrorAction SilentlyContinue | Select-Object TimeCreated,LogName,Id,LevelDisplayName,Message,MachineName
    }

}

function Get-SCSWindowsEventLog{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $EventlogName,
        $Level,
        $MaxEvents
    )
    $ScriptBlockContent = {
        Param($EventlogName,$Level,$MaxEvents)
        if($Level -eq 'All'){
            Get-WinEvent -MaxEvents $MaxEvents -FilterHashtable @{
                Logname   = $EventlogName
                #StartTime = (get-date).AddDays(-5)
                #EndTime   = get-date
            } -ErrorAction SilentlyContinue | Select-Object TimeCreated,LogName,ProviderName,Id,LevelDisplayName,Message,MachineName
        }else{
            Get-WinEvent -MaxEvents $MaxEvents -FilterHashtable @{
                Logname   = $EventlogName
                #StartTime = (get-date).AddDays(-5)
                #EndTime   = get-date
            } -ErrorAction SilentlyContinue | Where-Object LevelDisplayName -eq $Level | Select-Object TimeCreated,LogName,ProviderName,Id,LevelDisplayName,Message,MachineName
        }
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $EventlogName,$Level,$MaxEvents
    #Invoke-Command -ScriptBlock $ScriptBlockContent -ArgumentList $EventlogName,$Level,$MaxEvents
}

function Get-SCSRegistryItem{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $RegistryPath
    )

    $ScriptBlockContent = {
        Param($RegistryPath)
        $name, $value = $null
        Get-Item -Path $RegistryPath | ForEach-Object {
            foreach($item in $_.Property){
                if($($_.Name) -match 'HKEY_LOCAL_MACHINE'){$name  = $_.Name -replace 'HKEY_LOCAL_MACHINE','HKLM:'}
                if($($_.Name) -match 'HKEY_CURRENT_USER') {$name  = $_.Name -replace 'HKEY_CURRENT_USER','HKCU:'}
                $value = Get-ItemPropertyValue -Path $RegistryPath -Name $item
                [PSCustomObject]@{
                    Name     = $name
                    Property = $item
                    Value    = $value
                }
            }
        }
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $RegistryPath
}

function Get-SCSRegistryChildItem{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $RegistryPath
    )

    $ScriptBlockContent = {
        Param($RegistryPath)
        $name, $value = $null
        Get-ChildItem -Path $RegistryPath | ForEach-Object {
            foreach($item in $_.Property){
                if($($_.Name) -match 'HKEY_LOCAL_MACHINE'){$name  = $_.Name -replace 'HKEY_LOCAL_MACHINE','HKLM:'}
                if($($_.Name) -match 'HKEY_CURRENT_USER') {$name  = $_.Name -replace 'HKEY_CURRENT_USER','HKCU:'}
                $value = Get-ItemPropertyValue -Path $name -Name $item
                [PSCustomObject]@{
                    Name     = $name
                    Property = $item
                    Value    = $value
                }
            }
        }
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $RegistryPath
}

function Get-vRaResourceData{
    [CmdletBinding()]
    param(
        $Resource
    )
    foreach($_ in $Resource) { 
        if($_.Data.MachineName){
            [PSCustomObject]@{
                VMName           = $_.Data.MachineName
                Status           = $_.Status
                Owners           = $_.Owners
                Email            = $_.Data.'Scc.Ms.technicalContactEmail'
                #TenantId         = $_.TenantId
                DateCreated      = (Get-Date ($_.DateCreated))
                #LastUpdated      = (Get-Date ($_.LastUpdated))
                BlueprintName    = $_.Data.MachineBlueprintName
                OS               = $_.Data.MachineGuestOperatingSystem
                #Memory           = $_.Data.MachineMemory
                #CPU              = $_.Data.MachineCPU
                #TotalStorage     = $_.Data.MachineStorage
                ExposeToSpdn     = $_.Data.'Scc.Vm.Orch.ExposeToSpdn'
                #ResourceDomain   = $_.Data.'Scc.Ms.ResourceDomain'
                #PrimaryIPaddress = $_.data.__datacollected_ipaddress
                IPv4Address      = $_.data.NETWORK_LIST.data.NETWORK_ADDRESS
                #MACAddress       = $_.data.NETWORK_LIST.data.NETWORK_MAC_ADDRESS
                SPDNTranslatedIp = $_.Data.'Scc.Vm.Orch.spdnTranslatedIp'
                #PatchingWindow   = $_.Data.'Scc.Ms.PatchingWindow'
                ManagedState     = $_.Data.'Scc.Ms.State'
                #IsManaged        = $_.Data.'Scc.Ms.isManaged'
                #VMTemplate       = $_.Data.'Scc.Ms.Template'
                #UUID             = $_.Data.'Scc.Vm.Orch.UUID'
                ComputerName     = $_.Data.'SysPrep.UserData.ComputerName'
                LastPatched      = $_.Data.'Scc.Ms.LastPatched'
                #PatchingSuspend  = $_.Data.'Scc.Ms.suspendedPatching'
                #StorageCluster   = $_.Data.'VirtualMachine.Storage.Cluster.Name'
            }
        }
    }
}

function Invoke-SCSScriptBlock{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $RemoteCommand
    )
    $ScriptBlockContent = {
        Param($RemoteCommand)
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent
}

#endregion

#region Generall
$UDTitle = "Remote Operating - v0.0.16-beta"
$Pages   = @()
#endregion

#region content

#region "Home"
$Pages += New-UDPage -Name "Home" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
            #Send-RemoteOperatingMail -MailMessage "Page: Home -> Help needed."
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "There is no Help available"
            } -BottomSheet -Content {
                #New-UDHtml 'There is no Help available'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {
        New-UDHeading -Size 4 -Content { "The web framework for PowerShell remote operating" }
        New-UDHeading -Size 6 -Content{ "This is the web-based, interactive dashboard for remote operation tasks over WinRM. The following listet features are implemented:" }

        New-UDLayout -Columns 3 -Content {
            
            New-UDCard -Title 'Name Resolution Tester' -Content {
                New-UDParagraph -Text 'Test Forwardlookup to a host.'
            } -Links @(
                New-UDLink -Text 'Name Resolution Tester' -Url 'Name-Resolution-Tester'
            ) #-Size small

            New-UDCard -Title 'Connectivity Tester' -Content {
                New-UDParagraph -Text 'Test TCP connection to a remote host.'
            } -Links @(
                New-UDLink -Text 'Connectivity Tester' -Url 'Connectivity-Tester'
            ) #-Size small

            New-UDCard -Title 'Access Tester' -Content {
                New-UDParagraph -Text 'Test WinRM access to a remote host.'
            } -Links @(
                New-UDLink -Text 'Access Tester' -Url 'Access-Tester'
            ) #-Size small

            New-UDCard -Title 'Windows Updates' -Content {
                New-UDParagraph -Text 'List WSUS Server, installed Update, missing Updates, and WindowsUpdateClient Enventlog.'
            } -Links @(
                New-UDLink -Text 'Windows Updates' -Url 'Windows-Updates-Tester'
            ) #-Size small

            New-UDCard -Title 'Windows Eventlog' -Content {
                New-UDParagraph -Text 'List Eventlog entries from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows Eventlog' -Url 'Windows-Eventlog-Tester'
            ) #-Size small

            New-UDCard -Title 'Windows Registry' -Content {
                New-UDParagraph -Text 'List the Value of a Windows Registry path and name from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows Registry' -Url 'Windows-Registry-Tester'
            ) #-Size small

            New-UDCard -Title 'Windows Services' -Content {
                New-UDParagraph -Text 'List Windows Services from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows Services' -Url 'Windows-Service-Tester'
            ) #-Size small

            New-UDCard -Title 'Windows Processes' -Content {
                New-UDParagraph -Text 'List Windows Processes from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows Processes' -Url 'Windows-Process-Tester'
            ) #-Size small

            New-UDCard -Title 'Windows Features' -Content {
                New-UDParagraph -Text 'List installed Windows Features from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows Features' -Url 'Windows-Feature-Tester'
            ) #-Size small
 
            New-UDCard -Title 'Windows File Reader' -Content {
                New-UDParagraph -Text 'List file content from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows File Reader' -Url 'Windows-File-Reader'
            ) #-Size small

            New-UDCard -Title 'SCCM Agent Tester' -Content {
                New-UDParagraph -Text 'List SCCM Agent properties from a remote host.'
            } -Links @(
                New-UDLink -Text 'SCCM Agent Tester' -Url 'SCCM-Agent-Tester'
            ) #-Size small

            New-UDCard -Title 'SCCM Patching Tester' -Content {
                New-UDParagraph -Text 'List SCCM Patching properties from a remote host.'
            } -Links @(
                New-UDLink -Text 'SCCM Patching Tester' -Url 'SCCM-Patching-Tester'
            ) #-Size small

            if(Get-Module PowerVRA -ListAvailable){
                New-UDCard -Title 'vRAResource Tester' -Content {
                    New-UDParagraph -Text 'List resources of a Virtual Machine from vRA.'
                } -Links @(
                    New-UDLink -Text 'Ask for vRAResources' -Url 'vRAResource-Tester'
                ) #-Size small
            }
       }
    }
}
#endregion

#region "Getting Started"
$Pages += New-UDPage -Name "Getting Started" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "There is no Help available"
            } -BottomSheet -Content {
                #New-UDHtml 'There is no Help available'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Getting Started" }
        New-UDHtml "This Dashboard is written in PowerShell by Martin Walther, Swisscom (Schweiz) AG to simplify operating taks."

        New-UDHeading -Size 5 -Content { "Requirements" }

        New-UDHeading -Size 6 -Content { "PowerShell Universal Dashboard" }
        New-UDHtml "Universal Dashboard is a cross-platform PowerShell module for developing and hosting web-based, interactive dashboards, websites and REST APIs with an ASP.NET web service."
        New-UDHtml 'Universal Dashboard requires .NET Framework version 4.7.2, <a href="https://dotnet.microsoft.com/download/dotnet-framework/net472">download .NET Framework 4.7.2</a>'
        
        New-UDLayout -Columns 1 -Content {           
            New-UDCard -Text "Install-Module UniversalDashboard.Community -AcceptLicense -Force" -Links @(
                New-UDLink -Url https://ironmansoftware.com/powershell-universal-dashboard/ -Text "Universal Dashboard"
            )
        }

        New-UDHeading -Size 6 -Content { "PowerShell PSNetTools" }
        "PsNetTools is a cross platform PowerShell module to test network features on Windows, Mac and Linux."
        New-UDLayout -Columns 1 -Content {           
            New-UDCard -Text "Download and install PsNetTools from github.com"-Links @(
                New-UDLink -Url https://github.com/tinuwalther/PsNetTools/releases/download/v0.7.5/PsNetTools.zip -Text "Download PsNetTools"
            )
        }

        New-UDHeading -Size 6 -Content { "PowerShell PowervRA" }
        "PowervRA is a PowerShell module built on top of the services exposed by the vRealize Automation 7 REST API."
        New-UDLayout -Columns 1 -Content {           
            New-UDCard -Text "Install-Module PowervRA" -Links @(
                New-UDLink -Url https://powervra.readthedocs.io/en/latest/ -Text "PowervRA"
            )
        }

    }
}
#endregion

#region "Name Resolution Tester"
$Pages += New-UDPage -Name "Name Resolution Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Fully Qualified Name or IP Address of the remote host to test the name resolution, and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Name Resolution Tester" }
        New-UDHeading -Size 6 -Content { "Test the Forwardlookup to a remote host" }
        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Remotehost
                )
                Show-UDToast -Message "Send Tests to $Remotehost" -Balloon
                try{
                    $TestReturn = Test-PsNetDig -Destination $Remotehost
                    $CardOutput = "Test-PsNetDig -Destination $Remotehost"
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Details" -Endpoint {
                        $TestReturn | Out-UDGridData
                    }
                )

            }
        }
    }
}
#endregion

#region "Connectivity Tester"
$Pages += New-UDPage -Name "Connectivity Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Fully Qualified Name or IP Address of the remote host, the TCP port to test and press Submit'
                New-UDHtml 'TCP port examples: SSH = 22, SMTP = 25, HTTP = 80, HTTPS = 443, LDAP = 389, LDAPS = 636, RDP = 3389, WinRM-HTTP = 5985, WinRM-HTTPS = 5986'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Connectivity Tester" }
        New-UDHeading -Size 6 -Content { "Test TCP connection to a remote Host. On the remote Host, must be an Listener on the given TCP port otherwise the test fails." }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Name or IP Address'
                New-UDInputField -Type textbox  -Name Remoteport -Placeholder 'Remote TCPPort'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Remotehost, 

                    [Parameter(Mandatory)]
                    [UniversalDashboard.ValidationErrorMessage("The port-no you entered is invalid. Please enter a valid port between 0 and 65535.")]
                    [ValidateRange(0,65535)]
                    [Int32]$Remoteport
                )
                Show-UDToast -Message "Send Tests to $Remotehost" -Balloon
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort $Remoteport
                    $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort $Remoteport"    
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Details" -Endpoint {
                        $TestReturn | Out-UDGridData
                    }
                )
            }
        }
    }
}
#endregion

#region "Access Tester"
$Pages += New-UDPage -Name "Access Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Access Tester" }
        New-UDHeading -Size 6 -Content { "Test WinRM access to a remote host. You need a user account who is member of the local Administrators of the remote Host." }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'Username'
                New-UDInputField -Type password -Name Password   -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
                            $TestReturn = [PSCustomObject]@{
                                Input           = $Remotehost
                                'Session Id'    = $($rsession.Id)
                                'Session Name'  = $($rsession.Name)
                                'Computer Name' = $($RemoteReturn.ToString())
                                State           = $($rsession.State)
                                Availability    = $($rsession.Availability)
                            }
                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Details" -Endpoint {
                        $TestReturn | Out-UDGridData
                    }
                )
            }
        }
    }
}
#endregion

#region "Windows Update Tester"
$Pages += New-UDPage -Name "Windows Updates Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Updates Tester" }
        New-UDHeading -Size 6 -Content { "List configured WSUS Server, the last 5 installed Windows Update, missing Updates, and last 5 days of WindowsUpdateClient Enventlog from a remote Host." }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'Username'
                New-UDInputField -Type password -Name Password   -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            Show-UDToast -Message "Collect data from registry"
                            $WSUServerConfiguration  = Get-WsusServer -RemoteSession $rsession
                            Show-UDToast -Message "Collect installed Windows Update"
                            $InstalledWindowsUpdates = Get-InstalledUpdates -RemoteSession $rsession
                            Show-UDToast -Message "Collect missing Windows Update"
                            $MissingWindowsUpdates   = Get-MissingUpdates -RemoteSession $rsession
                            Show-UDToast -Message "Collect data from Windows Update Clientlog"
                            $WindowsUpdateClientLog  = Get-WindowsUpdateClientLog -RemoteSession $rsession
                            $CardOutput = "Input: $($Remotehost) -> ComputerName: $(Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME})"

                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(

                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Windows Server Update Service" -Endpoint {
                        $WSUServerConfiguration | Select-Object URI,ServerName,TcpPort,Status | Out-UDGridData
                    } -NoFilter

                    New-UDGrid -Title "Installed Windows Update" -Endpoint {
                        $InstalledWindowsUpdates | Select-Object InstalledOn,HotFixID,Description | Out-UDGridData
                    } -Links @(New-UDLink -Url https://www.catalog.update.microsoft.com/Home.aspx -Text "Microsoft Update Catalog")

                    New-UDGrid -Title "Missing Windows Update" -Endpoint {
                        $MissingWindowsUpdates | Select-Object Id,KBs,Categories,Title,Description,Mandatory,Present | Out-UDGridData
                    }

                    New-UDGrid -Title "Windows Update Enventlog" -Endpoint {
                        $WindowsUpdateClientLog | Select-Object TimeCreated,Id,LevelDisplayName,Message,MachineName,LogName | Out-UDGridData
                    }

                )
            }
        }
    }
}
#endregion

#region "Windows Eventlog Tester"
$Pages += New-UDPage -Name "Windows Eventlog Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, enter an Eventlog (e.g. Application, System, Security), choose a Level (e.g. Information, Warning, Error), choose MaxEvents and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Eventlog Tester" }
        New-UDHeading -Size 6 -Content { "List Windows Eventlog from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'Username'
                New-UDInputField -Type password -Name Password   -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Name or IP Address'
                New-UDInputField -Type textbox  -Name Eventlog   -Placeholder 'Eventlog'
                New-UDInputField -Type select   -Name Level      -Values @('All','Information','Warning','Error','Critical')
                New-UDInputField -Type select   -Name MaxEvents  -Values @('50','500','5000','50000')
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost,

                    [Parameter(Mandatory)]
                    $Eventlog,

                    [Parameter(Mandatory)]
                    $Level,

                    [Parameter(Mandatory)]
                    $MaxEvents
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput   = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn) -> Eventlog: $($Eventlog) -> Level: $($Level) -> MaxEvents: $($MaxEvents)"
                            Show-UDToast -Message "Collect data"
                            $TestReturn   = Get-SCSWindowsEventLog -RemoteSession $rsession -EventlogName $Eventlog -Level $Level -MaxEvents $MaxEvents
                        }else{
                            $TestReturn = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title $Eventlog -Endpoint {
                        $TestReturn | Select-Object TimeCreated,Id,LevelDisplayName,Message,ProviderName | Out-UDGridData
                    }
                )
            }
        }
    }
}
#endregion

#region "Registry Tester"
$Pages += New-UDPage -Name "Windows Registry Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, enter a Registry path (e.g. HKLM:\Software\Microsoft), and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Registry Tester" }
        New-UDHeading -Size 6 -Content { "List Windows Registry properties from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Name or IP Address'
                New-UDInputField -Type textbox  -Name RegistryPath -Placeholder 'Registry Path'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost,

                    [Parameter(Mandatory)]
                    $RegistryPath
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn      = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput        = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn) -> $($RegistryPath)"
                            Show-UDToast -Message "Collect data"
                            $RegistryItem      = Get-SCSRegistryItem -RemoteSession $rsession -RegistryPath $RegistryPath
                            $RegistryChildItem = Get-SCSRegistryChildItem -RemoteSession $rsession -RegistryPath $RegistryPath
                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(

                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Items" -Endpoint {
                        $RegistryItem | Select-Object Name,Property,Value | Out-UDGridData
                    }

                    New-UDGrid -Title "ChildItems" -Endpoint {
                        $RegistryChildItem | Select-Object Name,Property,Value | Out-UDGridData
                    }

                )
            }
        }
    }
}
#endregion

#region "File Reader"
$Pages += New-UDPage -Name "Windows File Reader" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, enter a path of a file to read from, and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows File Reader" }
        New-UDHeading -Size 6 -Content { "Read the content of a file from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Name or IP Address'
                New-UDInputField -Type textbox  -Name FilePath     -Placeholder 'File Path'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost,

                    [Parameter(Mandatory)]
                    $FilePath
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn) -> $($FilePath)"
                            Show-UDToast -Message "Collect data"
                            $FileProperties = Get-FileProperties -RemoteSession $rsession -File $FilePath
                            $FileContent    = Get-FileContent    -RemoteSession $rsession -File $FilePath
                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(

                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "File properties" -Endpoint {
                        $FileProperties | Select-Object Name,FullName,LastWriteTime | Out-UDGridData
                    }

                    New-UDGrid -Title "File content" -Endpoint {
                        $FileContent | Select-Object Line,Text | Out-UDGridData
                    }

                    #New-UDCollapsible -Id "FileContent" -Items {
                        #New-UDCollapsibleItem -Title "File content" -Icon file -Content {
                            #New-UDCard -Text $FileContent
                        #}
                    #}

                )
            }
        }
    }
}
#endregion

#region "Windows Service Tester"
$Pages += New-UDPage -Name "Windows Service Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, choose a Service state (Running, Stopped),  and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Service Tester" }
        New-UDHeading -Size 6 -Content { "List Windows Services from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Name or IP Address'
                New-UDInputField -Type select   -Name State        -Values @('All','Running','Stopped')
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost,

                    [Parameter(Mandatory)]
                    $State
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
                            Show-UDToast -Message "Collect data"
                            $TestResult     = Get-SCSServices -RemoteSession $rsession -State $State
                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Windows Services" -Endpoint {
                        $TestResult | Select-Object ProcessId,Name,DisplayName,Description,StartMode,State,Status,PathName,StartName | Out-UDGridData
                    }
                )
            }
        }
    }
}
#endregion

#region "Windows Process Tester"
$Pages += New-UDPage -Name "Windows Process Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Process Tester" }
        New-UDHeading -Size 6 -Content { "List Windows Processes from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
                            Show-UDToast -Message "Collect data"
                            $TestResult     = Get-SCSProcesses -RemoteSession $rsession
                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Windows Processes" -Endpoint {
                        $TestResult | Select-Object ProcessId,Name,WorkingSetSize,VirtualSize,Path,CommandLine | Out-UDGridData
                    }
                )
            }
        }
    }
}
#endregion

#region "Windows Feature Tester"
$Pages += New-UDPage -Name "Windows Feature Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Feature Tester" }
        New-UDHeading -Size 6 -Content { "List installed Windows Feature from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
                            $TestResult     = Get-SCSWindowsFeature -RemoteSession $rsession
                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Windows Features" -Endpoint {
                        $TestResult | Select-Object DisplayName,Name,DependsOn | Out-UDGridData
                    }
                )
            }
        }
    }
}
#endregion

#region "SCCM Patching Tester"
$Pages += New-UDPage -Name "SCCM Patching Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, and press Submit'
                New-UDHtml "The vRO-Trigger 'HKLM:\Software\Swisscom\SCCM' -Property 'LastPatchRun' should be deleted after patching and the SCCM-Trigger 'HKLM:\Software\Swisscom\WindowsUpdate' -Property 'LastPatchRun' must exists after patching."
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "SCCM Patching Tester" }
        New-UDHeading -Size 6 -Content { "List SCCM Patching properties from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
                            
                            Show-UDToast -Message "Collect data from registry"
                            $vRO  = Get-SCSRegistryItem -RemoteSession $rsession -RegistryPath 'HKLM:\Software\Swisscom\SCCM'
                            if([String]::IsNullOrEmpty($vRO.Value)){
                                $vRObgcolor = 'lightgreen'
                            }else{
                                $vRObgcolor = 'indianred'
                            }

                            $SCCM = Get-SCSRegistryItem -RemoteSession $rsession -RegistryPath 'HKLM:\Software\Swisscom\WindowsUpdate'
                            if([String]::IsNullOrEmpty($SCCM.Value)){
                                $SCCMbgcolor = 'indianred'
                            }else{
                                $SCCMbgcolor = 'lightgreen'
                            }

                            $WSUServerConfiguration  = Get-WsusServer -RemoteSession $rsession
                            if($WSUServerConfiguration.Status -match 'OK'){
                                $Wsusbgcolor = 'lightgreen'
                            }else{
                                $Wsusbgcolor = 'indianred'
                            }

                            Show-UDToast -Message "Collect BITS Service properties"
                            $BitsService  = Get-SccmService -RemoteSession $rsession -ServiceName "BITS"
                            if($BitsService.StartMode -match 'disabled'){
                                $Bitsbgcolor = 'indianred'
                            }else{
                                $Bitsbgcolor = 'lightgreen'
                            }

                            Show-UDToast -Message "Collect installed Windows Updates"
                            $InstalledWindowsUpdates = Get-InstalledUpdates -RemoteSession $rsession
                            Show-UDToast -Message "Collect data from WUAHandlerLog"
                            $wulog = Get-FileProperties  -RemoteSession $rsession -File "C:\Windows\CCM\Logs\WUAHandler.log"
                            $WUAHandler = [PSCustomObject]@{
                                LastWriteTime = $wulog.LastWriteTime
                                Name          = $wulog.Name
                                FullName      = $wulog.FullName
                            }
                            $MissingWindowsUpdates   = Get-SccmWUAHandlerLog -RemoteSession $rsession
                            #Show-UDToast -Message "Collect data from Windows Update Clientlog"
                            #$WindowsUpdateClientLog  = Get-WindowsUpdateClientLog -RemoteSession $rsession

                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(

                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "vRO Workflow" -Endpoint {
                        $vRO | Select-Object Name,Property,Value | Out-UDGridData
                    } -NoFilter -NoExport -BackgroundColor $vRObgcolor
                    New-UDGrid -Title "SCCM Workflow" -Endpoint {
                        $SCCM | Select-Object Name,Property,Value | Out-UDGridData
                    } -NoFilter -NoExport -BackgroundColor $SCCMbgcolor

                    New-UDGrid -Title "Windows Server Update Service" -Endpoint {
                        $WSUServerConfiguration | Select-Object URI,ServerName,TcpPort,Status | Out-UDGridData
                    } -NoFilter -NoExport -BackgroundColor $Wsusbgcolor
                    New-UDGrid -Title "BITS Service" -Endpoint {
                        $BitsService | Select-Object ProcessId,Name,DisplayName,Description,StartMode,State,Status,PathName,StartName | Out-UDGridData
                    } -NoFilter -NoExport -BackgroundColor $Bitsbgcolor

                    New-UDGrid -Title "Installed Windows Update" -Endpoint {
                        $InstalledWindowsUpdates | Select-Object InstalledOn,HotFixID,Description | Out-UDGridData
                    }

                    New-UDGrid -Title "Windows Update Handlerlog" -Endpoint {
                        $WUAHandler | Out-UDGridData
                    } -NoFilter -NoExport

                    New-UDGrid -Title "Content from Windows Update Handlerlog" -Endpoint {
                        $MissingWindowsUpdates | Select-Object DateTime,Message | Out-UDGridData
                    } -DefaultSortColumn DateTime -DefaultSortDescending $true
                    <#      
                    New-UDGrid -Title "Windows Update Client Enventlog" -Endpoint {
                        $WindowsUpdateClientLog | Select-Object TimeCreated,Id,LevelDisplayName,Message | Out-UDGridData
                    }
                    #>
                )
            }
        }
    }
}
#endregion

#region "SCCM Agent Tester"
$Pages += New-UDPage -Name "SCCM Agent Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the remote host-login, enter the Fully Qualified Name or IP Address of the remote host, and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "SCCM Agent Tester" }
        New-UDHeading -Size 6 -Content { "List SCCM Agent properties from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
                            Show-UDToast -Message "Search for installed SCCM Agent Software"
                            $SccmAgent      = Get-SccmAgent -RemoteSession $rsession -SoftwareName "Configuration Manager Client"
                            Show-UDToast -Message "Collect SCCM Service properties"
                            $SccmService    = Get-SccmService -RemoteSession $rsession -ServiceName "CcmExec"
                        }else{
                            $CardOutput = "Session to $Remotehost is $($rsession.State)"
                        }
                        Remove-PSSession -Session $rsession
                    }else{
                        $CardOutput = "Test-PsNetTping -Destination $Remotehost -TcpPort 5985"
                    }
                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(

                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "SCCM Agent" -Endpoint {
                        $SccmAgent | Select-Object Name,Version,Publisher,InstallDate | Out-UDGridData
                    } -NoFilter
                    New-UDGrid -Title "SCCM Service" -Endpoint {
                        #$SccmService | Select-Object Name,Status,StartType | Out-UDGridData
                        $SccmService | Select-Object ProcessId,Name,DisplayName,Description,StartMode,State,Status,PathName,StartName | Out-UDGridData
                    } -NoFilter

                )
            }
        }
    }
}
#endregion

#region "vRAResource Tester"
$Pages += New-UDPage -Name "vRAResource Tester" -Title "$($UDTitle)" -Content { 

    New-UdFab -Icon "plus" -Size "large" -ButtonColor "lightgreen" -IconColor 'white' -Content {
        New-UDFabButton -Icon "comment" -Size "large" -ButtonColor "lightblue" -IconColor 'white' -onClick {
            Show-UDToast "$($UDTitle): Ha, this is only a fake-function!" -Duration 5000
        }
        New-UDFabButton -Icon "question" -ButtonColor 'lightblue' -IconColor 'white' -onClick {
            Show-UDModal -Header {
                New-UDHeading -Size 6 -Text "Remote Information"
            } -BottomSheet -Content {
                New-UDHtml 'Enter the Username and Password for the Tenant-login, choose an Environment (e.g. DEV, INT, CAT, or PRD), enter a Tenant name (e.g. fornax-005), enter a VMName or leave All, choose an OS (e.g. All, Windows, Linux), and press Submit'
            }
        }
    }
    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "vRAResource Tester" }
        New-UDHeading -Size 6 -Content { "List all Windows Virtual Machines for a Tenant (e.g. fornax-005)." }
        
        Import-Module -Name CredentailManager
        $defaultuser     = $env:USERNAME
        if(Get-Module CredentialManager -ErrorAction SilentlyContinue){
        $Credentials = Get-StoredCredential -Target 'RemoteOps'
            if(![String]::IsNullOrEmpty($Credentials)){
                New-UDCard -Title "Cached credentials" -Text "You can execute this function with cached login data for $($Credentials.Username) without entering user name and password."
                $defaultuser     = $Credentials.Username
            }
        }

        New-UDLayout -Columns 1 -Content {

            New-UDInput -Title "vRA Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'Username' -DefaultValue $defaultuser
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type select   -Name Environment  -Values @( 'PRD','CAT','INT','DEV')
                New-UDInputField -Type textbox  -Name Tenant       -Placeholder 'Tenant'
                New-UDInputField -Type textbox  -Name VMName       -Placeholder 'VMName' -DefaultValue 'All'
                New-UDInputField -Type select   -Name OS           -Values @('All','Windows','Linux')
            } -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Environment,

                    [Parameter(Mandatory)]
                    $Tenant,

                    [Parameter(Mandatory)]
                    $VMName,

                    [Parameter(Mandatory)]
                    $OS
                )
                try{
                    if(Get-Module CredentialManager -ErrorAction SilentlyContinue){
                        $Credentials = Get-StoredCredential -Target 'RemoteOps'
                        if([String]::IsNullOrEmpty($Credentials)){
                            $secpasswd   = ConvertTo-SecureString $Password -AsPlainText -Force
                            $Credentials = New-StoredCredential -Target 'RemoteOps' -UserName $Username -Password $secpasswd
                        }
                    }
                    switch($Environment){
                        'DEV' {$vRAServer = 'cmp.dev-02.entcloud.swisscom.com'}
                        'INT' {$vRAServer = 'cmp.int-02.entcloud.swisscom.com'}
                        'CAT' {$vRAServer = 'cmp.cat.entcloud.swisscom.com'}
                        'PRD' {$vRAServer = 'cmp.entcloud.swisscom.com'}
                    }
                    Show-UDToast -Message "Connect-vRAServer -Server $($vRAServer) -Tenant $($Tenant) -Username $($Username)"
                    $connection  = Connect-vRAServer -Server $vRAServer -Tenant $Tenant -Username $Credentials.Username -Password $Credentials.Password -SslProtocol Tls12 -IgnoreCertRequirements
                    if($connection){
                        if($VMName -eq 'All'){
                            $CardOutput = "Environment -> ($Environment), vRAServer -> $($vRAServer), Tenant -> $($Tenant), -> OS $($OS), -> Username $($Username)"
                            switch($OS){
                                'All'     {$vRAMachineResource = Get-vRAResource -Type Machine}
                                'Windows' {$vRAMachineResource = Get-vRAResource -Type Machine | Where-Object {$_.Data.MachineGuestOperatingSystem -match 'Windows'}}
                                'Linux'   {$vRAMachineResource = Get-vRAResource -Type Machine | Where-Object {$_.Data.MachineGuestOperatingSystem -match 'Linux'}}
                            }
                        }else{
                            $CardOutput = "Environment -> ($Environment), vRAServer -> $($vRAServer), Tenant -> $($Tenant), VMName -> $($VMName) -> OS $($OS), -> Username $($Username)"
                            $vRAMachineResource = Get-vRAResource -Name $VMName
                        }
                        Show-UDToast -Message "Collect data from resources"
                        if($vRAMachineResource){
                            $TestResult = Get-vRaResourceData -Resource $vRAMachineResource
                        }
                        else{
                            $CardOutput = "No resources found in $($vRAServer) for Tenant $($Tenant) as User $($Username)."
                        }
                    }
                    else{
                        $CardOutput = "Could not connect to vRAServer $($vRAServer), Tenant $($Tenant) as User $($Username)."
                    }
                    Disconnect-vRAServer -Confirm:$false            
                }
                catch{
                    $CardOutput = "Environment -> ($Environment), vRAServer -> $($vRAServer), Tenant -> $($Tenant), -> Username $($Username): $($_.Exception.Message)"
                    $Error.Clear()
                }
                New-UDInputAction -Content @(
                    New-UDCard -Text "Filter: $($CardOutput)"
                    New-UDGrid -Title "Found $($TestResult.count) Virtual Machines" -Endpoint {
                        $TestResult | Select-Object Status,VMName,ComputerName,DateCreated,Owners,OS,BlueprintName,ManagedState,LastPatched,IPv4Address,SPDNTranslatedIp,ExposeToSpdn,Email | Out-UDGridData
                    } -DefaultSortColumn DateCreated -DefaultSortDescending $true
                )
            }
        }
    }
}
#endregion

#endregion

#region Dashboard
$Navigation = New-UDSideNav -Content {
    
    New-UDSideNavItem -Text "Home" -PageName "Home"                     -Icon home 
    New-UDSideNavItem -Text "About" -Children {
        New-UDSideNavItem -Text "Getting Started" -PageName "Getting Started" -Icon list
    } -Icon info

    New-UDSideNavItem -Text "Network" -Children {
        New-UDSideNavItem -Text "Name Resolution Tester" -PageName "Name Resolution Tester"   -Icon rocket 
        New-UDSideNavItem -Text "Connectivity Tester"    -PageName "Connectivity Tester"      -Icon rocket 
    } -Icon rocket
    
    New-UDSideNavItem -Text "Workload" -Children {
        New-UDSideNavItem -Text "Access Tester"          -PageName "Access Tester"            -Icon windows
        New-UDSideNavItem -Text "Windows Updates"        -PageName "Windows Updates Tester"   -Icon windows
        New-UDSideNavItem -Text "Windows Eventlog"       -PageName "Windows Eventlog Tester"  -Icon windows
        New-UDSideNavItem -Text "Windows Registry"       -PageName "Windows Registry Tester"  -Icon windows
        New-UDSideNavItem -Text "Windows Services"       -PageName "Windows Service Tester"   -Icon windows
        New-UDSideNavItem -Text "Windows Processes"      -PageName "Windows Process Tester"   -Icon windows
        New-UDSideNavItem -Text "Windows Features"       -PageName "Windows Feature Tester"   -Icon windows
        New-UDSideNavItem -Text "Windows File Reader"    -PageName "Windows File Reader"      -Icon windows
        New-UDSideNavItem -Text "SCCM Agent Tester"      -PageName "SCCM Agent Tester"        -Icon windows
        New-UDSideNavItem -Text "SCCM Patching Tester"   -PageName "SCCM Patching Tester"     -Icon windows
    } -Icon server

    if(Get-Module PowerVRA -ListAvailable){
        New-UDSideNavItem -Text "vRealize Automation" -Children {
            New-UDSideNavItem -Text "Ask for vRAResources" -PageName "vRAResource Tester" -Icon rocket
        } -Icon cloud
    }

} #-Fixed

#endregion

#region Start
$Footer = New-UDFooter -Links @(
    New-UDLink -Text ", from Ironman Software" -Url "https://ironmansoftware.com"
)
$Dashboard = New-UDDashboard -Pages $Pages -Navigation $Navigation -Footer $Footer

if([String]::IsNullOrEmpty((Get-UDDashboard -Name "OpsRemoteWinRM"))){
    Start-UDDashboard -Name "OpsRemoteWinRM" -Endpoint $Endpoint -Dashboard $Dashboard -Port 20001 -AutoReload
}
Start-Process "http://localhost:20001/Home"

<#
Get-UDDashboard -Name "OpsRemoteWinRM" | Stop-UDDashboard
#>

#endregion