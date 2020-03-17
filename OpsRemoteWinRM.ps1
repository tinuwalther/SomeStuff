<#

    https://ironmansoftware.com/universal-dashboard-2-6-beautification-ws-fed-and-bounty-hunters/
    Universal Dashboard requires .NET Framework version 4.7.2

    localhost:20001

#>
if(!(Get-Module UniversalDashboard.Community)){
    Import-Module UniversalDashboard.Community
}
if(!(Get-Module PsNetTools)){
    Import-Module PsNetTools
}

$UDTitle = "Remote Operating"

Get-UDDashboard -Name "OpsRemoteWinRM" | Stop-UDDashboard

#region functions
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
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        Get-CimInstance win32_service | Select-Object ProcessId,Name,DisplayName,Description,StartMode,State,Status,PathName,StartName
    }

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
        $EventlogName
    )

    $ScriptBlockContent = {
        Param($EventlogName)
        Get-WinEvent -MaxEvents 200 -FilterHashtable @{
            Logname   = $EventlogName
            StartTime = (get-date).AddDays(-5)
            EndTime   = get-date
        } -ErrorAction SilentlyContinue | Select-Object TimeCreated,LogName,ProviderName,Id,LevelDisplayName,Message,MachineName
    }
    Invoke-Command -Session $RemoteSession -ScriptBlock $ScriptBlockContent -ArgumentList $EventlogName
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

#region "Home"
$Page1 = New-UDPage -Name "Home" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "The web framework for PowerShell remote operating" }

        New-UDHeading -Size 6 -Content{ "This is the web-based, interactive dashboard for remote operation tasks over WinRM. The following listet features are implemented:" }

        New-UDLayout -Columns 3 -Content {
            
            New-UDCard -Title 'Name Resolution Tester' -Content {
                New-UDParagraph -Text 'Test TCP connection to a remote Host. On the remote Host, must be an Listener on the given TCP port otherwise the test fails.'
            } -Links @(
                New-UDLink -Text 'Name Resolution Tester' -Url 'Name-Resolution-Tester'
            ) -Size small

            New-UDCard -Title 'Connectivity Tester' -Content {
                New-UDParagraph -Text 'Test TCP connection to a remote Host. On the remote Host, must be an Listener on the given TCP port otherwise the test fails.'
            } -Links @(
                New-UDLink -Text 'Connectivity Tester' -Url 'Connectivity-Tester'
            ) -Size small

            New-UDCard -Title 'Access Tester' -Content {
                New-UDParagraph -Text 'Test WinRM access to a remote host. You need a user account who is member of the local Administrators of the remote Host.'
            } -Links @(
                New-UDLink -Text 'Access Tester' -Url 'Access-Tester'
            ) -Size small

            New-UDCard -Title 'Windows Updates' -Content {
                New-UDParagraph -Text 'List configured WSUS Server, the last 5 installed Windows Update, MissingUpdates, and last 5 days of WindowsUpdateClient Enventlog.'
            } -Links @(
                New-UDLink -Text 'Windows Updates' -Url 'Windows-Updates-Tester'
            ) -Size small

            New-UDCard -Title 'Windows Eventlog' -Content {
                New-UDParagraph -Text 'List the last 100 Eventlog entries from the last 5 days of a Windows Eventlog.'
            } -Links @(
                New-UDLink -Text 'Windows Eventlog' -Url 'Windows-Eventlog-Tester'
            ) -Size small

            New-UDCard -Title 'Windows Registry' -Content {
                New-UDParagraph -Text 'List the Value of a Windows Registry path and name.'
            } -Links @(
                New-UDLink -Text 'Windows Registry' -Url 'Windows-Registry-Tester'
            ) -Size small

            New-UDCard -Title 'Windows File Reader' -Content {
                New-UDParagraph -Text 'List file properties and the file content from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows File Reader' -Url 'Windows-File-Reader'
            ) -Size small

            New-UDCard -Title 'Windows Services' -Content {
                New-UDParagraph -Text 'List Windows Services from a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows Services' -Url 'Windows-Service-Tester'
            ) -Size small

            New-UDCard -Title 'Windows Processes' -Content {
                New-UDParagraph -Text 'List Windows Processes from a remote host.'
            } -Links @(
                #New-UDLink -Text 'Windows Services' -Url 'Windows-Service-Tester'
            ) -Size small

        }
        
        New-UDHeading -Size 6 -Content{ "PowerShell Modules: UniversalDashboard.Community, PsNetTools, Universal Dashboard requires .NET Framework version 4.7.2" }

    }

}
#endregion

#region "Name Resolution Tester"
$Page7 = New-UDPage -Name "Name Resolution Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Name Resolution Tester" }

        New-UDHeading -Size 6 -Content { "Test the Forwardlookup to a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Remote Name or IP Address'
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

                    New-UDCard -Text $CardOutput

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
$Page2 = New-UDPage -Name "Connectivity Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Connectivity Tester" }

        New-UDHeading -Size 6 -Content { "Test TCP connection to a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Remote Name or IP Address'
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

                    New-UDCard -Text $CardOutput

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
$Page6 = New-UDPage -Name "Access Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Access Tester" }

        New-UDHeading -Size 6 -Content { "Test WinRM accessto a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password   -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Remote Name or IP Address'
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
                # Output a new card based on that info

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

                    New-UDCard -Text $CardOutput

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
$Page3 = New-UDPage -Name "Windows Updates Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Updates Tester" }

        New-UDHeading -Size 6 -Content { "List Windows Updates from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password   -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Remote Name or IP Address'
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
                # Output a new card based on that info

                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $WSUServerConfiguration  = Get-WsusServer -RemoteSession $rsession
                            $InstalledWindowsUpdates = Get-InstalledUpdates -RemoteSession $rsession
                            $MissingWindowsUpdates   = Get-MissingUpdates -RemoteSession $rsession
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
                    $LinkText   = "Error in Test"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(

                    New-UDCard -Text $CardOutput #'https://www.catalog.update.microsoft.com/Home.aspx'

                    New-UDGrid -Title "Windows Server Update Service" -Endpoint {
                        $WSUServerConfiguration | Select-Object URI,ServerName,TcpPort,Status | Out-UDGridData
                    } -NoFilter

                    New-UDGrid -Title "Installed Windows Update" -Endpoint {
                        $InstalledWindowsUpdates | Select-Object InstalledOn,HotFixID,Description | Out-UDGridData
                    }

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
$Page4 = New-UDPage -Name "Windows Eventlog Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Eventlog Tester" }

        New-UDHeading -Size 6 -Content { "List Windows Eventlog from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password   -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Remote Name or IP Address'
                New-UDInputField -Type textbox  -Name Eventlog   -Placeholder 'Eventlog'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost,

                    [Parameter(Mandatory)]
                    $Eventlog
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                # Output a new card based on that info

                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput   = "New-PSSession -ComputerName $RemoteHost"
                            $RemoteReturn = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput   = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn) -> Eventlog: $($Eventlog)"
                            $TestReturn   = Get-SCSWindowsEventLog -RemoteSession $rsession -EventlogName $Eventlog
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

                    New-UDCard -Text $CardOutput

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
$Page5 = New-UDPage -Name "Windows Registry Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Registry Tester" }

        New-UDHeading -Size 6 -Content { "List Windows Registry properties from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Remote Name or IP Address'
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
                # Output a new card based on that info

                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn      = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput        = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn) -> $($RegistryPath)"
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

                    New-UDCard -Text $CardOutput

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
$Page8 = New-UDPage -Name "Windows File Reader" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows File Reader" }

        New-UDHeading -Size 6 -Content { "Read the content of a file from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Remote Name or IP Address'
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
                # Output a new card based on that info

                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn) -> $($FilePath)"
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

                    New-UDCard -Text $CardOutput

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
$Page9 = New-UDPage -Name "Windows Service Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Service Tester" }

        New-UDHeading -Size 6 -Content { "List Windows Services from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Remote Name or IP Address'
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
                # Output a new card based on that info

                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
                            $TestResult     = Get-SCSServices -RemoteSession $rsession
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

                    New-UDCard -Text $CardOutput

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
$Page10 = New-UDPage -Name "Windows Process Tester" -Title "$($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Windows Process Tester" }

        New-UDHeading -Size 6 -Content { "List Windows Processes from a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Remote Name or IP Address'
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
                # Output a new card based on that info

                try{
                    $TestReturn = Test-PsNetTping -Destination $Remotehost -TcpPort 5985
                    if($TestReturn.TcpSucceeded){
                        $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                        $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                        $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                        if($rsession.State -eq 'Opened'){
                            $RemoteReturn   = Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME}
                            $CardOutput     = "Input: $($Remotehost) -> ComputerName: $($RemoteReturn)"
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

                    New-UDCard -Text $CardOutput

                    New-UDGrid -Title "Windows Processes" -Endpoint {
                        $TestResult | Select-Object ProcessId,Name,WorkingSetSize,VirtualSize,Path,CommandLine | Out-UDGridData
                    }

                )

            }

        }

    }

}
#endregion

#region Dashboard
$Navigation = New-UDSideNav -Content {
    New-UDSideNavItem -Text "Home"                   -PageName "Home"                     -Icon home 
    New-UDSideNavItem -Text "Name Resolution Tester" -PageName "Name Resolution Tester"   -Icon rocket 
    New-UDSideNavItem -Text "Connectivity Tester"    -PageName "Connectivity Tester"      -Icon rocket 
    New-UDSideNavItem -Text "Access Tester"          -PageName "Access Tester"            -Icon rocket
    New-UDSideNavItem -Text "Windows Updates"        -PageName "Windows Updates Tester"   -Icon rocket
    New-UDSideNavItem -Text "Windows Eventlog"       -PageName "Windows Eventlog Tester"  -Icon rocket
    New-UDSideNavItem -Text "Windows Registry"       -PageName "Windows Registry Tester"  -Icon rocket
    New-UDSideNavItem -Text "Windows File Reader"    -PageName "Windows File Reader"      -Icon rocket
    New-UDSideNavItem -Text "Windows Services"       -PageName "Windows Service Tester"   -Icon rocket
    New-UDSideNavItem -Text "Windows Processes"      -PageName "Windows Process Tester"   -Icon rocket
} -Fixed

$Dashboard = New-UDDashboard -Pages @($Page1,$Page2,$Page3,$Page4,$Page5,$Page6,$Page7,$Page8,$Page9,$Page10) -Navigation $Navigation

Start-UDDashboard -Name "OpsRemoteWinRM" -Endpoint $Endpoint -Dashboard $Dashboard -Port 20001 -AutoReload

Start-Process "http://localhost:20001/Home"
