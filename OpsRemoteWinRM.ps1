<#

    https://ironmansoftware.com/universal-dashboard-2-6-beautification-ws-fed-and-bounty-hunters/
    Universal Dashboard requires .NET Framework version 4.7.2

    localhost:20001

#>
if(!(Get-Module UniversalDashboard.Community)){
    Import-Module UniversalDashboard.Community
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
        $config.WUServer
    }

}

function Get-InstalledgUpdates{
    [CmdletBinding()]
    param(
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 5 | Select-Object HotFixID,InstalledOn,Description | Sort-Object InstalledOn -Descending | ForEach-Object {
            "$($_.InstalledOn), $($_.HotFixID), $($_.Description)`r`n"
        }
    }

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
        $search_result.Updates | ForEach-Object {
            "$($_.Title)`r`n"
        }
    }

}

function Get-WindowsUpdateClientLog{
    [CmdletBinding()]
    param(
        $RemoteSession
    )

    Invoke-Command -Session $RemoteSession -ScriptBlock {
        Get-WinEvent -MaxEvents 50 -FilterHashtable @{
            Logname   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
            StartTime = (get-date).AddDays(-5)
            EndTime   = get-date
        } -ErrorAction SilentlyContinue | ForEach-Object {
            "$($_.TimeCreated), $($_.Id), $($_.LevelDisplayName), $($_.Message)`r`n"
        }
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
        Get-WinEvent -MaxEvents 100 -FilterHashtable @{
            Logname   = $EventlogName
            StartTime = (get-date).AddDays(-5)
            EndTime   = get-date
        } -ErrorAction SilentlyContinue | ForEach-Object {
            "$($_.TimeCreated), $($_.Id), $($_.LevelDisplayName), $($_.Message)`r`n"
        }
    }
    Invoke-Command -Session $rsession -ScriptBlock $ScriptBlockContent -ArgumentList $EventlogName
}

function Get-SCSRegistryValue{
    [CmdletBinding()]
    param(
        $RemoteSession,
        $RegistryPath,
        $RegistryName
    )

    $ScriptBlockContent = {
        Param($RegistryPath,$RegistryName)
        Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryName
    }
    Invoke-Command -Session $rsession -ScriptBlock $ScriptBlockContent -ArgumentList $RegistryPath,$RegistryName
}

#endregion

#region "Home"
$Page1 = New-UDPage -Name "Home" -Title "Home - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "The web framework for PowerShell remote operating" }

        New-UDHeading -Size 6 -Content{ "This is the web-based, interactive dashboard for remote operation tasks with the following features." }

        New-UDLayout -Columns 3 -Content {
            
            New-UDCard -Title 'Name Resolution Tester' -Content {
                New-UDParagraph -Text 'Test TCP connection to a remote Host. On the remote Host, must be an Listener on the given TCP port otherwise the test fails.'
            } -Links @(
                New-UDLink -Text 'Name Resolution Tester' -Url 'Name-Resolution-Tester'
            ) 

            New-UDCard -Title 'Connectivity Tester' -Content {
                New-UDParagraph -Text 'Test TCP connection to a remote Host. On the remote Host, must be an Listener on the given TCP port otherwise the test fails.'
            } -Links @(
                New-UDLink -Text 'Connectivity Tester' -Url 'Connectivity-Tester'
            ) 

            New-UDCard -Title 'Access Tester' -Content {
                New-UDParagraph -Text 'Test WinRM access to a remote host. You need a user account who is member of the local Administrators of the remote Host.'
            } -Links @(
                New-UDLink -Text 'Access Tester' -Url 'Access-Tester'
            ) 

            New-UDCard -Title 'Windows Updates' -Content {
                New-UDParagraph -Text 'List configured WSUS Server, the last 5 installed Windows Update, MissingUpdates, and last 5 days of WindowsUpdateClient Enventlog.'
            } -Links @(
                New-UDLink -Text 'Windows Updates' -Url 'Windows-Updates-Tester'
            ) 

            New-UDCard -Title 'Windows Eventlog' -Content {
                New-UDParagraph -Text 'List the last 100 Eventlog entries from the last 5 days of a Windows Eventlog.'
            } -Links @(
                New-UDLink -Text 'Windows Eventlog' -Url 'Windows-Eventlog-Tester'
            )

            New-UDCard -Title 'Windows Registry' -Content {
                New-UDParagraph -Text 'List the Value of a Windows Registry path and name.'
            } -Links @(
                New-UDLink -Text 'Windows Registry' -Url 'Windows-Registry-Tester'
            )

        }

    }

}
#endregion

#region "Name Resolution Tester"
$Page7 = New-UDPage -Name "Name Resolution Tester" -Title "Name Resolution Tester - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Test Name Resolution to a remote Host" }

        New-UDHeading -Size 6 -Content { "Test Forwardlookup to a remote Host" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Remote Name or IP Address'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Remotehost
                )

                Show-UDToast -Message "Send Tests to $Remotehost" -Balloon
                # Output a new card based on that info

                try{
                    $TestReturn = Resolve-DnsName -Name $Remotehost -WarningAction SilentlyContinue -DnsOnly | where Type -eq A
                
                    $CardOutput = @"
                    Input    : $Remotehost
                    Name     : $($TestReturn.Name)
                    Type     : $($TestReturn.Type)
                    TTL      : $($TestReturn.TTL)
                    Section  : $($TestReturn.Section)
                    NameHost : $($TestReturn.NameHost)
                    IPAddress: $($TestReturn.IPAddress)
"@

                    $ret   = "Name Resolution for $Remotehost is OK"
                    $color = "LightGreen"

                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $ret        = "Error in Test"
                    $color      = "IndianRed"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                            New-UDLink -Text "$ret"  -Url 'Name-Resolution-Tester'
                    ) -BackgroundColor $color -FontColor White

                )

            }

        }

    }

}
#endregion

#region "Connectivity Tester"
$Page2 = New-UDPage -Name "Connectivity Tester" -Title "Connectivity Tester - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Test connection to a remote Host" }

        New-UDHeading -Size 6 -Content { "Test TCP connection, displays diagnostic information for a connection" }

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
                # Output a new card based on that info

                try{
                    $TestReturn = Test-NetConnection -ComputerName $Remotehost -Port $Remoteport -WarningAction SilentlyContinue
                
                    $CardOutput = @"
                    Input            : $Remotehost
                    ComputerName     : $($TestReturn.ComputerName)
                    RemoteAddress    : $($TestReturn.RemoteAddress)
                    RemotePort       : $($TestReturn.RemotePort)
                    InterfaceAlias   : $($TestReturn.InterfaceAlias)
                    PingSucceeded    : $($TestReturn.PingSucceeded)
                    TcpTestSucceeded : $($TestReturn.TcpTestSucceeded)
"@

                    if($TestReturn.TcpTestSucceeded){
                        $ret   = "Connectivity over $Remoteport is OK"
                        $color = "LightGreen"
                    }else{
                        $ret   = "Connectivity over $Remoteport is not OK"
                        $color = "IndianRed"
                    }

                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $ret        = "Error in Test"
                    $color      = "IndianRed"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                            New-UDLink -Text "$ret" -Url 'Connectivity-Tester'
                    ) -BackgroundColor $color -FontColor White

                )

            }

        }

    }

}
#endregion

#region "Access Tester"
$Page6 = New-UDPage -Name "Access Tester" -Title "Access Tester - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "Test access to a remote Host" }

        New-UDHeading -Size 6 -Content { "Test WinRM access, displays diagnostic information for a connection" }

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
                    $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                    $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                    $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                
                    if($rsession.State -eq 'Opened'){
                        $ret   = "Access to $Remotehost is OK"
                        $color = "LightGreen"
                        
                        $CardOutput = @"
                        Input        : $Remotehost
                        Session Id   : $($rsession.Id)
                        Session Name : $($rsession.Name)
                        ComputerName : $(Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME})
                        State        : $($rsession.State)
                        Availability : $($rsession.Availability)
"@
                    }else{
                        $ret   = "Access to $Remotehost is not OK"
                        $color = "IndianRed"
                        $CardOutput = "Session to $Remotehost is $($rsession.State)"
                    }
                    Remove-PSSession -Session $rsession

                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $ret        = "Error in Test"
                    $color      = "IndianRed"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                            New-UDLink -Text "$ret" -Url 'Access-Tester'
                    ) -BackgroundColor $color -FontColor White

                )

            }

        }

    }

}
#endregion

#region "Windows Update Tester"
$Page3 = New-UDPage -Name "Windows Updates Tester" -Title "Windows Updates Tester - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "List Windows Updates from a remote Host" }

        New-UDHeading -Size 6 -Content { "Displays diagnostic information for a connection" }

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
                    $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                    $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                    $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                
                    if($rsession.State -eq 'Opened'){
                        $CardOutput = @"
                        Input        : $($Remotehost)
                        ComputerName : $(Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME})

                        WSUS Servers Server : $(Get-WsusServer -RemoteSession $rsession)

                        Installed Hotfix (Last 5): 
                        TimeCreated, Hotfix, Description
                        $(Get-InstalledgUpdates -RemoteSession $rsession)
                        Missing Hotfix:
                        $(Get-MissingUpdates -RemoteSession $rsession)
                        Windows Update Eventlog (Last 5 Days):
                        TimeCreated, Id, Level, Message
                        $(Get-WindowsUpdateClientLog -RemoteSession $rsession)
"@

                    }else{
                        $ret   = "Access to $Remotehost is not OK"
                        $color = "IndianRed"
                        $CardOutput = "Session to $Remotehost is $($rsession.State)"
                    }
                    Remove-PSSession -Session $rsession

                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $ret        = "Error in Test"
                    $color      = "IndianRed"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                        New-UDLink -Text 'Microsoft Update-Catalog' -Url 'https://www.catalog.update.microsoft.com/Home.aspx'
                    )

                )

            }

        }

    }

}
#endregion

#region "Windows Eventlog Tester"
$Page4 = New-UDPage -Name "Windows Eventlog Tester" -Title "Windows Eventlog Tester - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "List Windows Eventlog from a remote Host" }

        New-UDHeading -Size 6 -Content { "Displays diagnostic information for a connection" }

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
                    $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                    $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                    $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                
                    if($rsession.State -eq 'Opened'){
                        $CardOutput = @"
                        Input        : $($Remotehost)
                        ComputerName : $(Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME})

                        Windows Eventlog (Last 5 Days):
                        TimeCreated, Id, Level, Message
                        $(Get-SCSWindowsEventLog -RemoteSession $rsession -EventlogName $Eventlog)
"@

                    }else{
                        $ret   = "Access to $Remotehost is not OK"
                        $color = "IndianRed"
                        $CardOutput = "Session to $Remotehost is $($rsession.State)"
                    }
                    Remove-PSSession -Session $rsession

                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $ret        = "Error in Test"
                    $color      = "IndianRed"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                        New-UDLink -Text $Eventlog
                    )

                )

            }

        }

    }

}
#endregion

#region "Registry Tester"
$Page5 = New-UDPage -Name "Windows Registry Tester" -Title "Windows Registry Tester - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "List Windows Registry value from a remote Host" }

        New-UDHeading -Size 6 -Content { "Displays diagnostic information for a connection" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username     -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password     -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost   -Placeholder 'Remote Name or IP Address'
                New-UDInputField -Type textbox  -Name RegistryPath -Placeholder 'Registry Path'
                New-UDInputField -Type textbox  -Name RegistryName -Placeholder 'Registry Name'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost,

                    [Parameter(Mandatory)]
                    $RegistryPath,

                    [Parameter(Mandatory)]
                    $RegistryName
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                # Output a new card based on that info

                try{
                    $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                    $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                    $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                
                    if($rsession.State -eq 'Opened'){
                        $CardOutput = @"
                        Input        : $($Remotehost)
                        ComputerName : $(Invoke-Command -Session $rsession -ScriptBlock {$env:COMPUTERNAME})

                        Value for Path: $($RegistryPath) Name: $($RegistryName):
                        $(Get-SCSRegistryValue -RemoteSession $rsession -RegistryPath $RegistryPath -RegistryName $RegistryName)
"@

                    }else{
                        $ret   = "Access to $Remotehost is not OK"
                        $color = "IndianRed"
                        $CardOutput = "Session to $Remotehost is $($rsession.State)"
                    }
                    Remove-PSSession -Session $rsession

                }
                catch{
                    $CardOutput = "$($Remotehost): $($_.Exception.Message)"
                    $ret        = "Error in Test"
                    $color      = "IndianRed"
                    $Error.Clear()
                }

                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                        #New-UDLink -Text 'Microsoft Update-Catalog' -Url 'https://www.catalog.update.microsoft.com/Home.aspx'
                    )

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
} -Fixed

$Dashboard = New-UDDashboard -Pages @($Page1, $Page2, $Page3, $Page4, $Page5, $Page6, $Page7) -Navigation $Navigation

Start-UDDashboard -Name "OpsRemoteWinRM" -Endpoint $Endpoint -Dashboard $Dashboard -Port 20001 -AutoReload

Start-Process "http://localhost:20001/Home"
