<#

    https://ironmansoftware.com/universal-dashboard-2-6-beautification-ws-fed-and-bounty-hunters/

    localhost:20001

#>
$UDTitle = "Remote Operating"

Get-UDDashboard -Name "OpsRemoteWinRM" | Stop-UDDashboard

#region "Home"
$Page1 = New-UDPage -Name "Home" -Title "Home - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "The web framework for PowerShell remote operating" }

        New-UDHeading -Size 6 -Content{ "This is the web-based, interactive dashboard for remote operation tasks with the following features." }

        New-UDLayout -Columns 3 -Content {
            
            New-UDCard -Title 'Connectivity Test' -Content {
                New-UDParagraph -Text 'Test TCP connection to a remote Host. On the remote Host, must be an Listener on the given TCP port otherwise the test fails.'
            } -Links @(
                New-UDLink -Text 'Connectivity Tester' -Url 'Connectivity-Tester'
            ) 

            New-UDCard -Title 'Access Test' -Content {
                New-UDParagraph -Text 'Test WinRM access to a remote host. You need a user account who is member of the local Administrators of the remote Host.'
            } -Links @(
                New-UDLink -Text 'Access Tester' -Url 'Access-Tester'
            ) 

            # Get-Hotfix -last 5
            # Get-WindowsUpdateEventlog
            New-UDCard -Title 'Windows Updates' -Content {
                New-UDParagraph -Text 'NOT IMPLEMENTED YET!NOT IMPLEMENTED YET!NOT IMPLEMENTED YET!NOT IMPLEMENTED YET!NOT IMPLEMENTED YET!'
            } -Links @(
                New-UDLink -Text 'Windows Updates' -Url 'Windows-Updates-Tester'
            ) 

            <#
            New-UDCard -Title 'Windows Eventlog' -Content {
                New-UDParagraph -Text 'List I dont know yet ...'
            } -Links @(
                New-UDLink -Text 'Windows Eventlog' -Url 'Windows-Eventlog-Tester'
            ) -Size 'small'
            #>

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
                $TestReturn = Test-NetConnection -ComputerName $Remotehost -Port $Remoteport -WarningAction SilentlyContinue
                
                $CardOutput = @"
                ComputerName           : $($TestReturn.ComputerName)
                RemoteAddress          : $($TestReturn.RemoteAddress)
                RemotePort             : $($TestReturn.RemotePort)
                InterfaceAlias         : $($TestReturn.InterfaceAlias)
                PingSucceeded          : $($TestReturn.PingSucceeded)
                TcpTestSucceeded       : $($TestReturn.TcpTestSucceeded)
"@
                New-UDInputAction -Content @(

                    if($TestReturn.TcpTestSucceeded){
                        $ret   = "Connectivity over $Remoteport is OK"
                        $color = "LightGreen"
                    }else{
                        $ret   = "Connectivity over $Remoteport is not OK"
                        $color = "IndianRed"
                    }

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                            New-UDLink -Text "$ret"
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
                $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                if($rsession.State -eq 'Opened'){
                    $TestReturn = $rsession.State
                    $color = "LightGreen"
                }else{
                    $TestReturn = $rsession.State
                    $color = "IndianRed"
                }
                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $TestReturn -Links @(
                            #New-UDLink -Text "$ret"
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

                $CardOutput = (Get-itemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUServer' -ErrorAction SilentlyContinue).WUServer

                Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 5 | Select-Object HotFixID,InstalledOn,Description | Sort-Object InstalledOn -Descending | ForEach-Object {
                    if([String]::IsNullOrEmpty($CardOutput)){
                        $CardOutput = "$($_.InstalledOn) installed $($_.HotFixID) $($_.Description)"
                    }else{
                        $CardOutput = "$CardOutput`r`n$($_.InstalledOn) installed $($_.HotFixID) $($_.Description)"
                    }
                }

                $CardOutput = "$CardOutput`r`n`r`nWindows Update Eventlog:"

                Get-WinEvent -MaxEvents 15 -FilterHashtable @{
                    Logname   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
                    StartTime = (get-date).AddDays(-5)
                    EndTime   = get-date
                } -ErrorAction SilentlyContinue | ForEach-Object {
                    if([String]::IsNullOrEmpty($CardOutput)){
                        $CardOutput = "$($_.TimeCreated) $($_.Id) $($_.Message)"
                    }else{
                        $CardOutput = "$CardOutput`r`n$($_.TimeCreated) $($_.Id) $($_.Message)"
                    }
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
                $TestReturn = Test-NetConnection -ComputerName $Remotehost -Port $Remoteport -WarningAction SilentlyContinue
                
                $CardOutput = @"
                ComputerName           : $($TestReturn.ComputerName)
                RemoteAddress          : $($TestReturn.RemoteAddress)
                RemotePort             : $($TestReturn.RemotePort)
                InterfaceAlias         : $($TestReturn.InterfaceAlias)
                PingSucceeded          : $($TestReturn.PingSucceeded)
                TcpTestSucceeded       : $($TestReturn.TcpTestSucceeded)
"@
                New-UDInputAction -Content @(

                    if($TestReturn.TcpTestSucceeded){
                        $ret   = "Connectivity over $Remoteport is OK"
                        $color = "LightGreen"
                    }else{
                        $ret   = "Connectivity over $Remoteport is not OK"
                        $color = "IndianRed"
                    }

                    New-UDCard -Title "Details" -Text $CardOutput -Links @(
                            New-UDLink -Text "$ret"
                    ) -Size 'small' -BackgroundColor $color -FontColor White

                )

            }

        }

    }

}
#endregion

#region "ScriptBlock Tester"
$Page5 = New-UDPage -Name "Run Scriptblock" -Title "Run Scriptblock - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "List something from a remote Host" }

        New-UDHeading -Size 6 -Content { "Displays diagnostic information for a connection" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'username@domain.com'
                New-UDInputField -Type password -Name Password   -Placeholder 'Password'
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'Remote Name or IP Address'
                New-UDInputField -Type textbox  -Name Scriptblock -Placeholder 'Scriptblock'
            } -Validate -Endpoint {
                param(
                    [Parameter(Mandatory)]
                    $Username, 

                    [Parameter(Mandatory)]
                    $Password, 

                    [Parameter(Mandatory)]
                    $Remotehost,

                    $Scriptblock
                )
                Show-UDToast -Message "Send Tests to $Remotehost"
                # Output a new card based on that info
                <#
                $secpasswd  = ConvertTo-SecureString $Password -AsPlainText -Force
                $mycreds    = New-Object System.Management.Automation.PSCredential ($Username, $secpasswd)
                $rsession   = New-PSSession -ComputerName $RemoteHost -Credential $mycreds
                $TestReturn = Invoke-Command -Session $rsession -ScriptBlock { $Scriptblock }
                #>
                New-UDInputAction -Content @(

                    New-UDCard -Title "Details" -Text $TestReturn -Links @(
                            #New-UDLink -Text "$ret"
                    ) -Size 'small' -BackgroundColor $color -FontColor White

                )

            }

        }

    }

}
#endregion

#region Dashboard
$Navigation = New-UDSideNav -Content {
    New-UDSideNavItem -Text "Home"                -PageName "Home"                     -Icon home 
    New-UDSideNavItem -Text "Connectivity Tester" -PageName "Connectivity Tester"      -Icon rocket 
    New-UDSideNavItem -Text "Access Tester"       -PageName "Access Tester"            -Icon rocket
    New-UDSideNavItem -Text "Windows Updates"     -PageName "Windows Updates Tester"   -Icon rocket
    #New-UDSideNavItem -Text "Windows Eventlog"    -PageName "Windows Eventlog Tester"  -Icon rocket
    #New-UDSideNavItem -Text "Run Scriptblock"     -PageName "Run Scriptblock"          -Icon rocket
} -Fixed

$Dashboard = New-UDDashboard -Pages @($Page1, $Page2, $Page3, $Page4, $Page5, $Page6) -Navigation $Navigation

Start-UDDashboard -Name "OpsRemoteWinRM" -Endpoint $Endpoint -Dashboard $Dashboard -Port 20001 -AutoReload

Start-Process "http://localhost:20001/Home"
