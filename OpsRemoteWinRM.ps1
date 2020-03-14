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
                New-UDParagraph -Text 'Test TCP connection to a remote Host and displays diagnostic information about this connection. You can specify the remote Host, and a TCP port to send the test. On the remote Host, there must be an Listener on the given TCP port otherwise the test fails.'
            } -Links @(
                New-UDLink -Text 'Connectivity Test' -Url 'Connectivity-Tester'
            ) -Size 'small'

            New-UDCard -Title 'Windows Update' -Content {
                New-UDParagraph -Text 'Get last 5 installed Windows Updates of a remote host.'
            } -Links @(
                New-UDLink -Text 'Windows Updates' -Url 'Windows-Updates-Tester'
            ) -Size 'small'

            New-UDCard -Title 'Windows Eventlog' -Content {
                New-UDParagraph -Text 'List I dont know yet ...'
            } -Links @(
                New-UDLink -Text 'Windows Eventlog' -Url 'Windows-Eventlog-Tester'
            ) -Size 'small'

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
                New-UDInputField -Type textbox  -Name Remotehost -Placeholder 'RemoteName or IP Address'
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
                    ) -Size 'small' -BackgroundColor $color -FontColor White

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
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'Username'
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

#region "Windows Eventlog Tester"
$Page4 = New-UDPage -Name "Windows Eventlog Tester" -Title "Windows Eventlog Tester - $($UDTitle)" -Content { 

    New-UDLayout -Columns 1 -Content {

        New-UDHeading -Size 4 -Content { "List Windows Eventlog from a remote Host" }

        New-UDHeading -Size 6 -Content { "Displays diagnostic information for a connection" }

        New-UDLayout -Columns 1 -Content {
            
            New-UDInput -Title "Remote Information" -Content {
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'Username'
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
                New-UDInputField -Type textbox  -Name Username   -Placeholder 'Username'
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
    New-UDSideNavItem -Text "Home"              -PageName "Home"                     -Icon home 
    New-UDSideNavItem -Text "Connectivity Test" -PageName "Connectivity Tester"      -Icon rocket 
    New-UDSideNavItem -Text "Windows Updates"   -PageName "Windows Updates Tester"   -Icon rocket
    New-UDSideNavItem -Text "Windows Eventlog"  -PageName "Windows Eventlog Tester"  -Icon rocket
    New-UDSideNavItem -Text "Run Scriptblock"   -PageName "Run Scriptblock"          -Icon rocket
} -Fixed

$Dashboard = New-UDDashboard -Pages @($Page1, $Page2, $Page3, $Page4, $Page5) -Navigation $Navigation

Start-UDDashboard -Name "OpsRemoteWinRM" -Endpoint $Endpoint -Dashboard $Dashboard -Port 20001 -AutoReload

Start-Process "http://localhost:20001/Home"

Get-UDDashboard
