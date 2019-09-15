<#
https://ironmansoftware.com/universal-dashboard-2-6-beautification-ws-fed-and-bounty-hunters/
#>

Get-UDDashboard | Stop-UDDashboard

#region Dataset
$Hotfix = $null
if($IsWindows){
    $ps = @"
    PowerShell Platform: $($PSVersionTable.Platform)
    PowerShell Edition: $($PSVersionTable.PSEdition)
    PowerShell Version: $($PSVersionTable.PSVersion)
    PowerShell Home: $($PSHome)
    $(($env:PSModulePath) -replace ';',"`r`n")
"@

    $UpdateTitle = "Windows Updates"
    $WebSiteName = 'Microsoft Update Cataloge'
    $WebSiteUrl  = 'https://www.catalog.update.microsoft.com/Home.aspx'
    Get-CimInstance -Class Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 8| ForEach-Object {
        $Hotfix = $Hotfix + "`r`n$($_.HotFixID) installed at $(Get-Date ($_.InstalledOn) -f 'dddd dd MMMM yyyy')"
    }
    $Hotfix = $Hotfix.TrimStart("`r`n")
}
elseif($IsMacOS){
    $ps = @"
    PowerShell Platform: $($PSVersionTable.Platform)`r`n
    PowerShell Edition: $($PSVersionTable.PSEdition)`r`n
    PowerShell Version: $($PSVersionTable.PSVersion)`r`n`
    PowerShell Home: $($PSHome)`r`n`
    $(($env:PSModulePath) -replace ':',"`r`n")
"@

    $UpdateTitle = "Mac Updates"
    $WebSiteName = 'Apple security updates'
    $WebSiteUrl  = 'https://support.apple.com/en-us/HT201222'
    $ret = softwareupdate --history
    for ($i = 2; $i -le ($ret.GetUpperBound(0)); $i++){
        $Hotfix = $Hotfix + "`r`n" + $ret[$i].TrimEnd(' ')
    }
    $Hotfix = $Hotfix.TrimStart("`r`n")

}
elseif($IsLinux){
    $UpdateTitle = "Linux Updates"
    $Hotfix = "not implemented yet"
}

#endregion

#region Cache
$Schedule = New-UDEndpointSchedule -Every 15 -Minute
$Endpoint = New-UDEndpoint -Schedule $Schedule -Endpoint {
    $Cache:WebRequest1 = (Invoke-WebRequest -Uri 'https://tinuwalther.github.io'    | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}})
    $Cache:WebRequest2 = (Invoke-WebRequest -Uri 'https://it.martin-walther.ch'     | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}})
    $Cache:WebRequest3 = (Invoke-WebRequest -Uri 'https://foto.martin-walther.ch'   | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}})
    $Cache:WebRequest4 = (Invoke-WebRequest -Uri 'https://karin-bonderer.ch'        | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}})
    $Cache:WebRequest5 = (Invoke-WebRequest -Uri 'https://dev.cantunada.ch'         | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}})
    $Cache:WebRequest6 = (Invoke-WebRequest -Uri 'https://beawalther.wordpress.com' | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}})
}
#endregion

#region Dashboard
$Dashboard = New-UDDashboard -Title "Tinus Dashboard" -Content {

    New-UDLayout -Columns 6 -Content {

        New-UDGrid -Title 'EngOps Wiki' -AutoRefresh -RefreshInterval 900 -Endpoint {
            $Cache:WebRequest1 | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Tinus IT Wiki' -AutoRefresh -RefreshInterval 900 -Endpoint {
            $Cache:WebRequest2 | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Foto & IT' -AutoRefresh -RefreshInterval 900 -Endpoint {
            $Cache:WebRequest3 | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Karins Blog' -AutoRefresh -RefreshInterval 900 -Endpoint {
            $Cache:WebRequest4 | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Cantunada' -AutoRefresh -RefreshInterval 900 -Endpoint {
            $Cache:WebRequest5 | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Steinschmuck' -AutoRefresh -RefreshInterval 900 -Endpoint {
            $Cache:WebRequest6 | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

    }

    #region Layout
    New-UDLayout -Columns 6 -Content {

        New-UDCounter -Title "EngOps Wiki" -Icon linux -AutoRefresh -RefreshInterval 900 -Endpoint {
            (Invoke-WebRequest -Uri 'https://tinuwalther.github.io' | Select-Object -ExpandProperty StatusCode)
        } -BackgroundColor lightgreen -FontColor White
        
        New-UDCounter -Title "Tinus IT Wiki" -AutoRefresh -RefreshInterval 900 -Endpoint {
            (Invoke-WebRequest -Uri 'https://it.martin-walther.ch' | Select-Object -ExpandProperty StatusCode)
        } -Icon linux -BackgroundColor lightgreen -FontColor White
        
        New-UDCounter -Title "Foto & IT" -AutoRefresh -RefreshInterval 900 -Endpoint {
            (Invoke-WebRequest -Uri 'https://foto.martin-walther.ch' | Select-Object -ExpandProperty StatusCode)
        } -Icon linux -BackgroundColor lightgreen -FontColor White

        New-UDCounter -Title "Karins Blog" -AutoRefresh -RefreshInterval 900 -Endpoint {
            (Invoke-WebRequest -Uri 'https://karin-bonderer.ch' | Select-Object -ExpandProperty StatusCode)
        } -Icon linux -BackgroundColor lightgreen -FontColor White

        New-UDCounter -Title "Cantunada" -AutoRefresh -RefreshInterval 900 -Endpoint {
            (Invoke-WebRequest -Uri 'https://dev.cantunada.ch' | Select-Object -ExpandProperty StatusCode)
        } -Icon linux -BackgroundColor lightgreen -FontColor White

        New-UDCounter -Title "Steinschmuck" -AutoRefresh -RefreshInterval 900 -Endpoint {
            (Invoke-WebRequest -Uri 'https://beawalther.wordpress.com/' | Select-Object -ExpandProperty StatusCode)
        } -Icon linux -BackgroundColor lightgreen -FontColor White

    }  
    #endregion

    #region card
    New-UDLayout -Columns 3 -Content {  
        
        New-UDCard  -Title 'Installed PowerShell' -Text $ps -Links @(
            New-UDLink -Text 'Tinus EngOps Wiki' -Url 'https://tinuwalther.github.io/'
        ) -Size 'small' -BackgroundColor SteelBlue -FontColor White

        New-UDCard -Title $UpdateTitle -Text $Hotfix -Links @(
            New-UDLink -Text $WebSiteName -Url $WebSiteUrl
        ) -Size 'small' -BackgroundColor SteelBlue -FontColor White

        New-UDInput -Title "Test Website status" -Endpoint {

            param($WebSiteName) 
    
            # Get a module from the gallery
            $WebSiteURI = Invoke-WebRequest -Uri "https://$($WebSiteName)"
        
            # Output a new card based on that info
            New-UDInputAction -Content @(
                New-UDCard -Title "Website status" -Text "Test web-request '$($WebSiteName)' returned '$($WebSiteURI.StatusDescription)'" -Links @(
                    New-UDLink -Text 'Martin Walther - Foto & IT' -Url 'https://foto.martin-walther.ch/'
                ) -Size 'small' -BackgroundColor SteelBlue -FontColor White
            )
        }
    }

    New-UDLayout -Columns 1 -Content {
        <#
        New-UdGrid -Title "Processes" -AutoRefresh 360 -Endpoint {
            #https://docs.microsoft.com/de-de/powershell/module/Microsoft.PowerShell.Management/Get-Process?view=powershell-5.1
            Get-Process -IncludeUserName | Select-Object ProcessName,ID,@{Name = 'WS(KB)'; Expression = {($_.WorkingSet/1kb).ToString("N0")}},@{Name = 'CPU(s)'; Expression = {if ($_.CPU) {$_.CPU.ToString("N0")}}},UserName,Path | Out-UDGridData
        } -DefaultSortColumn 'WS(KB)' -DefaultSortDescending -BackgroundColor SteelBlue -FontColor White
        #>
        
        New-UdGrid -Title "Processes" -AutoRefresh 360 -Endpoint {
            Get-Process -IncludeUserName | Select-Object ProcessName,ID,WorkingSet,CPU,UserName,Path | Out-UDGridData
        } -DefaultSortColumn CPU -DefaultSortDescending -BackgroundColor SteelBlue -FontColor White
   }
        
    #endregion

    #region Input
    New-UDLayout -Columns 1 -Content {

        New-UDInput -Title "PowerShell Module Info Locator" -Endpoint {
            param($ModuleName) 
        
            # Get a module from the gallery
            $Module = Find-Module $ModuleName
        
            # Output a new card based on that info
            New-UDInputAction -Content @(
                New-UDCard -Title "$ModuleName - $($Module.Version)" -Text $Module.Description -BackgroundColor SteelBlue -FontColor White
            )
        }

    }
    #endregion
}
#endregion

Start-UDDashboard -Endpoint $Endpoint -Dashboard $Dashboard -Port 10001 -AutoReload
