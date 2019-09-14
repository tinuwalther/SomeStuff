<#
https://ironmansoftware.com/universal-dashboard-2-6-beautification-ws-fed-and-bounty-hunters/
#>

Get-UDDashboard | Stop-UDDashboard

#region Dataset
$out = $null
Get-ChildItem $HOME | ForEach-Object {
    $out = $out + "`r`n- " + $_.Name
}
$out = $out.TrimStart("`r`n")

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
PowerShell Version: $($PSVersionTable.PSVersion)`r`n`r`n
PowerShell Home: $($PSHome)

$(($env:PSModulePath) -replace ':',"`r`n")
"@

    $UpdateTitle = "Mac Updates"
    $Hotfix = "not implemented yet"
}
elseif($IsLinux){
    $UpdateTitle = "Linux Updates"
    $Hotfix = "not implemented yet"
}

#endregion

$Dashboard = New-UDDashboard -Title "Tinus Dashboard" -Content {

    <#
    New-UDButton -Text "Get-Date!" -OnClick {
        Show-UDToast -Message (Get-Date)
    }
    New-UDButton -Text "Test Foto" -Icon cloud -IconAlignment left -OnClick {
        Show-UDToast -Message (Invoke-WebRequest -Uri 'https://foto.martin-walther.ch' | Select-Object -ExpandProperty StatusDescription)
    }
    New-UDButton -Text "Button" -Icon cloud -IconAlignment right
    #>

    #region Layout
    New-UDLayout -Columns 6 -Content {

        $webret1 = (Invoke-WebRequest -Uri 'https://tinuwalther.github.io' | Select-Object -ExpandProperty StatusCode)
        if($webret1 -eq 200){
            New-UDCounter -Title "EngOps Wiki" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret1} -Icon linux -BackgroundColor lightgreen -FontColor White
        }
        else{
            New-UDCounter -Title "EngOps Wiki" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret1} -Icon linux -BackgroundColor Red -FontColor White
        }
        
        $webret2 = (Invoke-WebRequest -Uri 'https://it.martin-walther.ch' | Select-Object -ExpandProperty StatusCode)
        if($webret2 -eq 200){
            New-UDCounter -Title "Tinus IT Wiki" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret2} -Icon linux -BackgroundColor lightgreen -FontColor White
        }
        else{
            New-UDCounter -Title "Tinus IT Wiki" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret2} -Icon linux -BackgroundColor Red -FontColor White
        }
        
        $webret3 = (Invoke-WebRequest -Uri 'https://foto.martin-walther.ch' | Select-Object -ExpandProperty StatusCode)
        if($webret3 -eq 200){
            New-UDCounter -Title "Foto & IT" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret3} -Icon linux -BackgroundColor lightgreen -FontColor White
        }
        else{
            New-UDCounter -Title "Foto & IT" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret3} -Icon linux -BackgroundColor Red -FontColor White
        }

        $webret4 = (Invoke-WebRequest -Uri 'https://karin-bonderer.ch' | Select-Object -ExpandProperty StatusCode)
        if($webret4 -eq 200){
            New-UDCounter -Title "Karins Blog" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret4} -Icon linux -BackgroundColor lightgreen -FontColor White
        }
        else{
            New-UDCounter -Title "Karins Blog" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret} -Icon linux -BackgroundColor Red -FontColor White
        }

        $webret = (Invoke-WebRequest -Uri 'https://dev.cantunada.ch' | Select-Object -ExpandProperty StatusCode)
        if($webret -eq 200){
            New-UDCounter -Title "Cantunada" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret} -Icon linux -BackgroundColor lightgreen -FontColor White
        }
        else{
            New-UDCounter -Title "Cantunada" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret4} -Icon linux -BackgroundColor Red -FontColor White
        }

        $webret5 = (Invoke-WebRequest -Uri 'https://beawalther.wordpress.com/' | Select-Object -ExpandProperty StatusCode)
        if($webret5 -eq 200){
            New-UDCounter -Title "Steinschmuck" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret5} -Icon linux -BackgroundColor lightgreen -FontColor White
        }
        else{
            New-UDCounter -Title "Steinschmuck" -AutoRefresh -RefreshInterval 900 -Endpoint {$webret5} -Icon linux -BackgroundColor Red -FontColor White
        }

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

Start-UDDashboard -Dashboard $Dashboard -Port 10001 -AutoReload
