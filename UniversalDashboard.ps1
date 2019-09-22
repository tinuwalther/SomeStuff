<#
https://ironmansoftware.com/universal-dashboard-2-6-beautification-ws-fed-and-bounty-hunters/
#>

Get-UDDashboard | Stop-UDDashboard

if($PSVersionTable.PSVersion.Major -lt 6){
    $IsWindows = $true
}

#region Dataset
if($IsWindows){
    $UpdateTitle    = "Windows Updates"
    $WebSiteName    = 'Microsoft Update Cataloge'
    $WebSiteUrl     = 'https://www.catalog.update.microsoft.com/Home.aspx'
    $SSUWebSiteName = 'Microsoft Update Cataloge'
    $SSUWebSiteUrl  = 'https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV990001'
}
elseif($IsMacOS){
    $UpdateTitle = "Mac Updates"
    $WebSiteName = 'Apple security updates'
    $WebSiteUrl  = 'https://support.apple.com/en-us/HT201222'
}
elseif($IsLinux){
    $UpdateTitle = "Linux Updates"
    $Hotfix = "not implemented yet"
}
#endregion

#region Cache
#$server = (Invoke-WebRequest -UseBasicParsing -Uri 'https://foto.martin-walther.ch').RawContent | Select-String -Pattern 'Server:\s\S+' -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value
$Schedule = New-UDEndpointSchedule -Every 15 -Minute
$Endpoint = New-UDEndpoint -Schedule $Schedule -Endpoint {
    $Cache:WebRequest1 = Invoke-WebRequest -TimeoutSec 20 -UseBasicParsing -Uri 'https://tinuwalther.github.io'
    $Cache:WebRequest2 = Invoke-WebRequest -TimeoutSec 20 -UseBasicParsing -Uri 'https://it.martin-walther.ch'
    $Cache:WebRequest3 = Invoke-WebRequest -TimeoutSec 20 -UseBasicParsing -Uri 'https://foto.martin-walther.ch'
    $Cache:WebRequest4 = Invoke-WebRequest -TimeoutSec 20 -UseBasicParsing -Uri 'https://karin-bonderer.ch'
    $Cache:WebRequest5 = Invoke-WebRequest -TimeoutSec 20 -UseBasicParsing -Uri 'https://dev.cantunada.ch'
    $Cache:WebRequest6 = Invoke-WebRequest -TimeoutSec 20 -UseBasicParsing -Uri 'https://beawalther.wordpress.com'
}
#endregion

#region "PowerShell"
$Page1 = New-UDPage -Name "PowerShell" -Title "Tinus Dashboard" -Content {
    
    New-UDLayout -Columns 1 -Content {  
        
        New-UDTable -Title "Server Information" -Headers @(" ", " ") -Endpoint {

            if($IsWindows){
                $OsSystem    = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
                $datahash = [ordered] @{
                    'Computer Name'       = $env:COMPUTERNAME
                    'Operating System'    = $OsSystem
                    'PowerShell Platform' = $PSVersionTable.Platform
                    'PowerShell Edition'  = $PSVersionTable.PSEdition
                    'PowerShell Version'  = $PSVersionTable.PSVersion.ToString()
                    'PowerShell Home'     = $PSHome
                    'PowerShell Path'     = $(($env:PSModulePath).Replace(';',' - '))
                }
            }
            elseif($IsMacOS){
                $OsSystem    = (system_profiler SPSoftwareDataType | Select-String -pattern 'System Version') -replace '\s'
                $datahash = [ordered] @{
                    'Computer Name'       = hostname
                    'Operating System'    = $OsSystem
                    'PowerShell Platform' = $PSVersionTable.Platform
                    'PowerShell Edition'  = $PSVersionTable.PSEdition
                    'PowerShell Version'  = $PSVersionTable.PSVersion.ToString()
                    'PowerShell Home'     = $PSHome
                    'PowerShell Path'     = $(($env:PSModulePath) -replace ':'," - ")
                }
            }
    
            $datahash.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
        } -Links @( New-UDLink -Text 'Tinus EngOps Wiki' -Url 'https://tinuwalther.github.io/') -BackgroundColor SteelBlue -FontColor White

    }

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

}
#endregion

#region OS Updates"
$Page2 = New-UDPage -Name "OS Updates" -Title "Tinus Dashboard" -Content {
    
    New-UDLayout -Columns 1 -Content {  

        New-UdGrid -Title $UpdateTitle -Endpoint {
            if($IsWindows){
                $Hotfix = @()
                #$Hotfix = Get-CimInstance -Class Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn
                $regexPatchID = '^\d{4}\-\d{2}'
                $regexPatchKB = 'KB\d{6,7}'
                $Session      = New-Object -ComObject Microsoft.Update.Session
                $Searcher     = $Session.CreateUpdateSearcher()
                $HistoryCount = $Searcher.GetTotalHistoryCount()
                $Updates      = $Searcher.QueryHistory(0,$HistoryCount) | Select-Object Title,@{l='Name';e={$($_.Categories).Name}},Date
                $Updates | Select-Object @{Label = "InstalledOn";Expression = {Get-Date ($_.Date) -Format 'yyyy-MM-dd HH:mm:ss'}}, Title | ForEach-Object {
                    $patchID = $_.Title | select-string -Pattern $regexPatchID -AllMatches | ForEach-Object {$_.Matches.Value}
                    $patchKB = $_.Title | select-string -Pattern $regexPatchKB -AllMatches | ForEach-Object {$_.Matches.Value}
                    if($patchID){
                        $obj = [PSCustomObject]@{
                            HotFixID    = $patchKB
                            #UpdateID    = $patchID
                            Description = $_.Title
                            InstalledOn = $_.InstalledOn
                        }
                        $Hotfix += $obj
                    }
                }

                Get-ChildItem -Recurse C:\Windows\SoftwareDistribution\Download | Where-Object PSPath -like "*SSUCompDB_KB*.xml" | ForEach-Object {
                    [xml]$xml =  Get-Content $_.FullName
                    $SSU = $xml.CompDB.Features.Feature
                    if($SSU){
                        $obj = [PSCustomObject]@{
                            HotFixID    = $SSU.FeatureID | select-string -Pattern $regexPatchKB -AllMatches | ForEach-Object {$_.Matches.Value}
                            Description = $SSU.Type
                            InstalledOn = $(Get-Date (Get-Item $_.FullName).CreationTime -Format 'yyyy-MM-dd HH:mm:ss')
                        }
                        $Hotfix += $obj
                    }
                }
                
                Get-CimInstance -Class Win32_QuickFixEngineering | Where-Object Description -match 'Security Update' | Select-Object HotFixID,Description, @{Label = "InstalledOn";Expression = {Get-Date ($_.InstalledOn) -Format 'yyyy-MM-dd HH:mm:ss'}} | foreach {
                    if($Hotfix.HotFixID -notcontains $_.HotFixID){
                        $Hotfix += $_
                    }
                }
                
            }
            elseif($IsMacOS){
                $ret = softwareupdate --history
                $Hotfix  = @()
                for ($i = 2; $i -le $ret.GetUpperBound(0); $i++){
                    $ret[$i] | ForEach-Object {
                        $string = $_ -split '\s+'
                        $Installed = Get-Date "$($string[$string.GetUpperBound(0)-2]) $($string[$string.GetUpperBound(0)-1])" -Format 'yyyy-MM-dd HH:mm:ss'
                        if($string.GetUpperBound(0) -lt 6) {
                            $obj = [PSCustomObject]@{
                                Name      = $string[0]
                                Version   = $string[1]
                                InstalledOn = $Installed
                            }
                            $Hotfix += $obj
                        }
                        elseif($string.GetUpperBound(0) -eq 6) {
                            $obj = [PSCustomObject]@{
                                Name      = "$($string[0]) $($string[1]) $($string[2])"
                                Version   = $string[3]
                                InstalledOn = $Installed
                            }
                            $Hotfix += $obj
                        }
                        elseif($string.GetUpperBound(0) -eq 7) {
                            $obj = [PSCustomObject]@{
                                Name      = "$($string[0]) $($string[1]) $($string[2]) $($string[3]) $($string[4])"
                                Version   = ''
                                InstalledOn = $Installed
                            }
                            $Hotfix += $obj
                        }
                    }
                }
            }
            $Hotfix | Out-UDGridData
        } -Links @(New-UDLink -Text $WebSiteName -Url $WebSiteUrl) -DefaultSortColumn InstalledOn -DefaultSortDescending -BackgroundColor SteelBlue -FontColor White

    #https://www.catalog.update.microsoft.com/Search.aspx?q=
    }

}
#endregion

#region "Process Infos"
$Page3 = New-UDPage -Name "Process Infos" -Title "Tinus Dashboard" -Content { 

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

}
#endregion

#region "Web Tester"
$Page4 = New-UDPage -Name "Web Tester" -Title "Tinus Dashboard" -Content { 

    New-UDLayout -Columns 6 -Content {

        New-UDGrid -Title 'EngOps Wiki' -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest1  | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}} | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Tinus IT Wiki' -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest2 | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}} | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Foto & IT' -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest3 | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}} | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Karins Blog' -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest4 | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}} | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Cantunada' -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest5 | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}} | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

        New-UDGrid -Title 'Steinschmuck' -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest6 | Select-Object @{Name='Status'; Expression = {$_.StatusDescription}},@{Name='LastTest'; Expression = {Get-Date -f 'HH:mm:ss'}} | Out-UDGridData
        } -BackgroundColor SteelBlue -FontColor White -NoFilter -NoExport

    }

    New-UDLayout -Columns 6 -Content {

        New-UDCounter -Title "EngOps Wiki" -Icon linux -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest1 | Select-Object -ExpandProperty StatusCode
        } -BackgroundColor lightgreen -FontColor White
        
        New-UDCounter -Title "Tinus IT Wiki" -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest2 | Select-Object -ExpandProperty StatusCode
        } -Icon linux -BackgroundColor lightgreen -FontColor White
        
        New-UDCounter -Title "Foto & IT" -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest3 | Select-Object -ExpandProperty StatusCode
        } -Icon linux -BackgroundColor lightgreen -FontColor White

        New-UDCounter -Title "Karins Blog" -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest4 | Select-Object -ExpandProperty StatusCode
        } -Icon linux -BackgroundColor lightgreen -FontColor White

        New-UDCounter -Title "Cantunada" -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest5 | Select-Object -ExpandProperty StatusCode
        } -Icon linux -BackgroundColor lightgreen -FontColor White

        New-UDCounter -Title "Steinschmuck" -AutoRefresh -RefreshInterval 300 -Endpoint {
            $Cache:WebRequest6 | Select-Object -ExpandProperty StatusCode
        } -Icon linux -BackgroundColor lightgreen -FontColor White

    }  

    New-UDLayout -Columns 1 -Content {

        New-UDInput -Title "Test Website status" -Endpoint {

            param($WebSiteName) 

            # Get a module from the gallery
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls11,Tls12'
            $WebSiteURI = Invoke-WebRequest -TimeoutSec 20 -Uri "https://$($WebSiteName)"
$CardOutput = @"
$($WebSiteName) returned:

HTTP-Statuscode: $($WebSiteURI.StatusCode)
Status Description: $($WebSiteURI.StatusDescription)

$($WebSiteURI.RawContent | Select-String -Pattern 'Server:\s\S+' -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value)
$($WebSiteURI.RawContent | Select-String -Pattern 'Date:\s\D+\d+\D+\d+\s\d+\:\d+\:\d+\s\w+' -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value)
"@
            # Output a new card based on that info
            New-UDInputAction -Content @(

                New-UDCard -Title "Website status" -Text $CardOutput -Links @(
                        New-UDLink -Text $WebSiteName -Url "https://$($WebSiteName)"
                ) -Size 'small' -BackgroundColor SteelBlue -FontColor White
    
            )
        }

    }

}
#endregion

#region Dashboard
$Dashboard = New-UDDashboard -Pages @($Page1, $Page2, $Page3, $Page4)

Start-UDDashboard -Endpoint $Endpoint -Dashboard $Dashboard -Port 10001 -AutoReload
