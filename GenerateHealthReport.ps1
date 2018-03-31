#https://www.w3schools.com/css/css_align.asp

$HTMLHeader = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html>
<head>
<title>System Report</title>
<h1 id="home">Health report of computer $($env:COMPUTERNAME)</h1>
<style>

html, body, form, fieldset, table, th, tr, td, img {
    margin: 2;
    padding: 2;
    font: 96%/150% arial,helvetica,sans-serif;
    text-align:left;
}

ul {
    list-style-type: none;
    margin: 0;
    padding: 0;
    overflow: hidden;
    background-color: #333;
    position: -webkit-sticky; /* Safari */
    position: sticky;
    top: 0;
}

li {
    float: left;
}

li a {
    display: block;
    color: white;
    text-align: center;
    padding: 14px 16px;
    text-decoration: none;
}

li a:hover:not(.active) {
    background-color: #4CAF50;
}

.active {
    background-color: #4CAF50;
}

h1 {
    text-align: center;
    color: white;
    text-shadow: 2px 2px 4px #000000;
    border-radius: 25px;
    background-color: #4CAF50;
    padding: 25px;
}

table {
    border-collapse: collapse;
}

td, th {
    border: 1px solid white;
    padding: 5px;
}

th {
    background-color: #80BFFF; 
    color: white;
}

td {
    border: 1px solid white;
    vertical-align: top;
    padding: 5px;
}

tr:nth-child(even){
    background-color: #F5F6CE;
}

tr:nth-child(odd){
    background-color: #FBFBEF;
}

tr:hover td{
    Background-Color: red;
    Color:white;
}

footer {
    background-color: #A9F5A9;
    text-align: center;
    Color:white;
    border-radius: 25px;
    margin: 5px;
}
</style>
</head>
<body>
<ul>
  <li><a class="active" href="#home">Home</a></li>
  <li><a href="#uptime">Uptime</a></li>
  <li><a href="#memory">Memory</a></li>
  <li><a href="#disks">Disks</a></li>
  <li><a href="#logs">Eventlogs</a></li>
  <li><a href="#services">Services</a></li>
  <li><a href="#about">About</a></li>
</ul>
<div>
"@

$HTMLEnd = @"
</div>
</body>
<div>
<footer>
<p id="about">Copyright &#169 2018 <a href="https://it.martin-walther.ch" target="_blank"> it.martin-walther.ch</a></p>
</footer>
</div>
</html>
"@

function Get-HostUptime {
    [CmdletBinding()]
    param(
    )
    $function = $($MyInvocation.MyCommand.Name)
    $ret = @()
    try{
	    $Uptime = Get-WmiObject -Class Win32_OperatingSystem
	    $LastBootUpTime = $Uptime.ConvertToDateTime($Uptime.LastBootUpTime)
	    $Time = (Get-Date) - $LastBootUpTime
        $obj = [PSCustomObject]@{
            Days    = "{0:00}" -f $Time.Days
            Hours   = "{0:00}" -f $Time.Hours
            Minutes = "{0:00}" -f $Time.Minutes
            Seconds = "{0:00}" -f $Time.Seconds
        }
        $ret  += $obj
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

function Get-Raminfo{
    [CmdletBinding()]
    param()
    $function = $($MyInvocation.MyCommand.Name)
    $ret = @()
    try{
	    Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | %{
            $TotalRamMB    = [math]::round(($_.TotalVisibleMemorySize/(1024*1024)),2)
            $FreeRamMB     = [math]::round(($_.FreePhysicalMemory/(1024*1024)),2)
            $obj = [PSCustomObject]@{
                TotalRamGB     = $TotalRamMB
                FreeRamGB      = $FreeRamMB
                UsedRamGB      = $TotalRamMB - $FreeRamMB
                RamPercentFree = [math]::round((($FreeRamMB / $TotalRamMB) * 100),2)
            }
            $ret  += $obj
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

function Get-Diskinfo{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][Int]$thresholdspace
    )
    $function = $($MyInvocation.MyCommand.Name)
    $ret = @()
    try{
	    Get-WMIObject Win32_LogicalDisk -ErrorAction Stop| Where-Object{$_.DriveType -eq 3} | Where-Object{ ($_.freespace/$_.Size)*100 -lt $thresholdspace} | %{
            $obj = [PSCustomObject]@{
                Name        = $_.Name
                TotalSizeGB = [math]::round(($_.size/1gb),2)
                FreeSpaceGB = [math]::round(($_.freespace/1gb),2)
                PercentFree = [math]::round(($_.freespace/$_.size*100),2)
            }
            $ret  += $obj
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

function Get-LastEventCodes{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Logname,
        [Parameter(Mandatory=$true)][Int]   $day
    )
    $function = $($MyInvocation.MyCommand.Name)
    $ret = @()
    [DateTime]$now    = Get-Date
    [DateTime]$after  = $now.AddDays(-$day)
    [DateTime]$before = $now
    try{
        Get-EventLog $Logname -EntryType Error, Warning -After $after -Before $before -ErrorAction Stop | %{
            if($ret.EventID -notcontains $_.EventID){
                $obj = [PSCustomObject]@{
                    Logname       = $Logname
                    TimeGenerated = $_.TimeGenerated
                    EventID       = $_.EventID
                    EntryType     = $_.EntryType
                    Message       = $_.Message
                }
                $ret += $obj
            }
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

function Get-StoppedServices{
    [CmdletBinding()]
    param(
    )
    $function = $($MyInvocation.MyCommand.Name)
    $ret = @()
    try{
        Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object StartMode -eq 'Auto' | Where-Object State -eq 'Stopped' | %{
            $obj = [PSCustomObject]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                Status      = $_.Status
                State       = $_.State
                StartMode   = $_.StartMode
                StartName   = $_.StartName
                Description = $_.Description
            }
            $ret += $obj
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

function Set-HtmlMiddleEventlog{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Logname,
        [Parameter(Mandatory=$true)][Int]   $lastdays,
        [Parameter(Mandatory=$true)][Object]$htmlTable
    )
    $function = $($MyInvocation.MyCommand.Name)
    $ret = $null
    try{
$ret += @"
<div>
<h3>$Logname Log with Warnings or Errors</h3>
<p>The following is a list of the <b>$Logname log</b> for the <b>last $lastdays days</b> that had an Event Type of either Warning or Error.</p>
<table>$htmlTable</table>
</div>
"@
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret

}

$lastdays    = 2
$HTMLMiddle  = $null

#region HostUptime
$HTMLMiddle  += '<h2 id="uptime">Uptime</h2>'
$htmlTable   = Get-HostUptime | ConvertTo-Html -Fragment 
$HTMLMiddle  += @"
<div>
<p>The following is the <b>last boot-time</b> for the computer.</p>
<table>$htmlTable</table>
</div>
"@
#endregion

#region Memory
$HTMLMiddle  += '<h2 id="memory">Memory</h2>'
$htmlTable   = Get-Raminfo -Verbose | ConvertTo-Html -Fragment 
$HTMLMiddle  += @"
<div>
<p>The following list the memory usage.</p>
<table>$htmlTable</table>
</div>
"@
#endregion

#region Diskinfo
$PercentFree  = 50
$HTMLMiddle  += '<h2 id="disks">Disks</h2>'
$htmlTable   = Get-Diskinfo -thresholdspace $PercentFree -Verbose | ConvertTo-Html -Fragment 
$HTMLMiddle  += @"
<div>
<p>The following list the disks with <b>less than $PercentFree%</b> free space.</p>
<table>$htmlTable</table>
</div>
"@
#endregion

#region Eventlogs
$HTMLMiddle  += '<h2 id="logs">Eventlogs</h2>'
$LogsToCheck = @(
    'System',
    'Setup',
    'Application'
)

foreach($item in $LogsToCheck){
    $records = Get-LastEventCodes -Logname $item -day $lastdays -Verbose
    if(-not([String]::IsNullOrEmpty($records))){
        $records | Sort-Object TimeGenerated -Descending | ConvertTo-Json | ConvertFrom-Json
        $htmlTable = $records | Sort-Object TimeGenerated -Descending | ConvertTo-Html -Fragment 
        $HTMLMiddle += Set-HtmlMiddleEventlog -Logname $item -lastdays $lastdays -htmlTable $htmlTable 
    }
}
#endregion

#region Services
$HTMLMiddle  += '<h2 id="services">Services</h2>'
$htmlTable   = Get-StoppedServices -Verbose | ConvertTo-Html -Fragment 
$HTMLMiddle  += @"
<div>
<p>The following is a list of all <b>stopped services</b> with start-mode <b>automatic</b>.</p>
<table>$htmlTable</table>
</div>
"@
#endregion

$HTMLmessage = $HTMLHeader + $HTMLMiddle + $HTMLEnd
$HTMLmessage | Out-File -FilePath "$($env:TEMP)\Logreport.html" -Force

start "$($env:TEMP)\Logreport.html"
