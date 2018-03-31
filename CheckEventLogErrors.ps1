$HTMLHeader = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html>
<head>
<title>Systems Report</title>
<h2>Computer $($env:COMPUTERNAME)</h2>
<hr/>
<style>
    html, body, form, fieldset, table, tr, td, img {margin: 1;padding: 1;font: 96%/150% arial,helvetica,sans-serif;text-align:left;}
    TABLE{width:100%;border-width: 2px;border-style: solid;border-color: white;border-collapse: collapse;text-align:left;}
    TH{border-width: 2px;padding: 2px;border-style: solid;border-color: white;background-color:#80BFFF;text-align:left;}
    TD{border-width: 2px;padding: 2px;border-style: solid;border-color: white;background-color:#F5F6CE;text-align:left;}
    TR:hover td{Background-Color: red;Color:white;}
</style>
</head>
<body>
<div>
"@

$HTMLEnd = @"
</div>
</body>
<footer>
<hr/>
<p>Copyright &#169 2018 <a href="https://it.martin-walther.ch" target="_blank"> it.martin-walther.ch</a></p>
</footer>
</html>
"@


function Get-LastEventCodes{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Logname,
        [Parameter(Mandatory=$true)][Int]$day
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


<# Get Unexpected Shutdowns 6008 or System Crashes 1001 of the las 30 days
$Logname          = 'System'
$SystemRet = @()
try{
    Get-EventLog $Logname -InstanceId 1001, 6008 -EntryType Error -After $after -Before $before -ErrorAction SilentlyContinue | %{
        if($SystemRet.EventID -notcontains $_.EventID){
            $obj = [PSCustomObject]@{
                Logname       = $Logname
                TimeGenerated = $_.TimeGenerated
                EventID       = $_.EventID
                EntryType     = $_.EntryType
                Message       = $_.Message
            }
            $SystemRet += $obj
        }
    }
}
catch{
    $Error.Clear()
}
#>

$lastdays = 2
$SystemEventsReport      = Get-LastEventCodes -Logname System      -day $lastdays -Verbose | Sort-Object TimeGenerated -Descending | ConvertTo-Html -Fragment 
$ApplicationEventsReport = Get-LastEventCodes -Logname Application -day $lastdays -Verbose | Sort-Object TimeGenerated -Descending | ConvertTo-Html -Fragment 

$HTMLMiddle = @"
<div>
<h3>System Log with Warnings or Errors</h3>
<p>The following is a list of the last <b>System log</b> of the <b>last $lastdays days</b> that had an Event Type of either Warning or Error.</p>
<table class="normal">$SystemEventsReport</table>
</div>
<div>
<h3>Application Log with Warnings or Errors</h3>
<p>The following is a list of the last <b>Application log</b> of the <b>last $lastdays days</b> that had an Event Type of either Warning or Error.</p>
<table class="normal">$ApplicationEventsReport</table>
</div>
"@

$HTMLmessage = $HTMLHeader + $HTMLMiddle + $HTMLEnd
$HTMLmessage | Out-File -FilePath "$($env:TEMP)\Logreport.html" -Force

start "$($env:TEMP)\Logreport.html"
