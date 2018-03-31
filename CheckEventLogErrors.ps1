$HTMLHeader = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>Systems Report</title>
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
</html>
"@

$ret = @()
[DateTime]$now    = Get-Date
[DateTime]$after  = $now.AddDays(-2)
[DateTime]$before = $now

<# Get Unexpected Shutdowns 6008 or System Crashes 1001 of the las 30 days
$Logname          = 'System'
$SystemRet = @()
try{
    Get-EventLog $Logname -InstanceId 1001, 6008 -EntryType Error -After $after -Before $before -ErrorAction SilentlyContinue | %{
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
catch{
    $Error.Clear()
}
#>

# Get all Errors of the last X days
$Logname          = 'System'
$SystemRet = @()
try{
    Get-EventLog $Logname -EntryType Error, Warning -After $after -Before $before -ErrorAction SilentlyContinue | %{
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
catch{
    $Error.Clear()
}

$Logname          = 'Application'
$ApplicationRet   = @()
try{
    Get-EventLog $Logname -EntryType Error, Warning -After $after -Before $before -ErrorAction SilentlyContinue | %{
        $obj = [PSCustomObject]@{
            Logname       = $Logname
            TimeGenerated = $_.TimeGenerated
            EventID       = $_.EventID
            EntryType     = $_.EntryType
            Message       = $_.Message
        }
        $ApplicationRet += $obj
    }
}
catch{
    $Error.Clear()
}

$SystemEventsReport      = $SystemRet      | Sort-Object TimeGenerated | ConvertTo-Html -Fragment 
$ApplicationEventsReport = $ApplicationRet | Sort-Object TimeGenerated | ConvertTo-Html -Fragment 

$HTMLMiddle = @"
<h2>Events Report - The System/Application Log Events between $after and $before that were Warnings or Errors</h2>
<p>The following is a list of the last <b>System log</b> events that had an Event Type of either Warning or Error.</p>
<table class="normal">$SystemEventsReport</table>

<p>The following is a list of the last <b>Application log</b> events that had an Event Type of either Warning or Error.</p>
<table class="normal">$ApplicationEventsReport</table>
"@

$HTMLmessage = $HTMLHeader + $HTMLMiddle + $HTMLEnd
$HTMLmessage | Out-File -FilePath "$($env:TEMP)\Logreport.html" -Force

"$($env:TEMP)\Logreport.html"
