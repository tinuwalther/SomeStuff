#https://www.w3schools.com/css/css_align.asp

$HTMLHeader = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html>
<head>
<title>Systems Report</title>
<h1>Computer $($env:COMPUTERNAME)</h1>
<style>

html, body, form, fieldset, table, th, tr, td, img {
    margin: 2;
    padding: 2;
    font: 96%/150% arial,helvetica,sans-serif;
    text-align:left;
}

h1 {
    text-align: center;
    color: white;
    text-shadow: 2px 2px 4px #000000;
    border-radius: 25px;
    background-color: #A9F5A9;
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
<div>
"@

$HTMLEnd = @"
</div>
</body>
<div>
<footer>
<p>Copyright &#169 2018 <a href="https://it.martin-walther.ch" target="_blank"> it.martin-walther.ch</a></p>
</footer>
</div>
</html>
"@

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

function Set-HtmlMiddle{
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
$LogsToCheck = @(
    'System',
    'Setup',
    'Application'
)

foreach($item in $LogsToCheck){
    $records = Get-LastEventCodes -Logname $item -day $lastdays -Verbose
    if(-not([String]::IsNullOrEmpty($records))){
        $htmlTable = $records | Sort-Object TimeGenerated -Descending | ConvertTo-Html -Fragment 
        $HTMLMiddle += Set-HtmlMiddle -Logname $item -lastdays $lastdays -htmlTable $htmlTable 
    }
}

$HTMLmessage = $HTMLHeader + $HTMLMiddle + $HTMLEnd
$HTMLmessage | Out-File -FilePath "$($env:TEMP)\Logreport.html" -Force

start "$($env:TEMP)\Logreport.html"
