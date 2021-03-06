<#
  From a MemoryDump I returned the Crash-date as Sun May 28 00:30:51.221 2017 (UTC + 2:00),
  but I need a normal DateTime-Object, so wtf should I do? Do It with RegEx!!!
#>

$contentString = 'Sun May 28 00:30:51.221 2017 (UTC + 2:00)'
$regexString   = '^\w{1,3}\s\w{1,3}\s\d{1,2}\s\d{1,2}\:\d{1,2}\:\d{1,2}\.\d{1,3}\s\d{4}'

$regexDayMonth = '^\w{1,3}\s\w{1,3}\s\d{1,2}'
$regexYear     = '\s\d{4}\s'
$regexTime     = '\d{1,2}\:\d{1,2}\:\d{1,2}\.\d{1,3}'

$retDayMonth   = $contentString | Select-String -Pattern $regexDayMonth -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value
$retYear       = $contentString | Select-String -Pattern $regexYear     -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value
$retTime       = $contentString | Select-String -Pattern $regexTime     -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value

$retDateString = $retDayMonth + $retYear + $retTime -join ' '
Get-Date($retDateString)

<#
  Search User with SID
#>
$regexString   = '^S-1-5-21-\d{10}-\d{10}-\d{10}-500$' or '^S\-1\-5\-21\-(\d+-){1,14}500$'
$contentString = (Get-LocalUser | Where SID -match $regexString).SID
$contentString | Select-String -Pattern $regexString -AllMatches
