
$psCredentials   = Get-Credential -Message 'Enter your credentials'
$strComputerName = 'BigServer'

$aryDNSSuffixes  = 

Invoke-WmiMethod -Class win32_networkadapterconfiguration -Name setDNSSuffixSearchOrder -Credential $psCredentials -ComputerName $strComputerName -ArgumentList @($aryDNSSuffixes), $null

$nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
foreach($adapter in $nics){
    $adapter.GetIPProperties()
}


$cims = New-CimSession -ComputerName Server01 -Credential $cred -Authentication Negotiate
Get-DnsClientGlobalSetting -CimSession $cims
Set-DnsClientGlobalSetting -SuffixSearchList @("corp.contoso.com", "na.corp.contoso.com") -CimSession $cims
