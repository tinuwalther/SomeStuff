if($IsWindows){
    $psCredentials   = Get-Credential -Message 'Enter your credentials'
    $strComputerName = 'BigServer'
            
    $cims = New-CimSession -ComputerName $strComputerName -Credential $psCredentials -Authentication Negotiate

    $aryDNSSuffixes = @((Get-DnsClientGlobalSetting -CimSession $cims).SuffixSearchList)
    $aryDNSSuffixes += 'whatever.local'

    Set-DnsClientGlobalSetting -SuffixSearchList $aryDNSSuffixes -CimSession $cims
}

if($IsMacOS){
    scutil --dns | Select-String -Pattern 'search domain'
    (Get-Content -Path '/etc/resolv.conf' | Select-String -Pattern 'search\s\S+') -replace 'search\s'
}

if($IsLinux){
    Get-Content -Path '/etc/sysconfig/network-scripts/ifcfg-eth0'
    Get-Content -Path '/etc/resolv.conf'
    #DOMAIN="domain.com sub.domain.com"
}
