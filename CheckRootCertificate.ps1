function Get-ExpiredCertificates{
    [CmdletBinding()]
    param()
    $function = $($MyInvocation.MyCommand.Name)
    $ret = $null
    try{
        $ret = Get-ChildItem Cert:\ -ExpiringInDays 0 -Recurse
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

Get-ExpiredCertificates | Select-Object Thumbprint,FriendlyName,DnsNameList,Issuer,NotBefore,NotAfter,PSPath
