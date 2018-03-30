function Get-ExpiredCertificates{
    [CmdletBinding()]
    param()
    $function = $($MyInvocation.MyCommand.Name)
    $ret = $null
    try{
        $ret = Get-ChildItem Cert:\LocalMachine\Root -ExpiringInDays 0
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

Get-ExpiredCertificates | Select-Object Thumbprint,FriendlyName,Issuer,NotBefore,NotAfter
