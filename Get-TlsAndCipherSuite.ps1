function Get-RegValue {
    [CmdletBinding()]
    Param
    (
        # Registry Path
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$RegPath,

        # Registry Name
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$RegName
    )
	try{
		$RegItem = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Stop
		if($RegItem.$RegName -eq 1){$RegValue = $true}else{$RegValue = $false}
		[PSCustomObject]@{
			Path  = $RegPath
			Name  = $RegName
			Value = $RegValue
		}
	}catch{
		Write-Verbose "$RegPath not found"
		$Error.clear()
	}
}

$regSettings = @()
$regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
$regSettings += Get-RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
$regSettings += Get-RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
$regSettings += Get-RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
$regSettings += Get-RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
$regSettings += Get-RegValue $regKey 'Enabled'
$regSettings += Get-RegValue $regKey 'DisabledByDefault'

$regSettings

Get-TlsCipherSuite | Format-Table Name, Cipher*, Exchange

function Get-RegistryProperties{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
		[String] $Hive
    )

    if(Test-path -Path $hive){
        $root = Get-Item $hive
        $ret = foreach($subkey in $root.GetSubKeyNames()){
            $items = Get-Item "$hive\$subkey"
            if($items.subkeycount -eq 0){
                foreach($prop in $items.Property){
                    [PSCustomObject]@{
                        Hive     = $hive
                        Name     = $items.PSChildName
                        Property = $prop
                        Value    = Get-ItemPropertyValue -Path ("$hive\$subkey") -Name ($prop)
                    }
                }
            }
            else{
                Get-RegistryProperties -hive "$hive\$subkey"
            }
        }
    }
    return $ret
}

Get-RegistryProperties -Hive 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' | Sort-Object Hive, Name | Format-Table
