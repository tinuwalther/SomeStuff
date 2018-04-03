function Set-RegItemProperty{
    [CmdletBinding()]
    param(
        [hashtable]$values,
        [String]   $Root
    )
    try{
        foreach($item in $values.keys){
            Set-ItemProperty -Path $Root -Name $($item) -Value $($values[$item]) -Force -ErrorAction Stop
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
}

function Get-RegItemPropertyValue{
    [CmdletBinding()]
    param(
        [array]  $Names,
        [String] $Root
    )
    try{
        foreach($item in $Names){
            $ret += @{$($item)=Get-ItemPropertyValue -Path $Root -Name $($item) -ErrorAction Stop} 
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

$regkey = 'hklm:\Software\Company\ServerInfo'
$hash   = @{
    ComputerName=$($env:computername)
    InstallDate=$(Get-Date)
}

Set-RegItemProperty -values $hash -Root $regkey -verbose

$array   = @(
    'ComputerName',
    'InstallDate'
)

Get-RegItemPropertyValue -Names $array -Root $regkey -verbose
