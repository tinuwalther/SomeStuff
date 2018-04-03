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

$now     = Get-Date -f 'yyyy-MM-dd HH:mm:ss'
$rootkey = 'hklm:\Software\Company\ServerInfo'
$regkey  = "$rootkey\$now"

if(-not(Test-Path $regkey)){
    New-Item -Path $regkey -Force
}

$hash   = @{
    ComputerName=$($env:computername)
    InstallDate=$(Get-Date)
}

Set-RegItemProperty -values $hash -Root $regkey -verbose

$array   = @(
    'ComputerName',
    'InstallDate'
)

$childitems = Get-ChildItem -Path $rootkey
foreach($item in $childitems){
    Get-RegItemPropertyValue -Names $array -Root  $($item.Name -replace 'HKEY_LOCAL_MACHINE', 'hklm:') -verbose
}
