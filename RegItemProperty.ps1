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

function Get-RegItemPropertyNames{
    [CmdletBinding()]
    param(
        [array]  $Names,
        [String] $Root
    )
    try{
        $ret = @()
        foreach($item in $Names){
            $ret += $($item)
        }
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

function Get-RegChildItemNames{
    [CmdletBinding()]
    param(
        [String] $Root
    )
    try{
        $ret = $null
        $ret = Get-ChildItem -Path $Root | Select-Object -ExpandProperty PSChildName
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
    }
    return $ret
}

function Get-RegItemPropertyValues{
    [CmdletBinding()]
    param(
        [array]  $Names,
        [String] $Root
    )
    try{
        $ret = @()
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
    Mode='Managed'
}

Set-RegItemProperty -values $hash -Root $regkey -verbose

$array   = @(
    'ComputerName',
    'InstallDate',
    'Mode'
)

$newest     = @()
$now        = Get-Date
$childitems = Get-RegChildItemNames -Root $rootkey -Verbose
foreach($item in $childitems){
    @{$item=(New-TimeSpan –Start (Get-Date $item) –End $now | Select-Object -ExpandProperty Ticks)}
    #Get-RegItemPropertyNames  -Names $array -Root $("$rootkey\$item") -verbose
    #Get-RegItemPropertyValues -Names $array -Root $("$rootkey\$item") -verbose
}
