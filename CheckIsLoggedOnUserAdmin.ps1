function Test-IsUserMemberOfAdmin{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][String]$LocalAccount
    )
    $function = $($MyInvocation.MyCommand.Name)
    $ret = $false
    try{
        $Administrators = Get-LocalGroupMember -SID S-1-5-32-544  
        if($Administrators.Name -match $LocalAccount){   
            $ret = $true   
        }     
    }
    catch{
        Write-verbose "$($function): $($_.Exception.Message)"
        $Error.Clear()
        $ret = $false
    }
    return $ret
}

$LoggedOnUsers = (Get-CimInstance Win32_LoggedOnUser).antecedent.name | Select-Object -Unique
foreach($item in $LoggedOnUsers){ 
    if(Test-IsUserMemberOfAdmin -LocalAccount "$($env:ComputerName)\\$item"){
        @{LocalAdmin=$item}
    }
}
