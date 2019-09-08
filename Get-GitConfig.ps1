function Get-GitConfig{

    [CmdletBinding()]

    $function = $($MyInvocation.MyCommand.Name)
    Write-Verbose "Running $function"

    $ret = -404
    try{
        $ret = @(git config --list | ForEach-Object {
            $item = $_ -split '='
            $name  = $item[0]
            $value = $item[1]
            @{Property = @{$name=$value}}
        })
    }
    catch{
        Write-Host "$($function): $($_.Exception.Message)" -ForegroundColor Yellow
        $error.Clear()
        $ret = -400
    }
    return $ret

}

(Get-GitConfig).Property.'user.name'