<#
.SYNOPSIS
    A short one-line action-based description, e.g. 'Tests if a function is valid'

.DESCRIPTION
    A longer description of the function, its purpose, common use cases, etc.

.NOTES
    Information or caveats about the function e.g. 'This function is not supported in Linux'

.LINK
    https://pode.readthedocs.io/en/latest/Tutorials/OpenAPI/#default-setup

.EXAMPLE
    $body = @{
        name     = 'lnx1234'
        os       = 'Red Hat'
        version  = '8'
        ipv4addr = '10.26.0.34'
        subnet   = '255.255.255.0'
        owner    = 'tinu'
        action   = 'create'
    } | ConvertTo-Json -Compress

    $Properties = @{
        Method = 'POST'
        Uri    = "http://localhost:8080/api/vm/$($body)"
    }

    Invoke-RestMethod @Properties

#>
[CmdletBinding()]
param()

function Get-MWASecretsFromVault{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$Vault
    )

    if(-not(Test-SecretVault -Name $Vault)){
        Unlock-SecretVault -Name $Vault
    }
    
    $SecretInfo = Get-SecretInfo -Vault $Vault -WarningAction SilentlyContinue
    $ret = $SecretInfo | ForEach-Object {
        $Tags = foreach($item in $_.Metadata.keys){
            if($item -match 'Tags'){
                $($_.Metadata[$item])
            }
        }
        $Accessed = foreach($item in $_.Metadata.keys){
            if($item -match 'Accessed'){
                $($_.Metadata[$item])
            }
        }
        $ApiUri = foreach($item in $_.Metadata.keys){
            if($item -match 'URL'){
                $($_.Metadata[$item])
            }
        }
        [PSCustomObject]@{
            Name     = $_.Name
            ApiUri   = $ApiUri
            Tag      = $Tags
            Accessed = $Accessed
        }
    }
    return $ret
}

function Send-TelegramMessage{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String] $ApiUri,
    
        [Parameter(Mandatory=$false)]
        [Switch]$Html,
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object] $Message,
    
        [Parameter(Mandatory=$false)]
        [Int] $ChatID,
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object] $PSOctomes
    )
    
    begin {
        $StartTime = Get-Date
        $function = $($MyInvocation.MyCommand.Name)
        Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ Begin   ]', $function -Join ' ')
        $ret = $null
    }
    
    process {
        Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ Process ]', $function -Join ' ')
    
        try{
    
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            if($Html){
                $ParseMode = 'html'
            }else{
                $ParseMode = 'MarkdownV2'
            }
    
            $ChatID  = $PSOctomes | Where-Object User -eq Telegram_ChatId | Select-Object -ExpandProperty Token
            $payload = @{
                "chat_id"                   = $ChatID
                "text"                      = $Message
                "parse_mode"                = $ParseMode
                "disable_web_page_preview"  = $false
                "disable_notification"      = $false
            }
            Write-Verbose "Payload:"
            Write-Verbose "$($payload | Out-String)"
        
            $Token  = $PSOctomes | Where-Object User -eq Telegram_Token | Select-Object -ExpandProperty Token
            $ApiUri = $PSOctomes | Where-Object User -eq Telegram_Token | Select-Object -ExpandProperty ApiUri
            $Properties = @{
                Uri         = "$($ApiUri)$($Token)/sendMessage" #"https://api.telegram.org/bot$($Token)/sendMessage"
                Body        = (ConvertTo-Json -Depth 6 -InputObject $payload)
                Method      = 'POST'
                ContentType = 'application/json; charset=UTF-8'
                ErrorAction = 'Stop'
            }
    
            $ret = Invoke-RestMethod @Properties
    
            Write-Host "$($function)"
            $ret | Out-String
    
        }catch{
            Write-Warning $('ScriptName:', $($_.InvocationInfo.ScriptName), 'LineNumber:', $($_.InvocationInfo.ScriptLineNumber), 'Message:', $($_.Exception.Message) -Join ' ')
            $ret = $($_.Exception.Message)
            $Error.Clear()
        }
    }
    
    end {
        Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ End     ]', $function -Join ' ')
        $TimeSpan  = New-TimeSpan -Start $StartTime -End (Get-Date)
        $Formatted = $TimeSpan | ForEach-Object {
            '{1:0}h {2:0}m {3:0}s {4:000}ms' -f $_.Days, $_.Hours, $_.Minutes, $_.Seconds, $_.Milliseconds
        }
        Write-Verbose $('Finished in:', $Formatted -Join ' ')
        return $ret
    }
    
}

function Test-Output{
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 0
        )]
        $OutputObject
    )
    Write-Host "`nI get the following input to proceed:`n"
    Write-Host "$(($OutputObject | Out-String).Trim())`n" -ForegroundColor Cyan

    if($OutputObject -is [PSCustomObject]){
        Write-Host "$(($OutputObject.Gettype() | Out-String).Trim())`n" -ForegroundColor Cyan  
        try{
            $Data = $OutputObject | Select-Object -Expandproperty Data -ErrorAction Stop
            Write-Host "Check sub-object"
            if($Data.Gettype().Name -eq 'PSCustomObject'){
                Write-Host "$(($Data.Gettype() | Out-String).Trim())`n" -ForegroundColor Cyan
            }elseif($Data.Gettype().Name -eq 'String'){
                Write-Host "$(($Data.Gettype() | Out-String).Trim())`n" -ForegroundColor Cyan
                $Data = $Data | ConvertFrom-Json
            }
            Write-Host "OS         : $($Data.os)"
            Write-Host "Name       : $($Data.name)"
            Write-Host "Subnet     : $($Data.subnet)"
            Write-Host "Owner      : $($Data.owner)"
            Write-Host "Action     : $($Data.action)"    
        }catch{
            Write-Host "No sub-object" -ForegroundColor Yellow
            $Error.Clear()
        }
    }else{
        Write-Warning "InputObject is not a PSCustomObject"
    }

}

function Invoke-PodeJsonResponse{
    <#
    .SYNOPSIS
        Retrieve Pode-Response as JSON

    .DESCRIPTION
        Rest-Method to retrieve a Pode-Response as JSON

    .PARAMETER ApiUri
        URI of the API Route, for example http://localhost:8080/api/vm/

    .PARAMETER ApiData
        Data as JSON-String, for example "{ 'name': 'lnx1234', 'os': 'Red Hat' }"

    .EXAMPLE
        Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/vm/"{ name: 'lnx1234', os: 'Red Hat', ipv4addr: '10.26.0.34', subnet: '255.255.255.0', owner: 'tinu' }"
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = 'http://localhost:8080/api/vm',
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 0
        )]
        [String]$ApiUri,

        [Parameter(
            HelpMessage = '{ name: "lnx1234", os: "Red Hat", ipv4addr: "10.24.5.18", subnet: "255.255.255.0", owner: "tinu" }',
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 1
        )]
        [String]$ApiData
    )

    begin{
        $StartTime = Get-Date
        $function = $($MyInvocation.MyCommand.Name)
        Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ Begin   ]', $function -Join ' ')
    }

    process{
        Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ Process ]', $function -Join ' ')
        try{

            Add-PodeRoute -Method Post -Path "$($ApiUri)/$($ApiData)" -Authentication 'Validate' -ScriptBlock {

                $ret = [PSCustomObject]@{
                    TimeStamp = Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'
                    Uuid      = (New-Guid | Select-Object -ExpandProperty Guid)
                    Source    = $env:COMPUTERNAME
                    Data      = ($WebEvent.Parameters['json']) | ConvertFrom-Json
                }

                Test-Output -OutputObject $ret

                #region Secret
                # $SecretVault  = 'PSOctomes'
                # $AllSecrets   = Get-MWASecretsFromVault -Vault $SecretVault
                # $SecretObject = foreach($item in $AllSecrets){
                #     try{
                #         $Secret = Get-Secret -Vault $SecretVault -Name $item.Name -ErrorAction Stop
                #         [PSCustomObject]@{
                #             Name   = $item.Name
                #             User   = $Secret.UserName
                #             ApiUri = $item.ApiUri
                #             Token = [System.Net.NetworkCredential]::new($Secret.UserName, $Secret.Password).Password
                #         }
                #     }catch{
                #         $Error.Clear()
                #     }
                # }                
                # Send-TelegramMessage -Message $ret -Html -PSOctomes $SecretObject
                #endregion

                Write-PodeJsonResponse -Value $ret

            } -PassThru | Test-Output

        }catch{
            Write-Warning $('ScriptName:', $($_.InvocationInfo.ScriptName), 'LineNumber:', $($_.InvocationInfo.ScriptLineNumber), 'Message:', $($_.Exception.Message) -Join ' ')
            $Error.Clear()
        }
    }

    end{
        Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ End     ]', $function -Join ' ')
        $TimeSpan  = New-TimeSpan -Start $StartTime -End (Get-Date)
        $Formatted = $TimeSpan | ForEach-Object {
            '{1:0}h {2:0}m {3:0}s {4:000}ms' -f $_.Days, $_.Hours, $_.Minutes, $_.Seconds, $_.Milliseconds
        }
        Write-Verbose $('Finished in:', $Formatted -Join ' ')
        return $ret
    }

}

Start-PodeServer {

    New-PodeLoggingMethod -Terminal | Enable-PodeRequestLogging

    # setup basic auth (base64> username:password in header)
    New-PodeAuthScheme -Basic -Realm 'Pode Example Page' | Add-PodeAuth -Name 'Validate' -Sessionless -ScriptBlock {
        param($username, $password)
        # here you'd check a real user storage, this is just for example
        if ($username -eq 'morty' -and $password -eq 'pickle') {
            return @{
                User = @{
                    Name = 'Superman'
                }
            }
        }
        return @{ Message = 'Invalid details supplied' }
    }

    Write-Host "Running Pode server on $($PSScriptRoot)" -ForegroundColor Cyan
    Write-Host "Press Ctrl. + C to terminate the Pode server" -ForegroundColor Yellow

    Add-PodeEndpoint -Address localhost -Port 8080 -Protocol Http

    Invoke-PodeJsonResponse -ApiUri '/api/vm' -ApiData ':json'

}
