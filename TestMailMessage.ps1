<#
.Synopsis
   Test-SuspectedMailMesssage

.DESCRIPTION
   Test unreaded MailMesssage for non-swisscom-sender and http-links

.NOTES
   SenderEmailType: SMTP von extern, EX von Exchange intern

.EXAMPLE
   Test-SuspectedMailMesssage

#>

function Test-SuspectedMailMesssage{
    [CmdletBinding()]
    Param()

    Begin
    {
        Add-Type -AssemblyName "Microsoft.Office.Interop.Outlook"
        $OutlookFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]

        $outlook    = New-Object -ComObject outlook.application
        $namespace  = $outlook.GetNameSpace("MAPI")
        $inbox      = $namespace.GetDefaultFolder($OutlookFolders::olFolderInbox)
        $HttpRegex  = 'href\=\"http\:\/\/\S+\"'
        $StartTime  = Get-Date
        $FirstRTime = $StartTime.AddDays(-5)

        $ret = @()
    }
    Process
    {
        $Message = $inbox.Items.Restrict("[UnRead] = True AND [SenderEmailType] = 'SMTP'") |
         Where-Object SenderEmailAddress -NotMatch '@swisscom.com' | 
         Where-Object HTMLBody -Match $HttpRegex | 
         Select-Object -Property EntryID,ReceivedTime,Subject,SenderName,SenderEmailType,SenderEmailAddress,HTMLBody |
         Sort-Object ReceivedTime -Descending |
         Select-Object -First 1
        
        if($Message){
            $Message | ForEach-Object {
                if(($_.ReceivedTime) -gt $FirstRTime){

                    Write-Host "Suspected mail detected from $($_.SenderName)" -ForegroundColor Yellow

                    $Message | ForEach-Object {
                        $obj = [PSCustomObject]@{
                            ReceivedTime       = $_.ReceivedTime
                            Subject            = $_.Subject
                            SenderName         = $_.SenderName
                            SenderEmailType    = $_.SenderEmailType
                            SenderEmailAddress = $_.SenderEmailAddress
                            FoundHttpBody      = $_ | Select-String -Pattern $HttpRegex -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value
                        }
                        $ret += $obj
                    }

                    #Write-Host "Run-time: $(New-TimeSpan –Start $StartTime –End (Get-Date))"

                }
            }
        }
    }
    End
    {
        return $ret
    }
}

<#
.Synopsis
   Show-BalloonTip

.DESCRIPTION
   Show-BalloonTip

.NOTES
   Example of how to use this cmdlet

.EXAMPLE
   Show-BalloonTip -SuspectedMailMesssage [PSCustomObject]@{SenderName,SenderEmailAddress,ReceivedTime,FoundHttpBody}

#>
function Show-BalloonTip{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$SuspectedMailMesssage
    )

    Begin
    {
        Add-Type -AssemblyName System.Windows.Forms 
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path           = (Get-Process -id $pid).Path
        $BalloonText    = $null
    }
    Process
    {    
        $SuspectedMailMesssage | ForEach-Object{
            $BalloonText = "Mail from <$($_.SenderName)> <$($_.SenderEmailAddress)> at <$($_.ReceivedTime)> contains <$($_.FoundHttpBody)>"
        }
        $balloon.Icon            = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]::Warning 
        $balloon.BalloonTipText  = $BalloonText
        $balloon.BalloonTipTitle = "Attention suspected Mail detected!"
    
    }
    End
    {
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(5000)
    }
}

$SuspectedMail = Test-SuspectedMailMesssage
if($SuspectedMail){
    Show-BalloonTip -SuspectedMailMesssage $SuspectedMail
}
