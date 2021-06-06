<#
    ChatOps with PSDiscord
#>
Import-Module PSDiscord -Force

$Import = $false

$json_file        = "MssqlDB.tinu-inventory-2021523-13-00-00.json"
$WebhookUri       = 'your webhook address'

$CaptainHook      = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fvignette.wikia.nocookie.net%2Fdisneytsumtsum%2Fimages%2F4%2F4b%2FCaptainHook.png%2Frevision%2Flatest%2Fscale-to-width-down%2F210%3Fcb%3D20170210054607&f=1&nofb=1"
$ChatAngel        = "https://www.emojibase.com/resources/img/emojis/apple/x1f47c.png.pagespeed.ic.d2IjV3gUvN.png"
$ChatDevil        = "http://aux.iconspalace.com/uploads/16647871741233654299.png"

$SectionFactName  = "Import collection in to MongoDB:"
$SectionColor     = "BlueViolet"
$SectionTitleInfo = "[INFO] MongoDB import"
$SectionFactInfo  = New-DiscordFact -Name $SectionFactName -Value "The import $json_file finished successfully at $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')" -Inline $false
$SectionTitleWarn = "[WARN] MongoDB import"
$SectionFactWarn  = New-DiscordFact -Name $SectionFactName -Value "The import $json_file finished with failures at $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')" -Inline $false

if($Import){
    $Section = New-DiscordSection `
    -Title       $SectionTitleInfo `
    -Description '' `
    -Color       $SectionColor `
    -Facts       $SectionFactInfo `
    #-Author      $ChatAngel    
    Send-DiscordMessage -WebHookUrl $WebhookUri -Sections $Section -AvatarName 'Chat Angel' -AvatarUrl $ChatAngel
}else{
    $Section = New-DiscordSection `
    -Title       $SectionTitleWarn `
    -Description '' `
    -Color       $SectionColor `
    -Facts       $SectionFactWarn `
    #-Author      $ChatDevil 
    Send-DiscordMessage -WebHookUrl $WebhookUri -Sections $Section -AvatarName 'Chat Devil' -AvatarUrl $ChatDevil 
}
