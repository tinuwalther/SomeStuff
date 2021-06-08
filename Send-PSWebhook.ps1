# Import nothing

# Initialize variables
$webhook_url         = 'your webhook address'
$author_name         = 'PowerShell Hook'
$author_avatar       = 'http://img1.wikia.nocookie.net/__cb20111027212138/pichipichipitchadventures/es/images/thumb/f/fd/Captain-Hook-Wallpaper-disney-villains-976702_1024_768.png/456px-Captain-Hook-Wallpaper-disney-villains-976702_1024_768.png'

$section_title       = '[INFO] Send with PowerShell'
$section_description = 'Invoke-RestMethod to the WebHookUrl'
$section_color       = 5789910 #5858D6

$fact_title          = 'You are boarded'
$fact_message        = 'PowerShell Hook boarded your messenger!'

# New section as embed object
$embeds = @{
    "title"       = $section_title
    "description" = $section_description
    'color'       = $section_color
    "fields"      = @(
        @{'name' = $fact_title; 'value' = $fact_message; "inline" = $false}
    )
}

# Full message
$data = @{
    "username"   = $author_name
    "avatar_url" = $author_avatar
    "embeds"     = @($embeds)
}

# Content-Type
$headers = 'application/json; charset=UTF-8'

$result = Invoke-RestMethod -Uri $webhook_url -Body (ConvertTo-Json -Depth 6 -InputObject $data) -Method Post -ContentType $headers
$result