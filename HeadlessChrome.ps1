<#
  https://peter.sh/experiments/chromium-command-line-switches/#load-extension
#>
$path = "D:\Output\Report_20190731-123445"
$url  = "file:///$($path -replace '\\', '/')"

$chrome = "$(${env:ProgramFiles(x86)})\Google\Chrome\Application\chrome.exe"
& $chrome --headless --disable-gpu --print-to-pdf="$($path).pdf" "$($url).html"
