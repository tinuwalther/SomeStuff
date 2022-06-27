<#
Why should I use functions?
This allows us to reduce a complicated program into smaller, more manageable chunks, which reduces the overall complexity of our program. 
Reusability -- Once a function is written, it can be called multiple times from within the program.
#>

Describe "Test Module-Function" {

    BeforeDiscovery {
        Import-Module -Name PsNetTools -Force
    }
    
    it "[POS] Test-PsNetDig should not throw"{
        {'sbb1.ch' | Test-PsNetDig} | Should -Not -Throw
        {Test-PsNetDig '127.0.0.1'} | Should -Not -Throw
        {Test-PsNetDig -Destination '127.0.0.1'} | Should -Not -Throw
    }
}

Describe "Test Procedure" {

    it "[POS] [System.Net.Dns]::GetHostEntry() should not throw" -TestCase @{ InputObject = 'sbb1.ch'} {
        {
            $ret = foreach($item in $inputObject){
                $dnsreturn = [System.Net.Dns]::GetHostEntry($item)
                if(-not([String]::IsNullOrEmpty($dnsreturn))){
                    $TargetName = $dnsreturn.hostname
                    $collection = $dnsreturn.AddressList
                }
                foreach($item in $collection){
                    if($($item.AddressFamily) -eq [System.Net.Sockets.AddressFamily]::InterNetwork){
                        $ipv4address += $item.IPAddressToString
                    }
                    if($($item.AddressFamily) -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6){
                        $ipv6address += $item.IPAddressToString
                    }
                }
                @{ 'QueryFor'= $InputObject; 'ResolvedTo' = $TargetName; 'IPv4Address' = $ipv4address; 'IPv6Address' = $ipv6address }
            }
            return $ret
        } | should -Not -Throw
    }

}

Describe "Test Function" {

    BeforeDiscovery {

        function Test-DNSResolver {
            [CmdletBinding()]
            param(
                #region parameter, to add a new parameter, copy and paste the Parameter-region
                [Parameter(
                    Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position = 0
                )]
                [string] $InputString
                #endregion
            )
    
            begin{
                #region Do not change this region
                $StartTime = Get-Date
                $function = $($MyInvocation.MyCommand.Name)
                Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ Begin   ]', $function -Join ' ')
                #endregion
                $ret = $null # or @()
            }
    
            process{
                Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ Process ]', $function -Join ' ')
                try{
                    $dnsreturn = [System.Net.Dns]::GetHostEntry($InputString)
                    if(-not([String]::IsNullOrEmpty($dnsreturn))){
                        $TargetName = $dnsreturn.hostname
                        $collection = $dnsreturn.AddressList
                    }
                    foreach($item in $collection){
                        if($($item.AddressFamily) -eq [System.Net.Sockets.AddressFamily]::InterNetwork){
                            $ipv4address += $item.IPAddressToString
                        }
                        if($($item.AddressFamily) -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6){
                            $ipv6address += $item.IPAddressToString
                        }
                    }
                    return @{ 'QueryFor'= $InputString; 'ResolvedTo' = $TargetName; 'IPv4Address' = $ipv4address; 'IPv6Address' = $ipv6address }
                }catch{
                    Write-Verbose $('ScriptName:', $($_.InvocationInfo.ScriptName), 'LineNumber:', $($_.InvocationInfo.ScriptLineNumber), 'Message:', $($_.Exception.Message) -Join ' ')
                    return $($_.Exception.Message)
                    $Error.Clear()
                }
            }
    
            end{
                #region Do not change this region
                Write-Verbose $('[', (Get-Date -f 'yyyy-MM-dd HH:mm:ss.fff'), ']', '[ End     ]', $function -Join ' ')
                $TimeSpan  = New-TimeSpan -Start $StartTime -End (Get-Date)
                $Formatted = $TimeSpan | ForEach-Object {
                    '{1:0}h {2:0}m {3:0}s {4:000}ms' -f $_.Days, $_.Hours, $_.Minutes, $_.Seconds, $_.Milliseconds
                }
                Write-Verbose $('Finished in:', $Formatted -Join ' ')
                #endregion
                return $ret
            }
        }
    
    }
    
    it "[POS] Test-DNSResolver should not throw" -TestCase @{ InputObject = 'sbb1.ch'} {
        {
            Test-DNSResolver -InputString $InputObject
        } | should -Not -Throw
    }

}