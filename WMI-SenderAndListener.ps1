<#
    LINK
     https://adamtheautomator.com/your-goto-guide-for-working-with-windows-wmi-events-and-powershell/
#>

#region Filter

function New-WMIWatcher{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [String] $EventCycleSeconds = 15,

        [Parameter(Mandatory=$false)]
        [String] $WmiClassName = 'win32_service',

        [Parameter(Mandatory=$true)]
        [String] $SenderName
    )

    $function = $($MyInvocation.MyCommand.Name)
    Write-Verbose "Running $function"

    try{
        $FilterQuery = "Select * from __InstanceModificationEvent within $EventCycleSeconds where TargetInstance ISA $WmiClassName"
        $CIMEventFilterProperties = @{
	
            ## The name of the event filter. This can be anything related.
	        Name = $SenderName
	
            ## The namespace for the targetted class, for example, the targetted class for
	        ## **Win32_Service** is Root/CIMv2
	        EventNameSpace = "Root/CIMV2"
	
            ## The query language, usually **WQL**.
	        QueryLanguage = "WQL"
	
            ## The query to use.
	        Query = $FilterQuery
        }

        $CIMFilterInstance = New-CimInstance -ClassName __EventFilter -Namespace "Root/SubScription" -Property $CIMEventFilterProperties

        Write-Host "[INFO] $($function), $($TestResult.Name), $($TestResult.Query)" -ForegroundColor Green

        return $true
    }catch{
        Write-Host "[WARN] $($function) raised an error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Yellow
        $Error.Clear()
        return $false
    }
}


function Get-WMIWatcher{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String] $SenderName
    )

    $function = $($MyInvocation.MyCommand.Name)
    Write-Verbose "Running $function"

    Get-CimInstance -Namespace Root/Subscription -ClassName __FilterToConsumerBinding | Where-Object {$_.Filter.Name -like $SenderName}

}


function Remove-WMIWatcher{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String] $SenderName
    )

    $function = $($MyInvocation.MyCommand.Name)
    Write-Verbose "Running $function"

    Get-CimInstance -Namespace Root/Subscription -ClassName __FilterToConsumerBinding | Where-Object {$_.Filter.Name -like $SenderName} | Remove-CimInstance

}
#endregion

<#
#region Consumer
$CIMCOnsumerProperties = @{

	## The name that the script will register in the **Root/Subscription** namespace
	Name = "MyServiceConsumer"
	
    ## The file path and name which the log writes to when the event is triggered.
	FileName = "C:\\MyCIMMonitoring.txt"

	## The text to write in the log. You can add a variable by using the	
    ## %TargetInstance.WMIProperty%. In this example, the **Caption** and the **State
	##** are used.
	Text = "The Service %TargetInstance.Caption% has been Changed: %TargetInstance.State%"

}
$CIMEventConsumer=New-CimInstance -ClassName LogFileEventConsumer -Namespace 'ROOT/subscription' -Property $CIMCOnsumerProperties

## Test the consumer
Get-CimInstance -Namespace Root/Subscription -ClassName LogFileEventConsumer | Select Name, Text, FileName

#endregion


#region Binding
$CIMBindingProperties=@{
	Filter   = [Ref]$CIMFilterInstance
	Consumer = [Ref]$CIMEventConsumer
}

$CIMBinding = New-CimInstance -ClassName __FilterToConsumerBinding -Namespace "root/subscription" -Property $CIMBindingProperties


## Test the binding
Get-CimInstance -Namespace Root/Subscription -ClassName __FilterToConsumerBinding | Select Consumer, Filter

#endregion
#>

<#
New-WMIWatcher -SenderName 'TIN-ServiceListener' -EventCycleSeconds 10 -WmiClassName 'win32_service' -Verbose

Get-Watcher -SenderName 'TIN-ServiceListener'

Remove-Watcher -SenderName 'TIN-ServiceListener'
#>