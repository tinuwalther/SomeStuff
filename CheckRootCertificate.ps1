Get-ChildItem Cert:\LocalMachine\Root | Where-Object NotAfter -lt (Get-Date) | Select-Object FriendlyName,DnsNameList,NotBefore,NotAfter
