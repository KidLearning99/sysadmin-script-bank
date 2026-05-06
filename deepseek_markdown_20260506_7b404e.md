# Exchange Online Real-World Troubleshooting – Full PowerShell Commands

## SCENARIO 01 – External Partner Not Receiving Mail (Silent Drop at EOP)
```powershell
Get-MessageTrace -SenderAddress user@yourdomain.com -RecipientAddress partner@domain.com -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) | FL
Get-OutboundConnector | Select Name, TLSSettings, SmartHosts, Enabled | FL
Test-OutboundConnectivity -Identity 'ConnectorName'