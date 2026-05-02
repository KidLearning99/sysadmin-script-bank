const SCENARIOS_DATA = [

// ══════════════════ ENTRA ID ══════════════════

{id:'e1',cat:'entra',icon:'🔐',title:'App Registration Troubleshoot',difficulty:'Advanced',
desc:'Diagnose App Registration issues — permissions, secret expiry, redirect URIs, and sign-in failures.',
steps:[
{title:'Verify App Exists & Get Core Details',desc:'Confirm the app exists and retrieve App ID, Object ID, and sign-in audience.',
code:`Connect-MgGraph -Scopes "Application.Read.All"
$app = Get-MgApplication -Filter "displayName eq 'YourAppName'"
$app | Select-Object DisplayName, AppId, Id, SignInAudience, CreatedDateTime`},
{title:'Check API Permissions & Admin Consent',desc:'List all permissions and verify admin consent where required.',
code:`$app = Get-MgApplication -Filter "displayName eq 'YourAppName'"
$app.RequiredResourceAccess | ForEach-Object {
    $svc = Get-MgServicePrincipal -Filter "appId eq '$($_.ResourceAppId)'"
    Write-Host "Resource: $($svc.DisplayName)" -ForegroundColor Cyan
    $_.ResourceAccess | ForEach-Object { "  $($_.Type): $($_.Id)" }
}
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id |
  Select-Object ConsentType, Scope, PrincipalId`,
info:'Type "Role" = Application permission (admin consent required). Type "Scope" = Delegated permission.'},
{title:'Audit Secrets & Certificate Expiry',desc:'Find expired or soon-to-expire client secrets and certificates.',
code:`$app = Get-MgApplication -Filter "displayName eq 'YourAppName'"
$now = Get-Date
$app.PasswordCredentials | ForEach-Object {
    $days = ($_.EndDateTime - $now).Days
    [PSCustomObject]@{
        Name=$_.DisplayName; Expires=$_.EndDateTime.ToString("yyyy-MM-dd")
        Days=$days; Status=if($days -lt 0){"EXPIRED"}elseif($days -lt 30){"EXPIRING"}else{"OK"}
    }
} | Format-Table -AutoSize`,
warning:'AADSTS7000222=expired secret, AADSTS700027=expired certificate. Rotate before expiry.'},
{title:'Validate Redirect URIs',desc:'List all redirect URIs and verify they match what the app sends.',
code:`$app = Get-MgApplication -Filter "displayName eq 'YourAppName'"
Write-Host "Web Redirect URIs:" ; $app.Web.RedirectUris
Write-Host "SPA Redirect URIs:" ; $app.Spa.RedirectUris
Write-Host "Implicit Grant - Access Token: $($app.Web.ImplicitGrantSettings.EnableAccessTokenIssuance)"`},
{title:'Review Sign-in Failure Logs',desc:'Pull recent failed sign-ins and decode error codes.',
code:`Connect-MgGraph -Scopes "AuditLog.Read.All"
$appId = "00000000-0000-0000-0000-000000000000"
Get-MgAuditLogSignIn -Filter "appId eq '$appId' and status/errorCode ne 0" -Top 50 |
  Select-Object CreatedDateTime, @{N='User';E={$_.UserPrincipalName}},
    @{N='Error';E={$_.Status.ErrorCode}}, @{N='Reason';E={$_.Status.FailureReason}},
    ClientAppUsed, IpAddress | Sort-Object CreatedDateTime -Descending | Format-Table -AutoSize`,
info:'700016=App not found · 65001=Consent needed · 53003=CA blocked · 70011=Invalid scope'}
]},

{id:'e2',cat:'entra',icon:'🔑',title:'SSO Configuration Check',difficulty:'Medium',
desc:'Validate SAML/OIDC SSO — user assignment, claim mapping, token decode, and CA impact.',
steps:[
{title:'List Enterprise Apps with SSO Configured',desc:'Find all enterprise apps with SSO mode set.',
code:`Connect-MgGraph -Scopes "Application.Read.All"
Get-MgServicePrincipal -Filter "tags/any(t: t eq 'WindowsAzureActiveDirectoryIntegratedApp')" -All |
  Where-Object { $_.PreferredSingleSignOnMode } |
  Select-Object DisplayName, @{N='SSOMode';E={$_.PreferredSingleSignOnMode}}, AppId |
  Format-Table -AutoSize`},
{title:'Check User & Group Assignments',desc:'Verify correct users/groups are assigned.',
code:`$sp = Get-MgServicePrincipal -Filter "displayName eq 'YourAppName'"
Write-Host "Assignment Required: $($sp.AppRoleAssignmentRequired)"
Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id |
  ForEach-Object {
    $n = if($_.PrincipalType -eq "User"){(Get-MgUser -UserId $_.PrincipalId).UserPrincipalName}
         else{(Get-MgGroup -GroupId $_.PrincipalId).DisplayName}
    [PSCustomObject]@{ Type=$_.PrincipalType; Name=$n; Assigned=$_.CreatedDateTime }
  } | Format-Table -AutoSize`},
{title:'Review Claims Mapping & SAML Settings',desc:'Check the claims mapping policy for the enterprise app.',
code:`Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All"
$sp  = Get-MgServicePrincipal -Filter "displayName eq 'YourAppName'"
$tid = (Get-MgOrganization).Id
Get-MgServicePrincipalClaimMappingPolicy -ServicePrincipalId $sp.Id | Select-Object Id, DisplayName
Write-Host "SAML Metadata: https://login.microsoftonline.com/$tid/federationmetadata/2007-06/federationmetadata.xml?appid=$($sp.AppId)"`,
info:'For SAML: NameID must match the format expected by the SP. Check custom claims for role/group attributes.'},
{title:'Check Conditional Access Impact',desc:'Find CA policies targeting this application.',
code:`Connect-MgGraph -Scopes "Policy.Read.All"
$appId = "00000000-0000-0000-0000-000000000000"
Get-MgIdentityConditionalAccessPolicy -All |
  Where-Object {
    $_.Conditions.Applications.IncludeApplications -contains $appId -or
    $_.Conditions.Applications.IncludeApplications -contains "All"
  } |
  Select-Object DisplayName, State, @{N='Grant';E={$_.GrantControls.BuiltInControls -join ', '}} |
  Format-Table -AutoSize`}
]},

{id:'e3',cat:'entra',icon:'🔗',title:'Hard Match & Soft Match (AAD Connect)',difficulty:'Advanced',
desc:'Resolve Azure AD Connect object matching failures — ImmutableID conflicts and duplicate proxy addresses.',
steps:[
{title:'Check User Sync Status in Entra ID',desc:'Confirm sync state, ImmutableID, and on-prem attributes.',
code:`Connect-MgGraph -Scopes "User.Read.All"
Get-MgUser -UserId "user@contoso.com" -Property "DisplayName,UserPrincipalName,OnPremisesSyncEnabled,OnPremisesImmutableId,OnPremisesLastSyncDateTime,ProxyAddresses" |
  Select-Object DisplayName, UserPrincipalName, OnPremisesSyncEnabled,
    OnPremisesImmutableId, OnPremisesLastSyncDateTime,
    @{N='ProxyAddresses';E={$_.ProxyAddresses -join '; '}}`},
{title:'Compute ImmutableID from On-Prem ObjectGUID',desc:'On the DC: convert the AD ObjectGUID to Base64 ImmutableID.',
code:`Import-Module ActiveDirectory
$user = Get-ADUser "jsmith" -Properties ObjectGUID
$immutableId = [Convert]::ToBase64String($user.ObjectGUID.ToByteArray())
Write-Host "ObjectGUID  : $($user.ObjectGUID)"
Write-Host "ImmutableID : $immutableId"`},
{title:'Set ImmutableID for Hard Match',desc:'Set the cloud account ImmutableID to force-match it to the on-prem object.',
code:`Connect-MgGraph -Scopes "User.ReadWrite.All"
Update-MgUser -UserId "user@contoso.com" -OnPremisesImmutableId "BASE64_GUID_HERE=="
(Get-MgUser -UserId "user@contoso.com" -Property OnPremisesImmutableId).OnPremisesImmutableId`,
warning:'Setting the wrong ImmutableID can permanently orphan an account. Always verify the ObjectGUID from AD first.'},
{title:'Diagnose Soft Match Conflicts',desc:'Find duplicate proxy addresses blocking a soft match.',
code:`Connect-MgGraph -Scopes "User.Read.All"
$proxy = "smtp:user@contoso.com"
Get-MgUser -Filter "proxyAddresses/any(p:p eq '$proxy')" -All |
  Select-Object DisplayName, UserPrincipalName, Id, OnPremisesSyncEnabled`},
{title:'Force Delta Sync & Verify',desc:'Trigger delta sync and verify the match resolved.',
code:`Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Delta; Start-Sleep 60
Get-ADSyncConnectorRunStatus | Format-Table ConnectorName, RunProfileName, Result -AutoSize`}
]},

{id:'e4',cat:'entra',icon:'📊',title:'MFA Registration & Compliance Audit',difficulty:'Easy',
desc:'Audit MFA registration across the tenant, identify gaps, and enforce via Conditional Access.',
steps:[
{title:'Get Tenant-Wide MFA Registration Report',desc:'Pull authentication registration summary and export to CSV.',
code:`Connect-MgGraph -Scopes "Reports.Read.All"
$all = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
Write-Host "MFA Registered : $(($all|Where-Object IsMfaRegistered).Count) / $($all.Count)"
$all | Select-Object UserPrincipalName, IsMfaRegistered, IsMfaCapable, IsPasswordlessCapable |
  Export-Csv "C:\Reports\MFA_Registration.csv" -NoTypeInformation`},
{title:'Find Users Without MFA',desc:'List member accounts with no MFA method registered.',
code:`Connect-MgGraph -Scopes "Reports.Read.All"
Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
  Where-Object { -not $_.IsMfaRegistered -and $_.UserType -eq "Member" } |
  Select-Object UserPrincipalName, UserDisplayName, IsAdmin |
  Sort-Object IsAdmin -Descending | Format-Table -AutoSize`},
{title:'Inspect Per-User Auth Methods',desc:'Check which specific methods a user has registered.',
code:`Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All"
$uid = (Get-MgUser -UserId "user@contoso.com").Id
Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $uid | Select-Object DisplayName, DeviceTag
Get-MgUserAuthenticationPhoneMethod -UserId $uid | Select-Object PhoneNumber, PhoneType
Get-MgUserAuthenticationFido2Method -UserId $uid | Select-Object DisplayName, Model, CreatedDateTime`},
{title:'Enforce MFA via Conditional Access',desc:'Create a CA policy requiring MFA with breakglass exclusion.',
code:`Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
New-MgIdentityConditionalAccessPolicy -BodyParameter @{
    DisplayName="Require MFA - All Users"; State="enabledForReportingButNotEnforced"
    Conditions=@{
        Users=@{IncludeUsers="All";ExcludeGroups=@("BREAKGLASS-GROUP-ID")}
        Applications=@{IncludeApplications="All"}; ClientAppTypes=@("all")
    }
    GrantControls=@{Operator="OR";BuiltInControls=@("mfa")}
}`,
warning:'Always exclude at least one breakglass account. Test in Report-Only mode before enabling.'}
]},

{id:'e5',cat:'entra',icon:'👥',title:'Guest User Lifecycle',difficulty:'Easy',
desc:'Audit B2B guests, find stale accounts, check resource access, and clean up.',
steps:[
{title:'List All Guests with Sign-in Activity',desc:'Export full guest inventory including last sign-in.',
code:`Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All"
Get-MgUser -Filter "userType eq 'Guest'" -All -Property "DisplayName,UserPrincipalName,CreatedDateTime,SignInActivity,ExternalUserState" |
  ForEach-Object {[PSCustomObject]@{
    Name=$_.DisplayName; UPN=$_.UserPrincipalName
    Created=$_.CreatedDateTime?.ToString("yyyy-MM-dd")
    LastSignIn=$_.SignInActivity?.LastSignInDateTime?.ToString("yyyy-MM-dd"); State=$_.ExternalUserState
  }} | Sort-Object LastSignIn | Export-Csv "C:\Reports\Guests.csv" -NoTypeInformation`},
{title:'Find Inactive Guests (90+ Days)',desc:'Identify guests not signed in for 90+ days.',
code:`Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All"
$cutoff = (Get-Date).AddDays(-90)
Get-MgUser -Filter "userType eq 'Guest'" -All -Property "DisplayName,UserPrincipalName,SignInActivity" |
  Where-Object {-not $_.SignInActivity?.LastSignInDateTime -or $_.SignInActivity.LastSignInDateTime -lt $cutoff} |
  Select-Object DisplayName, UserPrincipalName,
    @{N='LastSignIn';E={$_.SignInActivity?.LastSignInDateTime?.ToString("yyyy-MM-dd") ?? "Never"}} |
  Format-Table -AutoSize`},
{title:'Check Guest Resource Memberships',desc:'Before removing, check what groups and Teams the guest belongs to.',
code:`Connect-MgGraph -Scopes "User.Read.All","Group.Read.All"
$guestId = (Get-MgUser -UserId "guest_company.com#EXT#@tenant.onmicrosoft.com").Id
Get-MgUserMemberOf -UserId $guestId -All |
  Select-Object @{N='Name';E={$_.AdditionalProperties['displayName']}},
               @{N='Type';E={$_.AdditionalProperties['@odata.type']}} | Format-Table -AutoSize`},
{title:'Disable & Remove Stale Guests',desc:'Disable the account, then remove after a review period.',
code:`Connect-MgGraph -Scopes "User.ReadWrite.All"
$guestId = "00000000-0000-0000-0000-000000000000"
Update-MgUser -UserId $guestId -AccountEnabled:$false
Write-Host "Disabled. After 30-day review: Remove-MgUser -UserId $guestId"`,
warning:'Hard deletion is permanent (30-day soft-delete recovery window). Always disable first.'}
]},

{id:'e6',cat:'entra',icon:'🛡',title:'Conditional Access Policy Audit',difficulty:'Medium',
desc:'Review all CA policies, coverage gaps, named locations, and breakglass accounts.',
steps:[
{title:'Export All CA Policies',desc:'Full inventory of CA policies and their state.',
code:`Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy -All |
  Select-Object DisplayName, State,
    @{N='IncludeUsers';E={$_.Conditions.Users.IncludeUsers -join ','}},
    @{N='IncludeApps'; E={$_.Conditions.Applications.IncludeApplications -join ','}},
    @{N='Grant';       E={$_.GrantControls.BuiltInControls -join ','}} |
  Export-Csv "C:\Reports\CA_Policies.csv" -NoTypeInformation`},
{title:'Find Users Not Covered by MFA Policy',desc:'Check exclusions on active MFA-requiring CA policies.',
code:`Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy -All |
  Where-Object { $_.GrantControls.BuiltInControls -contains "mfa" -and $_.State -eq "enabled" } |
  ForEach-Object {
    Write-Host "Policy: $($_.DisplayName)" -ForegroundColor Cyan
    Write-Host "  Excludes: $($_.Conditions.Users.ExcludeUsers -join ', ')"
    Write-Host "  Excl Groups: $($_.Conditions.Users.ExcludeGroups -join ', ')"
  }`},
{title:'Review Named Locations',desc:'List trusted IP ranges and country-based locations.',
code:`Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessNamedLocation -All |
  ForEach-Object {
    [PSCustomObject]@{
        Name=$_.DisplayName
        Type=if($_.AdditionalProperties.ipRanges){"IP Range"}else{"Country"}
        IsTrusted=$_.AdditionalProperties.isTrusted
        Ranges=($_.AdditionalProperties.ipRanges.cidrAddress -join ', ')
    }
  } | Format-Table -AutoSize`},
{title:'Validate Breakglass / Emergency Access Accounts',desc:'Confirm breakglass accounts exist and are properly excluded.',
code:`Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All"
$bg = Get-MgUser -Filter "startswith(displayName,'breakglass') or startswith(displayName,'emergency')" -All
Write-Host "Breakglass accounts found: $($bg.Count)"
$bg | ForEach-Object {
    $si = (Get-MgUser -UserId $_.Id -Property SignInActivity).SignInActivity
    [PSCustomObject]@{ UPN=$_.UserPrincipalName; LastSignIn=$si?.LastSignInDateTime; Enabled=$_.AccountEnabled }
} | Format-Table -AutoSize`,
warning:'Breakglass must be excluded from ALL CA, use phishing-resistant MFA, and trigger alerts on any sign-in.'}
]},

{id:'e7',cat:'entra',icon:'⭐',title:'PIM Audit',difficulty:'Advanced',
desc:'Review PIM role assignments, activation history, and permanent Global Admin assignments.',
steps:[
{title:'List Active Privileged Role Assignments',desc:'Get all permanent (non-JIT) privileged role assignments.',
code:`Connect-MgGraph -Scopes "RoleManagement.Read.Directory","User.Read.All"
Get-MgRoleManagementDirectoryRoleAssignment -All | ForEach-Object {
    $user = try{Get-MgUser -UserId $_.PrincipalId -EA Stop}catch{$null}
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId
    [PSCustomObject]@{User=$user?.UserPrincipalName ?? $_.PrincipalId;Role=$role.DisplayName;Scope=$_.DirectoryScopeId}
} | Format-Table -AutoSize`},
{title:'List Eligible PIM Role Assignments',desc:'Show all JIT-eligible roles configured in PIM.',
code:`Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All | ForEach-Object {
    $user = try{Get-MgUser -UserId $_.PrincipalId -EA Stop}catch{$null}
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId
    [PSCustomObject]@{User=$user?.UserPrincipalName ?? $_.PrincipalId;Role=$role.DisplayName;Expiration=$_.ScheduleInfo.Expiration.EndDateTime}
} | Format-Table -AutoSize`},
{title:'Review PIM Activation History',desc:'Detect unexpected privilege escalations.',
code:`Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All |
  Where-Object{$_.AssignmentType -eq "Activated"} | ForEach-Object {
    $user = try{Get-MgUser -UserId $_.PrincipalId -EA Stop}catch{$null}
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId
    [PSCustomObject]@{User=$user?.UserPrincipalName;Role=$role.DisplayName;Start=$_.StartDateTime;End=$_.EndDateTime}
} | Sort-Object Start -Descending | Select-Object -First 50 | Format-Table -AutoSize`},
{title:'Find Permanent Global Admin Assignments',desc:'Identify accounts with permanent (non-PIM) Global Admin.',
code:`Connect-MgGraph -Scopes "RoleManagement.Read.Directory","User.Read.All"
$gaId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'").Id
Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$gaId'" -All | ForEach-Object {
    $u = try{Get-MgUser -UserId $_.PrincipalId -EA Stop}catch{$null}
    [PSCustomObject]@{Principal=$u?.UserPrincipalName ?? $_.PrincipalId;Type="PERMANENT"}
} | Format-Table -AutoSize`,
warning:'Permanent Global Admin = critical risk. All GA should be JIT via PIM.'}
]},

{id:'e8',cat:'entra',icon:'🔍',title:'Risky Users Investigation',difficulty:'Medium',
desc:'Investigate Identity Protection risky users — assess, remediate, and dismiss.',
steps:[
{title:'Get All Current Risky Users',desc:'List users flagged by Identity Protection.',
code:`Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All","IdentityRiskyUser.ReadWrite.All"
Get-MgRiskyUser -Filter "riskState ne 'dismissed' and riskState ne 'remediated'" -All |
  Select-Object UserPrincipalName,RiskLevel,RiskState,RiskDetail,RiskLastUpdatedDateTime |
  Sort-Object RiskLevel | Format-Table -AutoSize`},
{title:'Get Risk Detections for a User',desc:'Drill into specific risk events for a user.',
code:`Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All"
Get-MgRiskDetection -Filter "userPrincipalName eq 'user@contoso.com'" -All |
  Select-Object RiskEventType,RiskLevel,Source,IpAddress,Location,ActivityDateTime |
  Sort-Object ActivityDateTime -Descending | Format-Table -AutoSize`},
{title:'Dismiss Risk (False Positive)',desc:'Dismiss the risk after confirming with the user.',
code:`Connect-MgGraph -Scopes "IdentityRiskyUser.ReadWrite.All"
$userId = (Get-MgUser -UserId "user@contoso.com").Id
Invoke-MgDismissRiskyUser -UserIds @($userId)
Get-MgRiskyUser -Filter "id eq '$userId'" | Select-Object UserPrincipalName,RiskState`},
{title:'Force Password Reset for Compromised User',desc:'Require password change and revoke all sessions.',
code:`Connect-MgGraph -Scopes "User.ReadWrite.All"
$userId = (Get-MgUser -UserId "user@contoso.com").Id
Update-MgUser -UserId $userId -PasswordProfile @{ForceChangePasswordNextSignIn=$true}
Invoke-MgInvalidateUserRefreshToken -UserId $userId
Write-Host "Password reset forced, sessions revoked."`,
warning:'Also disable the account if breach is confirmed. Investigate attack vector before re-enabling.'}
]},

{id:'e9',cat:'entra',icon:'📋',title:'License Assignment Audit',difficulty:'Easy',
desc:'Audit license allocation, find unused licenses, and identify inactive licensed users.',
steps:[
{title:'Get License Summary',desc:'View available vs consumed licenses across all SKUs.',
code:`Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgSubscribedSku | Select-Object @{N='SKU';E={$_.SkuPartNumber}},
    @{N='Enabled';E={$_.PrepaidUnits.Enabled}}, @{N='Consumed';E={$_.ConsumedUnits}},
    @{N='Available';E={$_.PrepaidUnits.Enabled - $_.ConsumedUnits}} |
  Sort-Object Available | Format-Table -AutoSize`},
{title:'Find Directly Assigned Licenses',desc:'Identify users with direct (not group-based) license assignments.',
code:`Connect-MgGraph -Scopes "User.Read.All"
Get-MgUser -All -Property "UserPrincipalName,LicenseAssignmentStates" |
  Where-Object{$_.LicenseAssignmentStates | Where-Object{$_.AssignedByGroup -eq $null}} |
  Select-Object UserPrincipalName,@{N='DirectCount';E={$_.LicenseAssignmentStates.Count}} |
  Format-Table -AutoSize`},
{title:'Find Licensed Inactive Users (90+ Days)',desc:'Identify wasted licenses on inactive users.',
code:`Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All"
$cutoff = (Get-Date).AddDays(-90)
Get-MgUser -All -Property "UserPrincipalName,AssignedLicenses,SignInActivity,AccountEnabled" |
  Where-Object{$_.AccountEnabled -and $_.AssignedLicenses.Count -gt 0} |
  Where-Object{-not $_.SignInActivity?.LastSignInDateTime -or $_.SignInActivity.LastSignInDateTime -lt $cutoff} |
  Select-Object UserPrincipalName, @{N='Licenses';E={$_.AssignedLicenses.Count}},
    @{N='LastSignIn';E={$_.SignInActivity?.LastSignInDateTime?.ToString("yyyy-MM-dd") ?? "Never"}} |
  Format-Table -AutoSize`},
{title:'Check License Assignment Errors',desc:'Find users with licensing errors (conflicting service plans).',
code:`Connect-MgGraph -Scopes "User.Read.All"
Get-MgUser -All -Property "UserPrincipalName,LicenseAssignmentStates" | ForEach-Object {
    $errs = $_.LicenseAssignmentStates | Where-Object{$_.State -eq "Error"}
    if($errs){[PSCustomObject]@{UPN=$_.UserPrincipalName;Errors=$errs.Error -join ', '}}
} | Format-Table -AutoSize`}
]},

{id:'e10',cat:'entra',icon:'🖥',title:'Device Registration & Join Status',difficulty:'Medium',
desc:'Audit device join type, compliance linkage, stale devices, and hybrid join SCP.',
steps:[
{title:'Get Device Join Overview',desc:'Inventory devices by join type.',
code:`Connect-MgGraph -Scopes "Device.Read.All"
Get-MgDevice -All | Group-Object TrustType | Select-Object Name,Count | Format-Table -AutoSize
Get-MgDevice -All | Select-Object DisplayName,TrustType,OperatingSystem,IsManaged,IsCompliant,
    @{N='LastSeen';E={$_.ApproximateLastSignInDateTime?.ToString("yyyy-MM-dd")}} |
  Sort-Object LastSeen | Format-Table -AutoSize`},
{title:'Find Stale Devices (180+ Days)',desc:'Identify devices not seen in 180+ days.',
code:`Connect-MgGraph -Scopes "Device.Read.All"
$cutoff = (Get-Date).AddDays(-180)
Get-MgDevice -All |
  Where-Object{$_.ApproximateLastSignInDateTime -lt $cutoff -or -not $_.ApproximateLastSignInDateTime} |
  Select-Object DisplayName,TrustType,OperatingSystem,
    @{N='LastSeen';E={$_.ApproximateLastSignInDateTime?.ToString("yyyy-MM-dd") ?? "Never"}} |
  Sort-Object LastSeen | Format-Table -AutoSize`},
{title:'Check User Device Registrations',desc:'List devices registered to a specific user.',
code:`Connect-MgGraph -Scopes "Device.Read.All","User.Read.All"
$uid = (Get-MgUser -UserId "user@contoso.com").Id
Get-MgUserRegisteredDevice -UserId $uid |
  Select-Object DisplayName,TrustType,OperatingSystem,IsManaged,IsCompliant | Format-Table -AutoSize`},
{title:'Verify Hybrid Join SCP',desc:'Check the AD Service Connection Point used during Hybrid Join.',
code:`$scp = Get-ADObject -Filter 'objectClass -eq "serviceConnectionPoint" and name -eq "62a0ff2e-97b9-4513-943f-0d221bd30080"' -Properties keywords
$scp.keywords | ForEach-Object {
    if($_ -match "azureADName:(.+)"){Write-Host "Tenant Name: $($matches[1])"}
    if($_ -match "azureADId:(.+)") {Write-Host "Tenant ID  : $($matches[1])"}
}`,info:'The SCP must exist in the AD Configuration partition for Hybrid Join to work.'}
]},

// ════ ACTIVE DIRECTORY ════

{id:'a1',cat:'ad',icon:'👤',title:'User Account Troubleshoot',difficulty:'Easy',
desc:'Diagnose locked, expired, disabled, and password-issue AD accounts.',
steps:[
{title:'Check Account Status',desc:'Full status — enabled, locked, expiry, bad password count.',
code:`Import-Module ActiveDirectory
$user = Get-ADUser "jsmith" -Properties *
[PSCustomObject]@{Enabled=$user.Enabled;LockedOut=$user.LockedOut;BadPwdCount=$user.BadPwdCount;
    PwdExpired=$user.PasswordExpired;PwdLastSet=$user.PasswordLastSet;
    AccountExpires=$user.AccountExpirationDate;LastLogon=[DateTime]::FromFileTime($user.LastLogon)}`},
{title:'Unlock Account & Reset Password',desc:'Unlock and force password change at next sign-in.',
code:`Import-Module ActiveDirectory
Unlock-ADAccount -Identity "jsmith"
$pwd = ConvertTo-SecureString "TempP@ss2024!" -AsPlainText -Force
Set-ADAccountPassword -Identity "jsmith" -NewPassword $pwd -Reset
Set-ADUser -Identity "jsmith" -ChangePasswordAtLogon $true`,warning:'Communicate temp password securely.'},
{title:'Check Group Memberships',desc:'List all direct and nested group memberships.',
code:`Get-ADPrincipalGroupMembership "jsmith" | Select-Object Name,GroupCategory | Sort-Object Name | Format-Table -AutoSize`},
{title:'Check Fine-Grained Password Policy',desc:'Determine which PSO applies to this account.',
code:`Get-ADUserResultantPasswordPolicy -Identity "jsmith" |
  Select-Object Name,MinPasswordLength,MaxPasswordAge,LockoutThreshold,LockoutDuration`}
]},

{id:'a2',cat:'ad',icon:'🌐',title:'Domain Controller Health Check',difficulty:'Medium',
desc:'Verify DC replication, SYSVOL, time sync, and FSMO role placement.',
steps:[
{title:'Check Replication Status',desc:'Run repadmin to confirm all DCs replicate without errors.',
code:`repadmin /replsummary
repadmin /showrepl /errorsonly`},
{title:'Run DCDiag',desc:'Full DC diagnostic to a log file.',
code:`dcdiag /test:replications /test:fsmocheck /test:netlogons /test:advertising /test:services /v /f:"C:\DCDiag_$(hostname).txt"
Select-String "FAILED" "C:\DCDiag_$(hostname).txt"`},
{title:'Verify SYSVOL & NETLOGON Shares',desc:'Confirm shares are accessible on all DCs.',
code:`(Get-ADDomainController -Filter *).HostName | ForEach-Object {
    Write-Host "=== $_ ===" -ForegroundColor Cyan
    Get-SmbShare -CimSession $_ | Where-Object{$_.Name -in "SYSVOL","NETLOGON"} | Select-Object Name,Path
}`},
{title:'Check Time Sync',desc:'Verify time on all DCs — clock skew breaks Kerberos.',
code:`(Get-ADDomainController -Filter *).HostName | ForEach-Object {
    Write-Host "=== $_ ===" -ForegroundColor Cyan
    Invoke-Command -ComputerName $_ -ScriptBlock{w32tm /query /status} | Select-String "Source|Stratum"
}`,info:'Max 5-minute Kerberos clock skew. PDC Emulator must sync to external NTP.'},
{title:'Identify FSMO Role Holders',desc:'Report which DC holds each of the 5 FSMO roles.',
code:`$f=Get-ADForest;$d=Get-ADDomain
"Schema: $($f.SchemaMaster)","DomainNaming: $($f.DomainNamingMaster)",
"PDCEmulator: $($d.PDCEmulator)","RIDMaster: $($d.RIDMaster)","InfraMaster: $($d.InfrastructureMaster)"`}
]},

{id:'a3',cat:'ad',icon:'🔄',title:'AD Replication Troubleshoot',difficulty:'Advanced',
desc:'Diagnose and resolve AD replication failures between domain controllers.',
steps:[
{title:'Identify Replication Errors',desc:'Full view of replication errors across all DCs.',
code:`repadmin /replsummary
repadmin /showrepl /errorsonly /csv > C:\repl_errors.csv`},
{title:'Check Replication Topology & Connections',desc:'Verify KCC-generated connections.',
code:`repadmin /showconn
Get-ADReplicationConnection -Filter * | Select-Object Name,ReplicateFromDirectoryServer,ReplicateToDirectoryServer | Format-Table -AutoSize`},
{title:'Force Replication',desc:'Manually trigger replication of a partition.',
code:`repadmin /replicate TargetDC SourceDC "DC=contoso,DC=com"
repadmin /syncall /Ade`},
{title:'Diagnose Network & DNS Connectivity',desc:'Test ports required for AD replication.',
code:`$dc2="DC02.contoso.com"
Resolve-DnsName $dc2
Test-NetConnection -ComputerName $dc2 -Port 135
Test-NetConnection -ComputerName $dc2 -Port 389
Test-NetConnection -ComputerName $dc2 -Port 445`,
info:'AD replication requires ports 135, 389/636, 445, and dynamic RPC (49152-65535).'}
]},

{id:'a4',cat:'ad',icon:'🔒',title:'AD Password & Lockout Policy',difficulty:'Easy',
desc:'Review password policy, PSOs, and trace account lockout source.',
steps:[
{title:'View Default Domain Password Policy',desc:'Check the domain-level password policy.',
code:`Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled,MinPasswordLength,MaxPasswordAge,LockoutThreshold,LockoutDuration,LockoutObservationWindow`},
{title:'List Fine-Grained Password Policies (PSOs)',desc:'Check PSO precedence and applicability.',
code:`Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name,Precedence,MinPasswordLength,LockoutThreshold,MaxPasswordAge | Format-Table -AutoSize
Get-ADUserResultantPasswordPolicy -Identity "jsmith"`},
{title:'Find All Locked Out Accounts',desc:'Get all currently locked accounts.',
code:`Search-ADAccount -LockedOut | Select-Object Name,SamAccountName,BadLogonCount,@{N='LastLogon';E={$_.LastLogonDate}} | Format-Table -AutoSize`},
{title:'Trace Lockout Source',desc:'Find which machine is generating bad password attempts.',
code:`Get-WinEvent -ComputerName (Get-ADDomain).PDCEmulator -FilterHashtable @{LogName="Security";Id=4740;StartTime=(Get-Date).AddHours(-1)} |
  Where-Object{$_.Properties[0].Value -eq "jsmith"} |
  Select-Object TimeCreated,@{N='CallerComputer';E={$_.Properties[1].Value}}`}
]},

{id:'a5',cat:'ad',icon:'🖥',title:'Stale Computer Objects Cleanup',difficulty:'Easy',
desc:'Find and safely remove inactive computer objects no longer joined to the domain.',
steps:[
{title:'Find Stale Computer Accounts (90+ Days)',desc:'Identify inactive computer accounts.',
code:`$cutoff=(Get-Date).AddDays(-90)
Get-ADComputer -Filter{LastLogonDate -lt $cutoff -and Enabled -eq $true} -Properties LastLogonDate,OperatingSystem |
  Select-Object Name,OperatingSystem,@{N='LastLogon';E={$_.LastLogonDate.ToString("yyyy-MM-dd")}},DistinguishedName |
  Sort-Object LastLogon | Format-Table -AutoSize`},
{title:'Disable & Move Stale Computers',desc:'Disable and move to a holding OU.',
code:`$cutoff=(Get-Date).AddDays(-90); $disabledOU="OU=Disabled-Computers,DC=contoso,DC=com"
Get-ADComputer -Filter{LastLogonDate -lt $cutoff -and Enabled -eq $true} -Properties LastLogonDate | ForEach-Object{
    Disable-ADAccount -Identity $_
    Move-ADObject -Identity $_.DistinguishedName -TargetPath $disabledOU
    Write-Host "Disabled: $($_.Name)"
}`,warning:'Keep disabled 30 days before deletion. Verify no services depend on these objects.'},
{title:'Delete Confirmed Stale Objects',desc:'Remove accounts in the disabled OU after review period.',
code:`Get-ADComputer -SearchBase "OU=Disabled-Computers,DC=contoso,DC=com" -Filter{WhenChanged -lt (Get-Date).AddDays(-120)} |
  ForEach-Object{Remove-ADComputer -Identity $_ -Confirm:$false; Write-Host "Removed: $($_.Name)"}`}
]},

{id:'a6',cat:'ad',icon:'🔑',title:'Kerberos & SPN Troubleshoot',difficulty:'Advanced',
desc:'Diagnose Kerberos failures, duplicate SPNs, and service account SPN configuration.',
steps:[
{title:'Find Duplicate SPNs',desc:'Duplicate SPNs cause Kerberos failures.',
code:`setspn -X -F`},
{title:'List SPNs for Service Account',desc:'View registered SPNs for a specific account.',
code:`setspn -L svc-webapp
Get-ADUser "svc-webapp" -Properties ServicePrincipalName | Select-Object -ExpandProperty ServicePrincipalName`},
{title:'Register & Remove SPNs',desc:'Add or remove SPNs for a service account.',
code:`setspn -A HTTP/webapp.contoso.com svc-webapp
setspn -A HTTP/webapp svc-webapp
# Remove: setspn -D HTTP/old.contoso.com svc-webapp
setspn -L svc-webapp`},
{title:'Test Kerberos & KDC Connectivity',desc:'Verify ticket retrieval and KDC reachability.',
code:`klist get HTTP/webapp.contoso.com
klist          # View cached tickets
klist purge    # Force re-auth
Test-NetConnection -ComputerName DC01.contoso.com -Port 88`,
info:'Event 4771=pre-auth failure, 4768=TGT request. Check Security log on PDC Emulator.'}
]},

{id:'a7',cat:'ad',icon:'🔍',title:'Service Account Audit',difficulty:'Medium',
desc:'Identify service accounts, check privileges, and find unsafe delegation.',
steps:[
{title:'Find All Service Accounts',desc:'Find by naming convention and PasswordNeverExpires.',
code:`Get-ADUser -Filter{SamAccountName -like "svc-*"} -Properties LastLogonDate,PasswordNeverExpires |
  Select-Object SamAccountName,Enabled,PasswordNeverExpires,LastLogonDate | Format-Table -AutoSize`},
{title:'Check Interactive Logon Restrictions',desc:'Verify service accounts are restricted from interactive logon.',
code:`secedit /export /areas USER_RIGHTS /cfg C:\secedit.cfg
Select-String "SeServiceLogonRight" C:\secedit.cfg
Select-String "SeInteractiveLogonRight" C:\secedit.cfg`},
{title:'Audit Privileged Group Memberships',desc:'Check for service accounts in admin groups.',
code:`Get-ADUser -Filter{SamAccountName -like "svc-*"} | ForEach-Object{
    $g = Get-ADPrincipalGroupMembership $_.SamAccountName | Where-Object{$_.Name -match "Admin|Domain Admin|Enterprise"}
    if($g){Write-Host "$($_.SamAccountName) in PRIVILEGED group:" -ForegroundColor Red; $g | Select-Object Name}
}`,warning:'Domain Admin rights for service accounts is a critical security risk. Apply least privilege.'},
{title:'Check for Unconstrained Delegation',desc:'Find accounts with unconstrained Kerberos delegation.',
code:`Get-ADUser -Filter{TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object SamAccountName | Format-Table -AutoSize
Get-ADComputer -Filter{TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
  Where-Object{$_.DistinguishedName -notmatch "Domain Controllers"} | Select-Object Name | Format-Table -AutoSize`,
warning:'Unconstrained delegation allows impersonation of any user. Migrate to constrained or RBCD immediately.'}
]},

// ════ EXCHANGE ONLINE ════

{id:'x1',cat:'exchange',icon:'📅',title:'Calendar Permissions & Delegation',difficulty:'Medium',
desc:'Manage calendar sharing, delegate access, and room mailbox booking configuration.',
steps:[
{title:'View Calendar Permissions',desc:'Check who has access to a mailbox calendar.',
code:`Connect-ExchangeOnline
Get-MailboxFolderPermission -Identity "user@contoso.com:\Calendar" |
  Select-Object User,AccessRights,SharingPermissionFlags | Format-Table -AutoSize`},
{title:'Set Calendar Permissions',desc:'Grant or remove calendar access.',
code:`Connect-ExchangeOnline
Add-MailboxFolderPermission -Identity "user@contoso.com:\Calendar" -User "manager@contoso.com" -AccessRights Editor
Set-MailboxFolderPermission -Identity "user@contoso.com:\Calendar" -User Default -AccessRights LimitedDetails`,
info:'Rights: Owner > PublishingEditor > Editor > Author > Reviewer > AvailabilityOnly > LimitedDetails'},
{title:'Configure Delegate Access',desc:'Grant Full Access + Send on Behalf to an assistant.',
code:`Connect-ExchangeOnline
Set-Mailbox "exec@contoso.com" -GrantSendOnBehalfTo "assistant@contoso.com"
Add-MailboxPermission "exec@contoso.com" -User "assistant@contoso.com" -AccessRights FullAccess -InheritanceType All
Add-RecipientPermission "exec@contoso.com" -Trustee "assistant@contoso.com" -AccessRights SendAs -Confirm:$false`,
warning:'SendAs + FullAccess grants full impersonation. Audit delegate access regularly.'},
{title:'Room Mailbox Booking Settings',desc:'Configure auto-accept and booking limits.',
code:`Connect-ExchangeOnline
$room = "boardroom@contoso.com"
Get-CalendarProcessing $room | Select-Object AutomateProcessing,BookingWindowInDays,MaximumDurationInMinutes,AllowConflicts
Set-CalendarProcessing $room -AutomateProcessing AutoAccept -MaximumDurationInMinutes 480 -BookingWindowInDays 180 -AllowConflicts $false`}
]},

{id:'x2',cat:'exchange',icon:'✉️',title:'Mail Flow Troubleshoot',difficulty:'Medium',
desc:'Trace email delivery — message trace, transport rules, connectors.',
steps:[
{title:'Run Message Trace',desc:'Track a specific email through Exchange Online routing.',
code:`Connect-ExchangeOnline
Get-MessageTrace -SenderAddress "sender@contoso.com" -RecipientAddress "recipient@domain.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
  Select-Object Received,SenderAddress,RecipientAddress,Subject,Status,FromIP | Format-Table -AutoSize`},
{title:'Get Message Trace Detail',desc:'Drill into delivery events for a specific message.',
code:`Connect-ExchangeOnline
Get-MessageTraceDetail -MessageTraceId "PASTE_TRACE_ID" -RecipientAddress "recipient@domain.com" |
  Select-Object Date,Event,Action,Detail | Format-Table -AutoSize -Wrap`},
{title:'Check Transport Rules',desc:'Review mail flow rules that could affect delivery.',
code:`Connect-ExchangeOnline
Get-TransportRule | Where-Object{$_.State -eq "Enabled"} | Select-Object Name,Priority,Description | Format-Table -AutoSize`},
{title:'Check Connectors & Accepted Domains',desc:'Review inbound/outbound connectors.',
code:`Connect-ExchangeOnline
Get-InboundConnector  | Select-Object Name,Enabled,SenderDomains,RequireTls | Format-Table -AutoSize
Get-OutboundConnector | Select-Object Name,Enabled,RecipientDomains,SmartHosts | Format-Table -AutoSize
Get-AcceptedDomain    | Select-Object DomainName,DomainType,Default | Format-Table -AutoSize`}
]},

{id:'x3',cat:'exchange',icon:'📦',title:'Mailbox Quota & Size Investigation',difficulty:'Easy',
desc:'Check mailbox sizes, quota limits, and archive status.',
steps:[
{title:'Get Mailbox Size Report',desc:'Export mailbox sizes sorted largest first.',
code:`Connect-ExchangeOnline
Get-Mailbox -ResultSize Unlimited | Get-MailboxStatistics |
  Select-Object DisplayName, @{N='SizeGB';E={[math]::Round($_.TotalItemSize.Value.ToBytes()/1GB,2)}},
    ItemCount,LastLogonTime | Sort-Object SizeGB -Descending | Select-Object -First 25 | Format-Table -AutoSize`},
{title:'Check Quota Settings',desc:'View quota config for a specific user.',
code:`Connect-ExchangeOnline
Get-Mailbox "user@contoso.com" | Select-Object DisplayName,IssueWarningQuota,ProhibitSendQuota,ProhibitSendReceiveQuota,ArchiveStatus`},
{title:'Enable & Check Archive Mailbox',desc:'Enable archiving and verify archive size.',
code:`Connect-ExchangeOnline
Enable-Mailbox "user@contoso.com" -Archive
Get-Mailbox "user@contoso.com" | Select-Object ArchiveStatus,ArchiveName
Get-MailboxStatistics "user@contoso.com" -Archive | Select-Object DisplayName,@{N='ArchiveSizeGB';E={[math]::Round($_.TotalItemSize.Value.ToBytes()/1GB,2)}}`},
{title:'Set Mailbox Quota',desc:'Adjust quota limits for a specific user.',
code:`Connect-ExchangeOnline
Set-Mailbox "user@contoso.com" -IssueWarningQuota 45GB -ProhibitSendQuota 48GB -ProhibitSendReceiveQuota 50GB -UseDatabaseQuotaDefaults $false`}
]},

{id:'x4',cat:'exchange',icon:'🔒',title:'Email Forwarding Audit',difficulty:'Easy',
desc:'Find unauthorized forwarding rules — a key BEC and data exfiltration indicator.',
steps:[
{title:'Find Mailboxes with Forwarding Set',desc:'List mailboxes with ForwardingAddress configured.',
code:`Connect-ExchangeOnline
Get-Mailbox -ResultSize Unlimited |
  Where-Object{$_.ForwardingAddress -or $_.ForwardingSmtpAddress} |
  Select-Object DisplayName,UserPrincipalName,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward | Format-Table -AutoSize`},
{title:'Find Inbox Rules with Forwarding',desc:'Check all inbox rules for redirect/forward to external addresses.',
code:`Connect-ExchangeOnline
Get-Mailbox -ResultSize Unlimited | ForEach-Object{
    $rules = Get-InboxRule -Mailbox $_.PrimarySmtpAddress -EA SilentlyContinue |
             Where-Object{$_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo}
    if($rules){Write-Host "ALERT: $($_.PrimarySmtpAddress)" -ForegroundColor Red; $rules | Select-Object Name,ForwardTo}
}`},
{title:'Remove Unauthorized Forwarding',desc:'Clear mailbox forwarding and suspicious inbox rules.',
code:`Connect-ExchangeOnline
Set-Mailbox "user@contoso.com" -ForwardingAddress $null -ForwardingSmtpAddress $null
Get-InboxRule -Mailbox "user@contoso.com" | Where-Object{$_.ForwardTo -or $_.RedirectTo} |
  ForEach-Object{Remove-InboxRule -Mailbox "user@contoso.com" -Identity $_.Identity -Confirm:$false}`,
warning:'External forwarding = primary BEC indicator. Alert your security team on every unauthorized finding.'},
{title:'Block External Forwarding Tenant-Wide',desc:'Transport rule to block all auto-forward to external.',
code:`Connect-ExchangeOnline
New-TransportRule "Block External Email Forwarding" -SentToScope NotInOrganization -MessageTypeMatches AutoForward -RejectMessageReasonText "External forwarding is not permitted." -RejectMessageEnhancedStatusCode "5.7.1"`}
]},

{id:'x5',cat:'exchange',icon:'🛡',title:'Anti-Spam & Anti-Phishing Review',difficulty:'Medium',
desc:'Review EOP policies, Safe Links, Safe Attachments, and anti-phishing configuration.',
steps:[
{title:'Review Spam Filter Policies',desc:'Check SCL thresholds and quarantine actions.',
code:`Connect-ExchangeOnline
Get-HostedContentFilterPolicy | Select-Object Name,IsDefault,SpamAction,HighConfidenceSpamAction,BulkThreshold,PhishSpamAction | Format-Table -AutoSize`},
{title:'Check Anti-Phishing Policies',desc:'Review impersonation protection and spoof settings.',
code:`Connect-ExchangeOnline
Get-AntiPhishPolicy | Select-Object Name,IsDefault,Enabled,EnableMailboxIntelligence,EnableSpoofIntelligence,EnableUnauthenticatedSender | Format-Table -AutoSize`},
{title:'Review Safe Links & Safe Attachments',desc:'Check Defender for Office 365 policies.',
code:`Connect-ExchangeOnline
Get-SafeLinksPolicy      | Select-Object Name,IsEnabled,EnableSafeLinksForEmail,EnableSafeLinksForTeams | Format-Table -AutoSize
Get-SafeAttachmentPolicy | Select-Object Name,Enable,Action,ActionOnError | Format-Table -AutoSize`},
{title:'Check Allowed & Blocked Senders',desc:'Review tenant-level allow/block list.',
code:`Connect-ExchangeOnline
Get-HostedConnectionFilterPolicy | Select-Object Name,IPAllowList,IPBlockList
Get-TenantAllowBlockListItems -ListType Sender | Format-Table -AutoSize
Get-TenantAllowBlockListItems -ListType Url    | Format-Table -AutoSize`}
]},

{id:'x6',cat:'exchange',icon:'📊',title:'Distribution Group Audit',difficulty:'Easy',
desc:'Audit DL groups — membership counts, empty groups, ownership, delivery restrictions.',
steps:[
{title:'Get All Distribution Groups with Member Count',desc:'Full inventory with membership stats.',
code:`Connect-ExchangeOnline
Get-DistributionGroup -ResultSize Unlimited | ForEach-Object {
    [PSCustomObject]@{Name=$_.DisplayName;Email=$_.PrimarySmtpAddress;
        Members=(Get-DistributionGroupMember $_.Identity -ResultSize Unlimited).Count;ManagedBy=$_.ManagedBy -join '; '}
} | Sort-Object Members | Format-Table -AutoSize`},
{title:'Find Empty & Ownerless Groups',desc:'Identify groups with no members or no owner.',
code:`Connect-ExchangeOnline
Get-DistributionGroup -ResultSize Unlimited | ForEach-Object {
    if((Get-DistributionGroupMember $_.Identity -ResultSize Unlimited).Count -eq 0){Write-Host "EMPTY: $($_.DisplayName)" -ForegroundColor Yellow}
    if(-not $_.ManagedBy){Write-Host "NO OWNER: $($_.DisplayName)" -ForegroundColor Red}
}`},
{title:'Review Delivery Restrictions',desc:'Check who can send to each distribution group.',
code:`Connect-ExchangeOnline
Get-DistributionGroup "GroupName@contoso.com" | Select-Object AcceptMessagesOnlyFrom,AcceptMessagesOnlyFromDLMembers,RequireSenderAuthenticationEnabled`},
{title:'Bulk Update Group Members',desc:'Add members from a CSV file.',
code:`Connect-ExchangeOnline
Import-Csv "C:\members_to_add.csv" | ForEach-Object {
    Add-DistributionGroupMember -Identity "team@contoso.com" -Member $_.EmailAddress
    Write-Host "Added: $($_.EmailAddress)"
}`}
]},

{id:'x7',cat:'exchange',icon:'📬',title:'Shared Mailbox Management',difficulty:'Easy',
desc:'Audit, manage permissions, and convert shared mailboxes.',
steps:[
{title:'List Shared Mailboxes with Delegates',desc:'Get all shared mailboxes with size and permissions.',
code:`Connect-ExchangeOnline
Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | ForEach-Object {
    $stat  = Get-MailboxStatistics $_.Identity -EA SilentlyContinue
    $perms = Get-MailboxPermission $_.Identity | Where-Object{$_.User -notlike "*NT AUTHORITY*"}
    [PSCustomObject]@{Name=$_.DisplayName;Email=$_.PrimarySmtpAddress;
        SizeGB=[math]::Round($stat.TotalItemSize.Value.ToBytes()/1GB,2);Users=($perms.User -join ', ')}
} | Format-Table -AutoSize`},
{title:'Grant Full Access & Send As',desc:'Give a user full access + send-as on a shared mailbox.',
code:`Connect-ExchangeOnline
Add-MailboxPermission   "shared@contoso.com" -User "user@contoso.com" -AccessRights FullAccess -AutoMapping $true
Add-RecipientPermission "shared@contoso.com" -Trustee "user@contoso.com" -AccessRights SendAs -Confirm:$false`},
{title:'Convert User Mailbox to Shared',desc:'Convert a licensed mailbox to shared to reclaim the license.',
code:`Connect-ExchangeOnline
Set-Mailbox "leavinguser@contoso.com" -Type Shared
Write-Host "Converted. Remove the Exchange license in M365 admin center."`,
warning:'After converting, remove the Exchange Online license. Shared mailboxes under 50GB need no license.'}
]},

// ════ INTUNE ════

{id:'i1',cat:'intune',icon:'💻',title:'Device Compliance Audit',difficulty:'Easy',
desc:'Audit compliance status, identify non-compliant devices, and trigger policy sync.',
steps:[
{title:'Get Compliance Summary by OS',desc:'High-level compliance breakdown by OS.',
code:`Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All"
$devices = Get-MgDeviceManagementManagedDevice -All
$devices | Group-Object ComplianceState | Select-Object Name,Count | Format-Table -AutoSize
$devices | Group-Object OperatingSystem | ForEach-Object {
    [PSCustomObject]@{OS=$_.Name;Total=$_.Count;Compliant=($_.Group|Where-Object ComplianceState -eq "compliant").Count}
} | Format-Table -AutoSize`},
{title:'List Non-Compliant Devices',desc:'Detailed list of non-compliant devices.',
code:`Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All"
Get-MgDeviceManagementManagedDevice -All |
  Where-Object{$_.ComplianceState -ne "compliant"} |
  Select-Object DeviceName,@{N='User';E={$_.UserPrincipalName}},OperatingSystem,ComplianceState,
    @{N='LastSync';E={$_.LastSyncDateTime.ToString("yyyy-MM-dd HH:mm")}} | Sort-Object LastSync | Format-Table -AutoSize`},
{title:'Review Compliance Policy Assignments',desc:'List policies and assigned groups.',
code:`Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
Get-MgDeviceManagementDeviceCompliancePolicy -All | ForEach-Object {
    Write-Host "=== $($_.DisplayName) ===" -ForegroundColor Cyan
    Get-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $_.Id |
      ForEach-Object{$_.Target | ConvertTo-Json -Compress}
}`},
{title:'Trigger Device Sync',desc:'Push a sync to a specific device.',
code:`Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All"
$deviceId = "00000000-0000-0000-0000-000000000000"
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/syncDevice"
Write-Host "Sync triggered."`}
]},

{id:'i2',cat:'intune',icon:'🚀',title:'Autopilot Enrollment Troubleshoot',difficulty:'Advanced',
desc:'Diagnose Autopilot registration, hash import, profile assignment, and OOBE failures.',
steps:[
{title:'Check Device Registration',desc:'Verify device is registered by serial number.',
code:`Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All"
Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All |
  Where-Object{$_.SerialNumber -eq "SERIAL123"} |
  Select-Object SerialNumber,Model,GroupTag,EnrollmentState,AzureActiveDirectoryDeviceId | Format-List`},
{title:'Import Hardware Hash',desc:'Capture and import device hash for Autopilot.',
code:`Install-Script -Name Get-WindowsAutopilotInfo -Force
Get-WindowsAutopilotInfo -OutputFile "C:\hash.csv"
Write-Host "Hash captured. Import via Intune > Enrollment > Windows > Devices > Import."`,
info:'Import sync can take 15-30 minutes. Use the Sync button in the Intune portal after import.'},
{title:'Check Autopilot Profile Assignment',desc:'Verify the correct deployment profile is assigned.',
code:`Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All"
Get-MgDeviceManagementWindowsAutopilotDeploymentProfile -All |
  Select-Object DisplayName,DeviceType,EnableWhiteGlove | Format-Table -AutoSize`},
{title:'Review Enrollment Status Page (ESP)',desc:'Check ESP timeout and block settings.',
code:`Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
Get-MgDeviceManagementDeviceEnrollmentConfiguration -All |
  Where-Object{$_.'@odata.type' -eq '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'} |
  Select-Object DisplayName,
    @{N='ShowESP';E={$_.AdditionalProperties.showInstallationProgress}},
    @{N='TimeoutMins';E={$_.AdditionalProperties.installProgressTimeoutInMinutes}} | Format-Table -AutoSize`,
info:'Default ESP timeout is 60 mins. Increase if apps are timing out during device setup.'}
]},

{id:'i3',cat:'intune',icon:'🔑',title:'BitLocker Key Recovery',difficulty:'Easy',
desc:'Retrieve BitLocker recovery keys from Intune/Entra ID for managed devices.',
steps:[
{title:'Get BitLocker Key for a Device',desc:'Retrieve the recovery key by device name.',
code:`Connect-MgGraph -Scopes "BitlockerKey.Read.All","DeviceManagementManagedDevices.Read.All"
$device = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq 'DESKTOP-ABC123'"
$keys = Get-MgInformationProtectionBitlockerRecoveryKey -All | Where-Object{$_.DeviceId -eq $device.AzureAdDeviceId}
$keys | ForEach-Object {
    $k = Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId $_.Id -Property key
    [PSCustomObject]@{Date=$_.CreatedDateTime;DriveType=$_.VolumeType;Key=$k.Key}
}`},
{title:'Search All BitLocker Keys',desc:'List all BitLocker keys stored in Entra ID.',
code:`Connect-MgGraph -Scopes "BitlockerKey.Read.All"
Get-MgInformationProtectionBitlockerRecoveryKey -All |
  Select-Object Id,DeviceId,CreatedDateTime,VolumeType | Format-Table -AutoSize`},
{title:'Verify BitLocker Policy Enforcement',desc:'Confirm a BitLocker policy is deployed via Intune.',
code:`Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
Get-MgDeviceManagementConfigurationPolicy -All |
  Where-Object{$_.Name -match "BitLocker|Encrypt"} | Select-Object Name,Id | Format-Table -AutoSize`,
warning:'Recovery keys are sensitive. Ensure only authorized staff have BitlockerKey.Read.All and audit access logs.'}
]},

{id:'i4',cat:'intune',icon:'📱',title:'App Deployment Troubleshoot',difficulty:'Medium',
desc:'Diagnose Intune app install failures, assignment gaps, and Win32 detection issues.',
steps:[
{title:'Get App Deployment Status',desc:'Check install state for an app across all assigned devices.',
code:`Connect-MgGraph -Scopes "DeviceManagementApps.Read.All"
$app = Get-MgDeviceAppManagementMobileApp -Filter "displayName eq 'YourAppName'"
Get-MgDeviceAppManagementMobileAppDeviceStatusesWithAppInstallSummary -MobileAppId $app.Id |
  Select-Object DeviceName,UserPrincipalName,InstallState,ErrorCode | Format-Table -AutoSize`},
{title:'List App Assignments',desc:'Review how the app is assigned and to which groups.',
code:`Connect-MgGraph -Scopes "DeviceManagementApps.Read.All"
Get-MgDeviceAppManagementMobileAppAssignment -MobileAppId "00000000-0000-0000-0000-000000000000" |
  Select-Object Intent,@{N='Target';E={$_.Target | ConvertTo-Json -Compress}} | Format-Table -AutoSize -Wrap`},
{title:'Check Win32 App Detection Rules',desc:'Review the detection method for a Win32 app.',
code:`Connect-MgGraph -Scopes "DeviceManagementApps.Read.All"
$app = Get-MgDeviceAppManagementMobileApp -Filter "displayName eq 'YourWin32App'"
($app | Get-MgDeviceAppManagementMobileAppAdditionalDetail).DetectionRules | ConvertTo-Json -Depth 5`,
info:'Common failure: detection rule does not match installed state. Verify file path, registry key, or MSI product code.'},
{title:'Force App Sync on Device',desc:'Trigger a device sync to re-push app installations.',
code:`Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All"
$deviceId = "00000000-0000-0000-0000-000000000000"
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/syncDevice"
Write-Host "Sync triggered. Allow 15-30 minutes for app re-evaluation."`}
]},

// ════ DEFENDER ════

{id:'d1',cat:'defender',icon:'🛡',title:'MDE Onboarding Check',difficulty:'Medium',
desc:'Verify MDE onboarding status, sensor health, and connectivity for Windows devices.',
steps:[
{title:'Check Onboarding via Intune',desc:'Verify which devices are onboarded to MDE.',
code:`Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All"
Get-MgDeviceManagementManagedDevice -All |
  Where-Object{$_.OperatingSystem -eq "Windows"} |
  Select-Object DeviceName,UserPrincipalName,ComplianceState,
    @{N='MDEOnboarded';E={$_.AdditionalProperties['isDefenderAgentOnboarded']}} | Format-Table -AutoSize`},
{title:'Check MDE Sensor Health',desc:'Query MDE machine sensor health via Security Center API.',
code:`# Requires MDE API token — see: https://learn.microsoft.com/microsoft-365/security/defender-endpoint/api-hello-world
$machines = Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines" -Headers @{Authorization="Bearer $mdeToken"}
$machines.value | Select-Object computerDnsName,osPlatform,healthStatus,onboardingStatus,lastSeen | Format-Table -AutoSize`},
{title:'Test MDE Connectivity from Endpoint',desc:'Test required MDE endpoints on port 443.',
code:`@("onboardingpackagescusprd.blob.core.windows.net","winatp-gw-cus.microsoft.com",
  "us.vortex-win.data.microsoft.com","settings-win.data.microsoft.com") | ForEach-Object {
    $r = Test-NetConnection -ComputerName $_ -Port 443 -WarningAction SilentlyContinue
    [PSCustomObject]@{Endpoint=$_;Port443=$r.TcpTestSucceeded}
} | Format-Table -AutoSize`},
{title:'Check Local AV Status',desc:'Query Defender AV state and signature version on the endpoint.',
code:`Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,QuickScanAge`}
]},

{id:'d2',cat:'defender',icon:'🚨',title:'Incident Response – Isolate Device',difficulty:'Advanced',
desc:'Contain a suspected compromise — isolate device, revoke sessions, collect evidence.',
steps:[
{title:'Isolate Device via MDE',desc:'Cut off network access while maintaining MDE connection.',
code:`$deviceId = "MDE_MACHINE_ID_HERE"
Invoke-RestMethod -Method POST -Uri "https://api.securitycenter.microsoft.com/api/machines/$deviceId/isolate" -Headers @{Authorization="Bearer $mdeToken"} -Body '{"Comment":"IR isolation - ticket #123"}' -ContentType "application/json"`,
warning:'Isolation blocks all network traffic except MDE telemetry. Notify the device owner and IR team.'},
{title:'Revoke User Sessions in Entra',desc:'Invalidate all refresh tokens and disable the account.',
code:`Connect-MgGraph -Scopes "User.ReadWrite.All"
$upn = "compromised.user@contoso.com"
Invoke-MgInvalidateUserRefreshToken -UserId $upn
Update-MgUser -UserId $upn -AccountEnabled:$false
Write-Host "Sessions revoked and account disabled." -ForegroundColor Red`},
{title:'Force Password Reset',desc:'Reset the password and require change at next logon.',
code:`Connect-MgGraph -Scopes "User.ReadWrite.All"
Update-MgUser -UserId "compromised.user@contoso.com" -PasswordProfile @{Password="Temp!R3set$(Get-Random)#IR";ForceChangePasswordNextSignIn=$true}`},
{title:'Collect Evidence from Audit Logs',desc:'Export sign-in and audit activity for IR timeline.',
code:`Connect-MgGraph -Scopes "AuditLog.Read.All"
$upn = "compromised.user@contoso.com"
Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$upn'" -Top 100 |
  Select-Object CreatedDateTime,IpAddress,AppDisplayName,@{N='Status';E={$_.Status.ErrorCode}} |
  Export-Csv "C:\IR\SignIns.csv" -NoTypeInformation
Get-MgAuditLogDirectoryAudit -Filter "initiatedBy/user/userPrincipalName eq '$upn'" -Top 100 |
  Select-Object ActivityDateTime,ActivityDisplayName,Result |
  Export-Csv "C:\IR\AuditLog.csv" -NoTypeInformation`}
]},

{id:'d3',cat:'defender',icon:'🔍',title:'Antivirus Policy & Exclusions Review',difficulty:'Medium',
desc:'Audit Defender AV policies, review exclusions, verify cloud protection settings.',
steps:[
{title:'Get AV Endpoint Security Policies',desc:'List Defender AV policies deployed via Intune.',
code:`Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
Get-MgDeviceManagementConfigurationPolicy -All |
  Where-Object{$_.Name -match "Antivirus|Defender|AV"} | Select-Object Name,Id,SettingCount | Format-Table -AutoSize`},
{title:'Check Local AV Exclusions on Endpoint',desc:'Review file, path, extension, and process exclusions.',
code:`$p = Get-MpPreference
Write-Host "Extension Exclusions:" ; $p.ExclusionExtension
Write-Host "Path Exclusions:"      ; $p.ExclusionPath
Write-Host "Process Exclusions:"   ; $p.ExclusionProcess`,
warning:'Broad exclusions (e.g., entire C:\Windows\Temp) significantly weaken protection. Review each entry.'},
{title:'Check RTP & Cloud Protection Settings',desc:'Verify real-time and cloud protection are enabled.',
code:`Get-MpPreference | Select-Object DisableRealtimeMonitoring,MAPSReporting,SubmitSamplesConsent,CloudBlockLevel,CloudExtendedTimeout,SignatureUpdateInterval`},
{title:'Force Signature Update & Quick Scan',desc:'Update signatures and run a quick scan.',
code:`Update-MpSignature
Write-Host "Signatures updated: $(Get-Date)"
Start-MpScan -ScanType QuickScan`}
]},

// ════ PURVIEW ════

{id:'p1',cat:'purview',icon:'🏷',title:'Sensitivity Labels Audit',difficulty:'Medium',
desc:'Review sensitivity label policies, check configuration, and find unlabeled SharePoint sites.',
steps:[
{title:'List All Sensitivity Labels & Policies',desc:'Get all labels and publishing policies.',
code:`Connect-IPPSSession
Get-Label | Select-Object DisplayName,Priority,IsActive,Guid | Format-Table -AutoSize
Get-LabelPolicy | Select-Object Name,Labels,AppliesTo | Format-Table -AutoSize`},
{title:'Check Mandatory Labeling Settings',desc:'Verify mandatory labeling and default label config.',
code:`Connect-IPPSSession
Get-LabelPolicy | ForEach-Object {
    Write-Host "=== $($_.Name) ===" -ForegroundColor Cyan
    $_.Settings | Format-List
}`},
{title:'Find Unlabeled SharePoint Sites',desc:'Check which SPO sites have no sensitivity label.',
code:`Connect-PnPOnline -Url "https://contoso-admin.sharepoint.com" -Interactive
Get-PnPTenantSite -IncludeOneDriveSites $false |
  Where-Object{-not $_.SensitivityLabel} | Select-Object Url,Title,Template | Format-Table -AutoSize`},
{title:'Search Label Activity in Audit Log',desc:'Query audit log for recent label application events.',
code:`Connect-IPPSSession
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -RecordType MipLabel -ResultSize 500 |
  Select-Object CreationDate,UserIds,Operations,
    @{N='LabelId';E={($_.AuditData | ConvertFrom-Json).SensitivityLabelEventData.SensitivityLabelId}} |
  Format-Table -AutoSize`}
]},

{id:'p2',cat:'purview',icon:'🔒',title:'DLP Policy Review',difficulty:'Medium',
desc:'Audit DLP policies, check rule hits, and investigate incidents.',
steps:[
{title:'List All DLP Policies',desc:'Get all DLP policies with workload targets and mode.',
code:`Connect-IPPSSession
Get-DlpCompliancePolicy | Select-Object Name,Mode,Enabled,Workload,WhenCreated | Format-Table -AutoSize`},
{title:'Get DLP Policy Rules',desc:'Review rules inside a specific DLP policy.',
code:`Connect-IPPSSession
Get-DlpComplianceRule -Policy "Your DLP Policy Name" |
  Select-Object Name,Disabled,Priority,@{N='ContentTypes';E={$_.ContentContainsSensitiveInformation | ConvertTo-Json -Compress}},BlockAccess | Format-List`},
{title:'Search DLP Incident Reports',desc:'Query recent DLP policy matches from the audit log.',
code:`Connect-IPPSSession
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -RecordType ComplianceDLPSharePoint -ResultSize 200 |
  Select-Object CreationDate,UserIds,Operations,
    @{N='Policy';E={($_.AuditData | ConvertFrom-Json).PolicyName}},
    @{N='Item';E={($_.AuditData | ConvertFrom-Json).ObjectId}} | Format-Table -AutoSize`},
{title:'Check Endpoint DLP Settings',desc:'Review DLP restrictions for Windows endpoints.',
code:`Connect-IPPSSession
$policy = Get-DlpCompliancePolicy | Where-Object{$_.Workload -match "Endpoint"}
Get-DlpComplianceRule -Policy $policy.Name |
  Select-Object Name,RestrictedApplications,PrinterGroups,RemovableMediaGroups | Format-List`}
]},

{id:'p3',cat:'purview',icon:'📋',title:'Retention Policy Audit',difficulty:'Easy',
desc:'Review retention policies, labels, and litigation hold configuration.',
steps:[
{title:'List All Retention Policies',desc:'Export all retention policies with workload targets.',
code:`Connect-IPPSSession
Get-RetentionCompliancePolicy | Select-Object Name,Enabled,Mode,Workload,SharePointLocation,ExchangeLocation | Format-Table -AutoSize`},
{title:'Check Retention Labels',desc:'List retention labels and their retention period.',
code:`Connect-IPPSSession
Get-ComplianceTag | Select-Object Name,RetentionAction,RetentionDuration,RetentionType,IsRecordLabel | Format-Table -AutoSize`},
{title:'Find Mailboxes on Litigation Hold',desc:'Identify mailboxes placed on Litigation Hold.',
code:`Connect-ExchangeOnline
Get-Mailbox -ResultSize Unlimited |
  Where-Object{$_.LitigationHoldEnabled} |
  Select-Object DisplayName,PrimarySmtpAddress,LitigationHoldDate,LitigationHoldOwner,LitigationHoldDuration | Format-Table -AutoSize`}
]},

// ════ SHAREPOINT ════

{id:'s1',cat:'spo',icon:'🌐',title:'SharePoint Site Permissions Audit',difficulty:'Medium',
desc:'Audit site permissions, find direct-access users, and review external sharing.',
steps:[
{title:'Get All Site Collections',desc:'Full list of SharePoint sites with sharing capability.',
code:`Connect-SPOService -Url "https://contoso-admin.sharepoint.com"
Get-SPOSite -Limit All | Select-Object Url,Title,Template,SharingCapability,StorageUsageCurrent,LockState | Format-Table -AutoSize`},
{title:'Get Site Permission Groups',desc:'List all owners, members, visitors for a site.',
code:`Connect-PnPOnline -Url "https://contoso.sharepoint.com/sites/YourSite" -Interactive
Get-PnPSiteGroup | ForEach-Object {
    Write-Host "=== $($_.Title) ===" -ForegroundColor Cyan
    Get-PnPGroupMember -Identity $_.Title | Select-Object Title,Email
}`},
{title:'Find Direct-Access Permissions',desc:'Identify users with permissions not through a group.',
code:`Connect-PnPOnline -Url "https://contoso.sharepoint.com/sites/YourSite" -Interactive
Get-PnPWebPermission | Where-Object{$_.MemberType -eq "User"} |
  Select-Object Member,PermissionLevel,MemberType | Format-Table -AutoSize`},
{title:'Review External Sharing Configuration',desc:'Check sharing settings at tenant and site level.',
code:`Connect-SPOService -Url "https://contoso-admin.sharepoint.com"
Get-SPOTenant | Select-Object SharingCapability,DefaultSharingLinkType,RequireAcceptingAccountMatchInvitedAccount
Get-SPOSite "https://contoso.sharepoint.com/sites/YourSite" |
  Select-Object SharingCapability,ExternalUserExpirationRequired,ExternalUserExpireInDays`}
]},

{id:'s2',cat:'spo',icon:'💾',title:'SharePoint Storage & Quota',difficulty:'Easy',
desc:'Check tenant storage, site quotas, and identify sites nearing limits.',
steps:[
{title:'Check Tenant Storage Usage',desc:'View total storage consumption.',
code:`Connect-SPOService -Url "https://contoso-admin.sharepoint.com"
Get-SPOTenant | Select-Object StorageQuota,StorageQuotaAllocated,@{N='UsedGB';E={[math]::Round($_.StorageQuotaUsed/1024,1)}}`},
{title:'Find the 20 Largest Sites',desc:'List top 20 sites by storage consumption.',
code:`Connect-SPOService -Url "https://contoso-admin.sharepoint.com"
Get-SPOSite -Limit All | Select-Object Url,Title,@{N='StorageGB';E={[math]::Round($_.StorageUsageCurrent/1024,2)}},StorageQuota |
  Sort-Object StorageGB -Descending | Select-Object -First 20 | Format-Table -AutoSize`},
{title:'Set Site Storage Quota',desc:'Assign a specific storage quota to a site.',
code:`Connect-SPOService -Url "https://contoso-admin.sharepoint.com"
Set-SPOSite -Identity "https://contoso.sharepoint.com/sites/YourSite" -StorageQuota 102400 -StorageQuotaWarningLevel 90000
# Values in MB: 102400MB = 100GB`}
]},

// ════ M365 / GENERAL ════

{id:'m1',cat:'m365',icon:'👑',title:'Admin Role Assignment Review',difficulty:'Easy',
desc:'Audit who holds which admin roles in M365 — identify over-privileged accounts.',
steps:[
{title:'List All Admin Role Assignments',desc:'Full list of users with directory roles.',
code:`Connect-MgGraph -Scopes "RoleManagement.Read.Directory","User.Read.All"
Get-MgDirectoryRole -All | ForEach-Object {
    $role=$_; Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id | ForEach-Object {
        $u=try{Get-MgUser -UserId $_.Id -EA Stop}catch{$null}
        [PSCustomObject]@{Role=$role.DisplayName;User=$u?.UserPrincipalName ?? $_.Id}
    }
} | Sort-Object Role | Format-Table -AutoSize`},
{title:'Find All Global Administrators',desc:'List every Global Admin — this list should be short.',
code:`Connect-MgGraph -Scopes "RoleManagement.Read.Directory","User.Read.All"
$gaId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'").Id
Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$gaId'" -All | ForEach-Object {
    $u=try{Get-MgUser -UserId $_.PrincipalId -EA Stop}catch{$null}
    [PSCustomObject]@{UPN=$u?.UserPrincipalName ?? $_.PrincipalId;Scope=$_.DirectoryScopeId}
} | Format-Table -AutoSize`,
warning:'Microsoft recommends 2-4 Global Admins maximum. More = larger attack surface.'},
{title:'Get Last Sign-in for Admin Accounts',desc:'Identify stale or inactive admin accounts.',
code:`Connect-MgGraph -Scopes "RoleManagement.Read.Directory","User.Read.All","AuditLog.Read.All"
$gaId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'").Id
Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$gaId'" -All | ForEach-Object {
    $u=try{Get-MgUser -UserId $_.PrincipalId -Property "UserPrincipalName,SignInActivity" -EA Stop}catch{$null}
    if($u){[PSCustomObject]@{UPN=$u.UserPrincipalName;LastSignIn=$u.SignInActivity?.LastSignInDateTime?.ToString("yyyy-MM-dd") ?? "Never"}}
} | Format-Table -AutoSize`}
]},

{id:'m2',cat:'m365',icon:'🔍',title:'Unified Audit Log Investigation',difficulty:'Medium',
desc:'Search the Unified Audit Log for security events, admin actions, and data access.',
steps:[
{title:'Search by Operation',desc:'Find specific operations like file access or permission changes.',
code:`Connect-IPPSSession
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -Operations "FileAccessed","FileDownloaded","SharingInvitationCreated" -ResultSize 500 |
  Select-Object CreationDate,UserIds,Operations,@{N='Item';E={($_.AuditData | ConvertFrom-Json).ObjectId}} | Format-Table -AutoSize`},
{title:'Search All Activity by User',desc:'Get all audit events for a specific user.',
code:`Connect-IPPSSession
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds "user@contoso.com" -ResultSize 1000 |
  Select-Object CreationDate,Operations,RecordType | Sort-Object CreationDate |
  Export-Csv "C:\Audit_user.csv" -NoTypeInformation`},
{title:'Detect Bulk File Download (Exfiltration)',desc:'Identify users downloading unusual volumes of files.',
code:`Connect-IPPSSession
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations "FileDownloaded" -ResultSize 5000 |
  Group-Object UserIds | Select-Object Name,Count | Sort-Object Count -Descending |
  Where-Object Count -gt 50 | Format-Table -AutoSize`},
{title:'Search for Admin Role Changes',desc:'Find recent admin role additions or removals.',
code:`Connect-IPPSSession
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -Operations "Add member to role.","Remove member from role." -ResultSize 200 |
  Select-Object CreationDate,UserIds,Operations,@{N='Role';E={($_.AuditData | ConvertFrom-Json).ModifiedProperties.NewValue}} | Format-Table -AutoSize`}
]},

{id:'m3',cat:'m365',icon:'💬',title:'Teams Channel & Membership Audit',difficulty:'Easy',
desc:'Audit Teams membership, find inactive teams, review guest access.',
steps:[
{title:'List All Teams with Member Count',desc:'Export all Teams with membership statistics.',
code:`Connect-MgGraph -Scopes "Team.ReadBasic.All","Group.Read.All"
Get-MgGroup -Filter "resourceProvisioningOptions/Any(x:x eq 'Team')" -All | ForEach-Object {
    [PSCustomObject]@{Name=$_.DisplayName;Owners=(Get-MgGroupOwner -GroupId $_.Id).Count;
        Members=(Get-MgGroupMember -GroupId $_.Id).Count;Created=$_.CreatedDateTime?.ToString("yyyy-MM-dd");Visibility=$_.Visibility}
} | Sort-Object Members | Format-Table -AutoSize`},
{title:'Find Teams with No Owners',desc:'Identify ownerless teams.',
code:`Connect-MgGraph -Scopes "Team.ReadBasic.All","Group.Read.All"
Get-MgGroup -Filter "resourceProvisioningOptions/Any(x:x eq 'Team')" -All | ForEach-Object {
    if((Get-MgGroupOwner -GroupId $_.Id).Count -eq 0){[PSCustomObject]@{TeamName=$_.DisplayName;TeamId=$_.Id}}
} | Format-Table -AutoSize`,warning:'Ownerless teams cannot be self-managed. Assign owners or archive immediately.'},
{title:'List Guest Members in a Team',desc:'Find all external guests in a specific Team.',
code:`Connect-MgGraph -Scopes "Group.Read.All","User.Read.All"
$teamGroupId = "00000000-0000-0000-0000-000000000000"
Get-MgGroupMember -GroupId $teamGroupId -All |
  ForEach-Object{Get-MgUser -UserId $_.Id -Property "DisplayName,UserPrincipalName,UserType"} |
  Where-Object{$_.UserType -eq "Guest"} | Select-Object DisplayName,UserPrincipalName | Format-Table -AutoSize`},
{title:'Archive Inactive Teams',desc:'Archive stale teams using the Teams module.',
code:`Connect-MicrosoftTeams
Get-Team | Where-Object{$_.Archived -eq $false} | Select-Object DisplayName,GroupId | Format-Table -AutoSize
# To archive: Set-TeamArchivedState -GroupId "TEAM_GROUP_ID" -Archived $true`}
]},

{id:'m4',cat:'m365',icon:'🔔',title:'Service Health & Incident Check',difficulty:'Easy',
desc:'Check M365 service health, active incidents, and incident timelines.',
steps:[
{title:'Get Current Service Health',desc:'Real-time health — highlight degraded services.',
code:`Connect-MgGraph -Scopes "ServiceHealth.Read.All"
Get-MgServiceAnnouncementHealthOverview -All |
  Where-Object{$_.Status -ne "serviceOperational"} | Select-Object Service,Status | Format-Table -AutoSize`},
{title:'Get All Active Incidents',desc:'List active service incidents with severity.',
code:`Connect-MgGraph -Scopes "ServiceHealth.Read.All"
Get-MgServiceAnnouncementIssue -All |
  Where-Object{$_.Status -ne "resolved" -and $_.Status -ne "falsePositive"} |
  Select-Object Title,Service,Status,Severity,StartDateTime | Sort-Object StartDateTime | Format-Table -AutoSize`},
{title:'Get Incident Timeline & Updates',desc:'Read the full update timeline for a specific incident.',
code:`Connect-MgGraph -Scopes "ServiceHealth.Read.All"
$issue = Get-MgServiceAnnouncementIssue -ServiceHealthIssueId "EX123456"
$issue | Select-Object Title,Status,Service,Severity,StartDateTime
$issue.Posts | ForEach-Object {
    Write-Host "[$($_.CreatedDateTime)] $($_.PostType)" -ForegroundColor Cyan
    Write-Host $_.Description.Content
}`}
]},

// ════ NETWORK ════

{id:'n1',cat:'network',icon:'🌐',title:'DNS Resolution Troubleshoot',difficulty:'Easy',
desc:'Diagnose DNS failures, validate M365 DNS records, and flush cache.',
steps:[
{title:'Test DNS Against Multiple Servers',desc:'Test resolution using different DNS servers.',
code:`$host="login.microsoftonline.com"
@("8.8.8.8","1.1.1.1","9.9.9.9","<YOUR-DC-IP>") | ForEach-Object {
    try{$r=Resolve-DnsName -Name $host -Server $_ -EA Stop;[PSCustomObject]@{DNS=$_;IP=$r.IPAddress -join ',';Status="OK"}}
    catch{[PSCustomObject]@{DNS=$_;IP="";Status="FAILED"}}
} | Format-Table -AutoSize`},
{title:'Validate M365 DNS Records',desc:'Check MX, SPF, DKIM, and DMARC for your domain.',
code:`$d="contoso.com"
Write-Host "=== MX ===" -ForegroundColor Cyan; Resolve-DnsName $d -Type MX | Select-Object NameExchange,Preference
Write-Host "=== SPF ===" -ForegroundColor Cyan; Resolve-DnsName $d -Type TXT | Where-Object{$_.Strings -match "v=spf1"} | Select-Object -Expand Strings
Write-Host "=== DKIM selector1 ===" -ForegroundColor Cyan; try{Resolve-DnsName "selector1._domainkey.$d" -Type CNAME}catch{"Not found"}
Write-Host "=== DMARC ===" -ForegroundColor Cyan; Resolve-DnsName "_dmarc.$d" -Type TXT | Select-Object -Expand Strings`},
{title:'Flush DNS Cache',desc:'Clear DNS cache on client and DNS server.',
code:`Clear-DnsClientCache
Write-Host "Client DNS cache flushed."
# On DNS Server: Clear-DnsServerCache -ComputerName "DC01.contoso.com" -Force`},
{title:'Check DNS Forwarders on DC',desc:'Review DNS forwarder configuration.',
code:`Get-DnsServerForwarder | Select-Object IPAddress,TimeoutInterval,UseRootHint
Get-DnsServerRecursion  | Select-Object Enable,Timeout,SecureResponse`}
]},

{id:'n2',cat:'network',icon:'🔌',title:'M365 Network Connectivity Check',difficulty:'Easy',
desc:'Test M365 endpoint connectivity and diagnose proxy and TLS issues.',
steps:[
{title:'Test Core M365 Endpoints on Port 443',desc:'Verify connectivity to essential M365 URLs.',
code:`@("login.microsoftonline.com","outlook.office365.com","teams.microsoft.com","graph.microsoft.com","aadcdn.msftauth.net") | ForEach-Object {
    $r=Test-NetConnection -ComputerName $_ -Port 443 -WarningAction SilentlyContinue
    [PSCustomObject]@{Endpoint=$_;Port443=$r.TcpTestSucceeded;PingMs=$r.PingReplyDetails?.RoundtripTime}
} | Format-Table -AutoSize`},
{title:'Check Proxy Configuration',desc:'View proxy settings for system and browser traffic.',
code:`netsh winhttp show proxy
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable,ProxyServer,ProxyOverride`},
{title:'Verify TLS 1.2 Support',desc:'Confirm TLS 1.2 works — required for all M365 services.',
code:`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try{
    $req = [Net.HttpWebRequest]::Create("https://login.microsoftonline.com")
    $req.GetResponse() | Out-Null
    Write-Host "TLS 1.2 is working." -ForegroundColor Green
}catch{Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red}`},
{title:'Run M365 Network Connectivity Test',desc:'Use Microsoft connectivity tool for full assessment.',
code:`Start-Process "https://connectivity.office.com"
# Quick PowerShell endpoint check
@("https://login.microsoftonline.com","https://outlook.office365.com","https://graph.microsoft.com") | ForEach-Object {
    try{$r=Invoke-WebRequest $_ -UseBasicParsing -TimeoutSec 5 -EA Stop; Write-Host "OK [$($r.StatusCode)]: $_" -ForegroundColor Green}
    catch{Write-Host "FAIL: $_ - $($_.Exception.Message)" -ForegroundColor Red}
}`}
]},

// ════ WINDOWS SERVER ════

{id:'w1',cat:'winserver',icon:'🖥',title:'Windows Server Health Check',difficulty:'Easy',
desc:'Baseline health — CPU, memory, disk, critical services, and event log errors.',
steps:[
{title:'System Overview',desc:'OS version, uptime, CPU, and memory at a glance.',
code:`$os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem
[PSCustomObject]@{
    ComputerName=$env:COMPUTERNAME; OS=$os.Caption
    UptimeDays=[math]::Round((New-TimeSpan -Start $os.LastBootUpTime).TotalDays,1)
    Cores=$cs.NumberOfLogicalProcessors; RamGB=[math]::Round($cs.TotalPhysicalMemory/1GB,1)
    FreeRamGB=[math]::Round($os.FreePhysicalMemory/1MB,1)
}`},
{title:'Check Disk Space',desc:'View disk usage and free percentage on all volumes.',
code:`Get-PSDrive -PSProvider FileSystem |
  Select-Object Name, @{N='TotalGB';E={[math]::Round(($_.Used+$_.Free)/1GB,1)}},
    @{N='UsedGB';E={[math]::Round($_.Used/1GB,1)}}, @{N='FreeGB';E={[math]::Round($_.Free/1GB,1)}},
    @{N='Free%';E={[math]::Round($_.Free/($_.Used+$_.Free)*100,1)}} |
  Where-Object{$_.TotalGB -gt 0} | Format-Table -AutoSize`},
{title:'Check Critical Services',desc:'Verify Windows and AD services are running.',
code:`@("W32Time","Netlogon","DNS","ADWS","DFSR","kdc","LanmanServer","LanmanWorkstation","RpcSs","Spooler") |
  ForEach-Object{Get-Service -Name $_ -EA SilentlyContinue} |
  Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize`},
{title:'Review System Event Log Errors (24h)',desc:'Pull critical and error events from last 24 hours.',
code:`Get-WinEvent -FilterHashtable @{LogName="System","Application";Level=1,2;StartTime=(Get-Date).AddHours(-24)} -EA SilentlyContinue |
  Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message |
  Sort-Object TimeCreated -Descending | Select-Object -First 30 | Format-Table -AutoSize -Wrap`}
]},

{id:'w2',cat:'winserver',icon:'🔒',title:'Certificate Services (PKI) Check',difficulty:'Advanced',
desc:'Audit CA certs, find expired/expiring certs, and check template health.',
steps:[
{title:'List Certs from Local Machine Store',desc:'View all machine certs and flag expired/expiring ones.',
code:`Get-ChildItem Cert:\LocalMachine\My |
  Select-Object Subject,Issuer, @{N='Expires';E={$_.NotAfter.ToString("yyyy-MM-dd")}},
    @{N='DaysLeft';E={($_.NotAfter-(Get-Date)).Days}},Thumbprint |
  Sort-Object DaysLeft | Format-Table -AutoSize`},
{title:'Check CA Configuration & Templates',desc:'Review Enterprise CA and available certificate templates.',
code:`Import-Module ADCSAdministration
Get-CertificationAuthority | Select-Object ComputerName,Name,IsRoot,ValidityPeriod
certutil -catemplates`},
{title:'Find Expired CA Certs in Active Directory',desc:'Search AD for CA certificates that have expired.',
code:`$now=Get-Date
Get-ADObject -Filter{objectClass -eq "certificationAuthority"} -SearchBase "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com" -Properties cACertificate | ForEach-Object {
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]$_.cACertificate
    [PSCustomObject]@{CA=$_.Name;Expires=$cert.NotAfter.ToString("yyyy-MM-dd");DaysLeft=($cert.NotAfter-$now).Days}
} | Format-Table -AutoSize`,
warning:'An expired CA cert breaks all certificate validation in the domain. Monitor 90+ days in advance.'}
]},

{id:'w3',cat:'winserver',icon:'🖨',title:'Print Spooler Troubleshoot',difficulty:'Easy',
desc:'Diagnose spooler issues — stuck jobs, service crashes, and driver problems.',
steps:[
{title:'Check Spooler Status & Stuck Jobs',desc:'Verify the spooler service state.',
code:`Get-Service Spooler | Select-Object Name,Status,StartType
$jobs=Get-ChildItem "C:\Windows\System32\spool\PRINTERS" -EA SilentlyContinue
Write-Host "Stuck jobs in spool folder: $($jobs.Count)"`},
{title:'Clear Stuck Print Jobs',desc:'Stop spooler, clear stuck jobs, restart.',
code:`Stop-Service Spooler -Force
Remove-Item "C:\Windows\System32\spool\PRINTERS\*" -Force -EA SilentlyContinue
Start-Service Spooler
Write-Host "Spooler restarted." -ForegroundColor Green`},
{title:'List Installed Printer Drivers',desc:'Audit printer drivers and flag third-party ones.',
code:`Get-PrinterDriver | Select-Object Name,Manufacturer,DriverVersion,PrinterEnvironment | Sort-Object Manufacturer | Format-Table -AutoSize
Get-PrinterDriver | Where-Object{$_.Manufacturer -notmatch "Microsoft"} | Format-Table -AutoSize`,
info:'Buggy third-party printer drivers are the top cause of spooler crashes. Keep drivers updated.'}
]},

// ════ AUTOMATION ════

{id:'au1',cat:'automation',icon:'⚙️',title:'PowerShell Remoting Setup',difficulty:'Medium',
desc:'Configure and troubleshoot PowerShell Remoting (WinRM) for remote management.',
steps:[
{title:'Enable & Verify WinRM',desc:'Enable remoting and verify the WinRM listener.',
code:`Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-WSManQuickConfig -Force
Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTP"}
Test-WSMan -ComputerName localhost`},
{title:'Configure TrustedHosts',desc:'Add machines to TrustedHosts for non-domain remoting.',
code:`Get-Item WSMan:\localhost\Client\TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "Server01,Server02" -Concatenate -Force`,
warning:'Wildcard TrustedHosts (*) is a security risk. Use specific hostnames in production.'},
{title:'Test Remote Connection',desc:'Open a remote session and run a test command.',
code:`$server="Server01.contoso.com"; $cred=Get-Credential
Test-NetConnection -ComputerName $server -Port 5985
Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock {
    [PSCustomObject]@{Name=$env:COMPUTERNAME;OS=(Get-CimInstance Win32_OperatingSystem).Caption;
        UptimeDays=[math]::Round((Get-Date).Subtract((Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalDays,1)}
}`}
]},

{id:'au2',cat:'automation',icon:'🤖',title:'Scheduled Task Audit',difficulty:'Easy',
desc:'Audit scheduled tasks — find high-privilege tasks and verify script integrity.',
steps:[
{title:'List All Active Scheduled Tasks',desc:'Get all enabled tasks with run-as account and last result.',
code:`Get-ScheduledTask | ForEach-Object {
    $info=$_ | Get-ScheduledTaskInfo
    [PSCustomObject]@{TaskName=$_.TaskName;Path=$_.TaskPath;State=$_.State;RunAsUser=$_.Principal.UserId;
        LastRun=$info.LastRunTime;LastResult=$info.LastTaskResult;NextRun=$info.NextRunTime}
} | Where-Object{$_.State -ne "Disabled"} | Format-Table -AutoSize`},
{title:'Find Tasks Running as SYSTEM or Admin',desc:'Identify high-privilege tasks.',
code:`Get-ScheduledTask |
  Where-Object{$_.Principal.UserId -match "SYSTEM|Administrator|NETWORK SERVICE" -or $_.Principal.RunLevel -eq "Highest"} |
  Select-Object TaskName,TaskPath,@{N='RunAs';E={$_.Principal.UserId}},@{N='Elevated';E={$_.Principal.RunLevel}} | Format-Table -AutoSize`},
{title:'Verify Task Script Files Exist',desc:'Check script files referenced by tasks still exist.',
code:`Get-ScheduledTask | ForEach-Object {
    $_.Actions | Where-Object{$_.Execute -match "\.ps1|\.bat|\.cmd"} | ForEach-Object {
        $path=$_.Execute -replace '"',''
        [PSCustomObject]@{Task=$_.TaskName;Script=$path;Exists=Test-Path $path}
    }
} | Where-Object{-not $_.Exists} | Format-Table -AutoSize`}
]},

// ════ AZURE ════

{id:'az1',cat:'azure',icon:'☁️',title:'Azure RBAC & Access Review',difficulty:'Medium',
desc:'Audit Azure RBAC assignments, find over-privileged identities, and review custom roles.',
steps:[
{title:'List All Role Assignments at Subscription Level',desc:'Export all RBAC assignments.',
code:`Connect-AzAccount
Set-AzContext -SubscriptionId (Get-AzSubscription | Where-Object{$_.State -eq "Enabled"} | Select-Object -First 1 -ExpandProperty Id)
Get-AzRoleAssignment | Select-Object DisplayName,SignInName,RoleDefinitionName,Scope,ObjectType | Sort-Object RoleDefinitionName | Format-Table -AutoSize`},
{title:'Find Owner & Contributor at Subscription Scope',desc:'Identify high-privilege subscription-level assignments.',
code:`Get-AzRoleAssignment |
  Where-Object{$_.RoleDefinitionName -in @("Owner","Contributor") -and $_.Scope -match "^/subscriptions/[^/]+$"} |
  Select-Object DisplayName,SignInName,RoleDefinitionName,ObjectType | Format-Table -AutoSize`,
warning:'Owner at subscription scope = full control. Use resource group scoping instead.'},
{title:'Check Service Principal Role Assignments',desc:'Find all service principals with Azure RBAC roles.',
code:`Get-AzRoleAssignment | Where-Object{$_.ObjectType -eq "ServicePrincipal"} |
  Select-Object DisplayName,RoleDefinitionName,Scope,ObjectId | Format-Table -AutoSize`},
{title:'Review Custom Role Definitions',desc:'List custom RBAC roles and verify least privilege.',
code:`Get-AzRoleDefinition | Where-Object{$_.IsCustom} |
  Select-Object Name,Description,@{N='Actions';E={$_.Actions -join '; '}},@{N='NotActions';E={$_.NotActions -join '; '}} | Format-List`}
]},

{id:'az2',cat:'azure',icon:'💰',title:'Azure Resource & Cost Audit',difficulty:'Easy',
desc:'Find orphaned resources, stopped VMs, and unused IPs to optimize spend.',
steps:[
{title:'List All Resources by Type',desc:'Count of all resource types in the subscription.',
code:`Connect-AzAccount
Get-AzResource | Group-Object ResourceType | Select-Object Name,Count | Sort-Object Count -Descending | Format-Table -AutoSize`},
{title:'Find Orphaned Managed Disks',desc:'Identify managed disks not attached to any VM.',
code:`Get-AzDisk | Where-Object{$_.ManagedBy -eq $null} |
  Select-Object Name,ResourceGroupName,DiskSizeGB,@{N='SKU';E={$_.Sku.Name}},@{N='EstMonthly';E={"~$($_.DiskSizeGB * 0.05)/mo"}} |
  Format-Table -AutoSize`},
{title:'Find Deallocated (Stopped) VMs',desc:'List VMs that are stopped but still incurring disk charges.',
code:`Get-AzVM -Status | Where-Object{$_.PowerState -eq "VM deallocated"} |
  Select-Object Name,ResourceGroupName,Location,@{N='Size';E={$_.HardwareProfile.VmSize}},PowerState | Format-Table -AutoSize`},
{title:'Find Unused Public IP Addresses',desc:'Identify public IPs not associated with any resource.',
code:`Get-AzPublicIpAddress | Where-Object{$_.IpConfiguration -eq $null} |
  Select-Object Name,ResourceGroupName,Location,PublicIpAllocationMethod,IpAddress | Format-Table -AutoSize`}
]},

{id:'az3',cat:'azure',icon:'🔐',title:'Azure Key Vault Audit',difficulty:'Medium',
desc:'Review Key Vault access policies, check secret/cert expiry, and enable protection features.',
steps:[
{title:'List All Key Vaults & Access Policies',desc:'Export all Key Vaults with access policy config.',
code:`Connect-AzAccount
Get-AzKeyVault | ForEach-Object {
    $kv=Get-AzKeyVault -VaultName $_.VaultName
    $kv.AccessPolicies | ForEach-Object {
        [PSCustomObject]@{VaultName=$kv.VaultName;ObjectId=$_.ObjectId;DisplayName=$_.DisplayName;
            Keys=$_.PermissionsToKeys -join ',';Secrets=$_.PermissionsToSecrets -join ','}
    }
} | Format-Table -AutoSize`},
{title:'Check Secret & Certificate Expiry',desc:'List secrets and certs expiring within 30 days.',
code:`$now=Get-Date
Get-AzKeyVault | ForEach-Object {
    Write-Host "=== $($_.VaultName) ===" -ForegroundColor Cyan
    Get-AzKeyVaultSecret -VaultName $_.VaultName |
      Where-Object{$_.Expires -lt $now.AddDays(30)} |
      Select-Object Name,Enabled,@{N='Expires';E={$_.Expires?.ToString("yyyy-MM-dd")}},@{N='DaysLeft';E={($_.Expires-$now).Days}} | Format-Table -AutoSize
}`,warning:'Expired Key Vault secrets break dependent applications. Set expiry alerts via Azure Monitor.'},
{title:'Enable Soft Delete & Purge Protection',desc:'Verify all Key Vaults have protection features enabled.',
code:`Get-AzKeyVault | ForEach-Object {
    $kv=Get-AzKeyVault -VaultName $_.VaultName
    if(-not $kv.EnableSoftDelete -or -not $kv.EnablePurgeProtection){
        Write-Host "UNPROTECTED: $($_.VaultName) SoftDelete=$($kv.EnableSoftDelete) PurgeProtection=$($kv.EnablePurgeProtection)" -ForegroundColor Red
        # Update-AzKeyVault -VaultName $_.VaultName -EnableSoftDelete $true -EnablePurgeProtection $true
    }else{Write-Host "OK: $($_.VaultName)" -ForegroundColor Green}
}`,warning:'Without purge protection, deleted secrets can be permanently destroyed. Enable on all vaults.'}
]}

];
