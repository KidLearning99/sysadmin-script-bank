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
]},

// ════ EXCHANGE ONLINE — REAL-WORLD TROUBLESHOOTING (42 SCENARIOS) ════

{id:'x8',cat:'exchange',icon:'📭',title:'External Partner Not Receiving Mail — Silent Drop at EOP',difficulty:'Advanced',
desc:'Partner reports zero emails received for 72h. No NDR generated on either side. Sent Items show delivered.',
steps:[
{title:'Run Message Trace',desc:'Confirm via extended message trace — filter last 7 days for sender/recipient pair.',
code:`Connect-ExchangeOnline
Get-MessageTrace -SenderAddress "user@yourdomain.com" -RecipientAddress "partner@domain.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) | FL`},
{title:'Decode the Delivery Status',desc:'Check status codes. Delivered+no hop = EOP handed off. FilteredAsSpam or GettingStatus = recipient gateway issue.',
code:`Get-MessageTraceDetail -MessageTraceId "PASTE_ID" -RecipientAddress "partner@domain.com" |
  Select-Object Date,Event,Action,Detail | Format-Table -AutoSize -Wrap`},
{title:'Check Outbound Connector TLS',desc:'If TLS is enforced and partner certificate expired, mail silently queues then drops.',
code:`Connect-ExchangeOnline
Get-OutboundConnector | Select-Object Name,TlsSettings,SmartHosts,Enabled | FL`},
{title:'Test SMTP Connectivity to Partner',desc:'Verify port 25 is reachable and review the banner.',
code:`Test-NetConnection -ComputerName "mail.partnerdomain.com" -Port 25`},
{title:'Engage Partner IT with EOP Headers',desc:'Request partner gateway logs for your sending IP visible in message trace headers. Their spam filter may be silently discarding.',
code:`# EOP outbound IPs published at: https://aka.ms/o365ips
# Share with partner IT to whitelist your sending IPs`,
info:'If connector enforces TLS and partner cert expired, messages queue silently and expire. Fix: remove TLS enforcement or update partner cert.'}
]},

{id:'x9',cat:'exchange',icon:'❌',title:'NDR 5.7.57 — SMTP Auth Blocked on Shared Mailbox',difficulty:'Medium',
desc:'Service account gets NDR 5.7.57: "Client not authenticated to send anonymous mail." Was working last week.',
steps:[
{title:'Check Authentication Policy',desc:'A security hardening run may have applied a policy blocking SMTP AUTH.',
code:`Connect-ExchangeOnline
Get-AuthenticationPolicy | FL`},
{title:'Inspect Mailbox-Level SMTP Auth Setting',desc:'Check if SMTP AUTH is explicitly disabled at the mailbox level.',
code:`Get-CASMailbox "SharedMailbox@domain.com" | FL SmtpClientAuthenticationDisabled`},
{title:'Check Org-Wide SMTP Auth Setting',desc:'If disabled at org level, all mailboxes are blocked regardless of per-mailbox setting.',
code:`Get-TransportConfig | FL SmtpClientAuthenticationDisabled`},
{title:'Re-Enable SMTP Auth for Specific Mailbox',desc:'Enable only for the shared mailbox — do not enable org-wide.',
code:`Set-CASMailbox "SharedMailbox@domain.com" -SmtpClientAuthenticationDisabled $false`,
warning:'Enabling SMTP AUTH org-wide is a security risk. Always scope to specific mailboxes only.'},
{title:'Verify App Credentials & Consider OAuth',desc:'Confirm the app uses correct credentials. Transition to Graph API or SMTP OAuth.',
code:`# Modern alternative: use Microsoft Graph API with OAuth
# https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth`,
info:'NDR 5.7.57 = SMTP AUTH attempted but blocked. Fix: per-mailbox re-enable and transition to OAuth long-term.'}
]},

{id:'x10',cat:'exchange',icon:'📩',title:'Legitimate Email Going to Spam — SPF Softfail from SaaS Relay',difficulty:'Easy',
desc:'Marketing newsletters via third-party SaaS platform land in recipients Junk. SPF record exists but SaaS relay IPs are missing.',
steps:[
{title:'Read Message Headers for SPF Result',desc:'Check Authentication-Results header in junk-delivered message.',
code:`# In raw headers look for:
# Authentication-Results: spf=softfail
# softfail (~all) allows delivery but marks as suspicious`},
{title:'Identify SaaS Sending IPs and Update SPF',desc:'Add the SaaS include mechanism to your SPF record.',
code:`# Current SPF check:
Resolve-DnsName "yourdomain.com" -Type TXT | Select-Object Strings
# Add SaaS include: v=spf1 include:_spf.yourdomain.com include:sendgrid.net ~all
# Validate: nslookup -type=TXT yourdomain.com`,
warning:'Do not exceed 10 DNS lookups in your SPF record — causes SPF permerror.'},
{title:'Set Up DKIM in SaaS Platform',desc:'Add CNAME records for DKIM signing — adds cryptographic pass stronger than SPF alone.',
code:`Connect-ExchangeOnline
Get-DkimSigningConfig | Select-Object Domain,Enabled,Status`},
{title:'Set DMARC Policy',desc:'Add DMARC record for monitoring then tighten enforcement.',
code:`# Add DNS TXT record: _dmarc.yourdomain.com
# v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
# Progress to p=quarantine once SPF+DKIM passing
Resolve-DnsName "_dmarc.yourdomain.com" -Type TXT`,
info:'SPF softfail + no DKIM = low composite auth score = junk. Fix: SPF include + DKIM CNAME + DMARC monitoring.'}
]},

{id:'x11',cat:'exchange',icon:'🔐',title:'Connector Failure After TLS Certificate Renewal',difficulty:'Advanced',
desc:'Inbound partner connector stopped after partner renewed their TLS cert. Messages queue with NDR 4.7.57.',
steps:[
{title:'Confirm Error in Message Trace',desc:'Extended trace shows exact TLS error: untrusted, expired, or subject mismatch.',
code:`Connect-ExchangeOnline
Get-MessageTrace -StartDate (Get-Date).AddDays(-2) -EndDate (Get-Date) | Where-Object{$_.Status -eq "Failed"} | FL`},
{title:'Inspect Connector TLS Settings',desc:'Find if TlsSenderCertificateName references the old CN.',
code:`Get-InboundConnector | FL Name,TlsSenderCertificateName,RequireTls,Enabled`},
{title:'Verify New Certificate CN from Partner',desc:'Get the new cert Subject CN and verify with test.',
code:`Test-NetConnection -ComputerName "mail.partner.com" -Port 25`},
{title:'Update Connector with New Certificate Name',desc:'Set the TlsSenderCertificateName to match the renewed certificate.',
code:`Set-InboundConnector -Identity "PartnerInbound" -TlsSenderCertificateName "mail.partner.com"`,
info:'Fix: update TlsSenderCertificateName to new CN. After updating, ask partner to resend a test message.'}
]},

{id:'x12',cat:'exchange',icon:'🔁',title:'Mail Loop — Hybrid Routing Misconfiguration',difficulty:'Advanced',
desc:'Message to on-prem mailbox bounces between EOP and on-prem. NDR 5.4.6: Routing loop detected.',
steps:[
{title:'Read X-MS-Exchange-Organization Headers',desc:'Open full headers — count hops and find where the loop turns back.',
code:`# Look for repeated Received: headers and X-MS-Exchange-Organization-SCL values
# Count where EOP and on-prem ping-pong`},
{title:'Check On-Prem Send Connector',desc:'Verify on-prem send connector is not routing all mail back to EOP.',
code:`# On Exchange Server 2016/2019:
Get-SendConnector | FL Name,AddressSpaces,SmartHosts,Enabled`},
{title:'Verify Accepted Domains Type',desc:'Domain must be InternalRelay (not Authoritative) if mailboxes remain on-prem.',
code:`Connect-ExchangeOnline
Get-AcceptedDomain | FL DomainName,DomainType`},
{title:'Fix Accepted Domain and Test',desc:'Change to InternalRelay for hybrid domain, or fix on-prem send connector smart host.',
code:`Set-AcceptedDomain -Identity "yourdomain.com" -DomainType InternalRelay`,
warning:'Authoritative + missing on-prem mailbox = loop. On-prem should route outbound to internet directly.'}
]},

{id:'x13',cat:'exchange',icon:'📆',title:'Calendar Meeting Requests Going to Junk',difficulty:'Medium',
desc:'Meeting invites from external partners arrive in Junk since a Defender policy change two weeks ago.',
steps:[
{title:'Read X-Forefront-Antispam-Report Header',desc:'Find the SCL value and identify what triggered the score.',
code:`# In raw headers look for:
# X-Forefront-Antispam-Report: SCL:5; CIP:x.x.x.x; ...
# SCL 5+ = spam classification`},
{title:'Check Allowed Sender Domains',desc:'Verify partner domain is in the org allowed sender list.',
code:`Connect-ExchangeOnline
Get-HostedContentFilterPolicy | Select-Object Name,AllowedSenderDomains,BulkThreshold | FL`},
{title:'Check Bulk Threshold Setting',desc:'Meeting platforms often have BCL-4. If BulkThreshold is too low, they get junked.',
code:`Get-HostedContentFilterPolicy | Select-Object Name,BulkThreshold`},
{title:'Add Domain to Safe Senders & Adjust Threshold',desc:'Whitelist the partner domain and raise bulk threshold.',
code:`Set-HostedContentFilterPolicy -Identity "Default" -AllowedSenderDomains @{Add="partner.com"} -BulkThreshold 6
Get-MessageTrace -Subject "Meeting" -StartDate (Get-Date).AddDays(-7) | Format-Table -AutoSize`,
info:'Real fix: encourage partner to implement DKIM+DMARC so their mail passes authentication properly.'}
]},

{id:'x14',cat:'exchange',icon:'📬',title:'NDR 5.2.2 — Mailbox Full Despite Cloud Storage',difficulty:'Medium',
desc:'User gets NDR 5.2.2 "mailbox full" from external senders. User has 100GB mailbox and it appears empty.',
steps:[
{title:'Check Total Mailbox Usage Including Recoverable Items',desc:'NDR 5.2.2 can be triggered by a full Recoverable Items folder, not just primary quota.',
code:`Connect-ExchangeOnline
Get-MailboxStatistics "user@domain.com" | Select-Object DisplayName,TotalItemSize,ItemCount,StorageLimitStatus`},
{title:'Check Recoverable Items Size',desc:'Recoverable Items has its own 30GB quota — common when Litigation Hold is enabled.',
code:`Get-MailboxFolderStatistics "user@domain.com" -FolderScope RecoverableItems |
  Select-Object Name,FolderSize | Format-Table -AutoSize`},
{title:'Enable Archive for Relief',desc:'Enable archive and create auto-move policy for old items.',
code:`Enable-Mailbox "user@domain.com" -Archive`},
{title:'Increase Recoverable Items Quota',desc:'Temporarily raise quota while investigating (requires E3+).',
code:`Set-Mailbox "user@domain.com" -RecoverableItemsQuota 60GB -RecoverableItemsWarningQuota 55GB`,
warning:'Validate with legal team before cleaning the dumpster if litigation hold is active.'}
]},

{id:'x15',cat:'exchange',icon:'⏱',title:'Delayed Mail — Greylisting by Receiving Domain',difficulty:'Easy',
desc:'Outbound messages to specific domain take 5-15 mins to deliver. No NDR. Recipients confirm late arrival.',
steps:[
{title:'Confirm via Message Trace',desc:'Look for multiple Temporary failure events followed by final Delivered — 4xx codes indicate greylisting.',
code:`Connect-ExchangeOnline
Get-MessageTraceDetail -MessageTraceId "PASTE_ID" | Select-Object Date,Event,Detail | Format-Table -AutoSize`},
{title:'Understand EOP IP Rotation',desc:'EOP rotates outbound IPs. Greylisting servers whitelist a specific IP — rotation resets the timer.',
code:`# EOP outbound IPs: https://aka.ms/o365ips
# Greylisting resets if IP changes between retries`},
{title:'Ask Partner to Whitelist EOP IP Ranges',desc:'Most direct fix — partner whitelists EOP outbound ranges.',
code:`# Direct partner IT to: https://aka.ms/o365ips
# Ask them to whitelist all EOP outbound IP ranges`},
{title:'Monitor Outbound Spam Filter Policy',desc:'Review outbound policy settings.',
code:`Get-HostedOutboundSpamFilterPolicy | FL`,
info:'Greylisting is a spam defense that temp-rejects first-time senders. Sender retries and succeeds — but with delay. No Exchange fix needed if routing is correct.'}
]},

{id:'x16',cat:'exchange',icon:'🔴',title:'Outbound Mail Blocked — User Added to Restricted Senders',difficulty:'Advanced',
desc:'User cannot send external mail. NDR: "Your account has been restricted." Internal mail works fine.',
steps:[
{title:'Verify in Restricted Senders List',desc:'Check Defender portal for the user in Restricted Entities.',
code:`# Microsoft Defender > Policies & Rules > Anti-spam > Restricted entities
# Note the timestamp of restriction`},
{title:'Investigate for Account Compromise',desc:'Check audit log for suspicious sign-ins, inbox rule changes, forwarding rules.',
code:`Connect-ExchangeOnline
Get-InboxRule -Mailbox "user@domain.com" | Select-Object Name,ForwardTo,ForwardAsAttachmentTo,DeleteMessage
Search-UnifiedAuditLog -UserIds "user@domain.com" -Operations "Set-InboxRule","New-InboxRule" -StartDate (Get-Date).AddDays(-7)`,
warning:'Never release from restricted list without first confirming the account is clean and secured.'},
{title:'Reset Credentials & Revoke Sessions',desc:'Force password reset and revoke all active sessions.',
code:`Connect-MgGraph -Scopes "User.ReadWrite.All"
Update-MgUser -UserId "user@domain.com" -PasswordProfile @{ForceChangePasswordNextSignIn=$true}
Invoke-MgInvalidateUserRefreshToken -UserId "user@domain.com"`},
{title:'Remove Forwarding Rules & Release Restriction',desc:'Delete suspicious inbox rules then remove from restricted list via Defender portal.',
code:`Remove-InboxRule -Mailbox "user@domain.com" -Identity "RuleIdHere" -Confirm:$false
# Then release from Defender portal: Restricted entities > select user > Release`,
info:'EOP auto-adds senders when outbound spam thresholds are exceeded — strong account compromise indicator.'}
]},

{id:'x17',cat:'exchange',icon:'🌐',title:'DMARC Failure — Subdomain Not Covered by SPF',difficulty:'Medium',
desc:'Notification emails from notifications.yourdomain.com fail DMARC at recipient gateways.',
steps:[
{title:'Check DMARC Record for Subdomain',desc:'If no subdomain DMARC record, subdomain inherits parent policy.',
code:`Resolve-DnsName "_dmarc.notifications.yourdomain.com" -Type TXT
Resolve-DnsName "_dmarc.yourdomain.com" -Type TXT`},
{title:'Check SPF for Subdomain',desc:'Subdomain needs its own SPF record — it does not inherit parent SPF.',
code:`Resolve-DnsName "notifications.yourdomain.com" -Type TXT`},
{title:'Create Subdomain SPF Record',desc:'Add TXT record scoped to that subdomain sending servers.',
code:`# DNS TXT record on notifications.yourdomain.com:
# v=spf1 include:servers.yourapplication.com ~all`},
{title:'Add DKIM & DMARC for Subdomain',desc:'Generate DKIM key in SaaS platform for the subdomain and publish monitoring DMARC.',
code:`Get-DkimSigningConfig | Select-Object Domain,Enabled,Status
# DNS: _dmarc.notifications.yourdomain.com TXT v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`,
info:'Parent DMARC p=reject causes all subdomain mail to be rejected if subdomain has no SPF/DKIM. Fix: subdomain-specific records.'}
]},

{id:'x18',cat:'exchange',icon:'🔄',title:'Out-of-Office Reply Looping to Mailing List',difficulty:'Medium',
desc:'Newsletter sent to 500 subscribers. One OOF replies to the list address, triggering another send — loop.',
steps:[
{title:'Identify Loop Source in Message Trace',desc:'Find repeated cycles between mailing list address and subscriber. OOF has Auto-Submitted: auto-replied header.',
code:`Connect-ExchangeOnline
Get-MessageTrace -SenderAddress "newsletter@domain.com" -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) | Format-Table -AutoSize`},
{title:'Check OOF External Setting',desc:'Verify if OOF is sending to all external including mailing lists.',
code:`Get-MailboxAutoReplyConfiguration -Identity "user@domain.com" | FL AutoReplyState,ExternalAudience`},
{title:'Check Remote Domain Auto-Reply Setting',desc:'Disable auto-replies to the mailing list domain.',
code:`Get-RemoteDomain | Select-Object DomainName,AutoReplyEnabled | FL
Set-RemoteDomain -Identity "*" -AutoReplyEnabled $false`},
{title:'Create Transport Rule to Block Auto-Replies to DL',desc:'Block messages where Auto-Submitted header is not "no" sent to the DL address.',
code:`New-TransportRule "Block Auto-Replies to DL" -HeaderMatchesMessageHeader "Auto-Submitted" -HeaderMatchesPatterns "auto-" -SentTo "newsletter@domain.com" -DeleteMessage $true`,
info:'Fix: block auto-replies via transport rule + set remote domain AutoReplyEnabled=$false.'}
]},

{id:'x19',cat:'exchange',icon:'🏢',title:'New Employee Cannot Receive External Mail — Accepted Domain Missing',difficulty:'Medium',
desc:'New team on custom domain (newbrand.com from merger) cannot receive external mail. NDR 5.1.10.',
steps:[
{title:'Check Accepted Domains',desc:'NDR 5.1.10 = recipient address not in Exchange routing tables.',
code:`Connect-ExchangeOnline
Get-AcceptedDomain | Select-Object DomainName,DomainType,IsDefault | Format-Table -AutoSize`},
{title:'Add Domain to Microsoft 365',desc:'Add domain, complete DNS verification, add MX/CNAME/SPF records.',
code:`# M365 Admin Center > Settings > Domains > Add Domain
# Add newbrand.com, verify with TXT record, add MX+SPF records`},
{title:'Verify Accepted Domain Type in EOP',desc:'After DNS verification, domain should be Authoritative for direct delivery.',
code:`New-AcceptedDomain -DomainName "newbrand.com" -DomainType Authoritative -Name "NewBrand"
Get-AcceptedDomain | Select-Object DomainName,DomainType`},
{title:'Assign Addresses to Mailboxes and Test',desc:'Set email address on newbrand.com for each mailbox.',
code:`Set-Mailbox -Identity "user@contoso.com" -EmailAddresses @{Add="user@newbrand.com"}
Get-Mailbox -ResultSize Unlimited | Where-Object{$_.EmailAddresses -like "*newbrand.com*"}`,
info:'Domain provisioned in Entra ID for identity but never added as Accepted Domain in Exchange. No MX record existed.'}
]},

{id:'x20',cat:'exchange',icon:'📎',title:'Large Attachments Silently Dropped',difficulty:'Easy',
desc:'Design team emails with 80-150MB CAD files sent externally never received. No NDR. Internal works fine.',
steps:[
{title:'Check Org Message Size Limits',desc:'Check org-level send/receive limits.',
code:`Connect-ExchangeOnline
Get-TransportConfig | Select-Object MaxSendSize,MaxReceiveSize`},
{title:'Check Connector-Level Limits',desc:'Connector may override org limit with a lower value.',
code:`Get-OutboundConnector | Select-Object Name,MaxMessageSize`},
{title:'Check Mailbox-Level Limits',desc:'Mailbox-level limits override org defaults.',
code:`Get-Mailbox "user@domain.com" | Select-Object MaxSendSize,MaxReceiveSize`},
{title:'Set Appropriate Limits or Redirect to SharePoint',desc:'Increase limit if business requirement, or redirect large files to SharePoint links.',
code:`Set-TransportConfig -MaxSendSize 150MB
# Better approach: share large files via SharePoint/OneDrive links`,
info:'Outbound connector MaxMessageSize was 30MB. Messages over limit were rejected with no NDR generated to sender.'}
]},

{id:'x21',cat:'exchange',icon:'🏨',title:'Conference Room Rejecting All Booking Requests',difficulty:'Easy',
desc:'Meeting booking requests to a conference room always get automatic decline. Was working last month.',
steps:[
{title:'Check Resource Booking Settings',desc:'Review all calendar processing settings.',
code:`Connect-ExchangeOnline
Get-CalendarProcessing -Identity "ConfRoom@domain.com" | FL AutomateProcessing,AllBookInPolicy,BookingWindowInDays,MaximumDurationInMinutes,ResourceDelegates`},
{title:'Fix AutomateProcessing',desc:'Must be AutoAccept for automatic booking.',
code:`Set-CalendarProcessing -Identity "ConfRoom@domain.com" -AutomateProcessing AutoAccept`},
{title:'Fix BookingWindowInDays',desc:'If reset to 0, all requests decline. Default is 180.',
code:`Set-CalendarProcessing -Identity "ConfRoom@domain.com" -BookingWindowInDays 180 -AllBookInPolicy $true
Get-Mailbox "ConfRoom@domain.com" | Select-Object ResourceType,IsResource`},
{title:'Test After Fix',desc:'Send a test meeting request and verify auto-accept.',
code:`# Send test meeting from any internal mailbox to confirm room auto-accepts
Get-CalendarProcessing -Identity "ConfRoom@domain.com" | Select-Object AutomateProcessing,BookingWindowInDays`,
info:'BookingWindowInDays reset to 0 during a policy sweep — room auto-declined all requests.'}
]},

{id:'x22',cat:'exchange',icon:'📰',title:'Journaling Stops — Journal Rule Not Delivering to Archive',difficulty:'Advanced',
desc:'Compliance team reports journal messages stopped arriving in third-party archiving system three days ago.',
steps:[
{title:'Check Journal Rule Status',desc:'Confirm rule is enabled and JournalEmailAddress is correct.',
code:`Connect-ExchangeOnline
Get-JournalRule | FL Name,Enabled,JournalEmailAddress,Scope`},
{title:'Check Alternate Journal Mailbox for NDRs',desc:'Exchange sends NDRs for failed journal delivery — check that mailbox.',
code:`Get-TransportConfig | Select-Object JournalingReportNdrTo`},
{title:'Verify Archiving Endpoint Availability',desc:'Test email delivery to journal endpoint manually.',
code:`# Send test to JournalEmailAddress directly from Outlook
# If fails: check TLS cert on archive system, check port/connector`},
{title:'Restart Journaling Flow',desc:'After fixing delivery issue, re-enable the rule.',
code:`Enable-JournalRule -Identity "ArchiveRule"
Set-TransportConfig -JournalingReportNdrTo "journalerrors@domain.com"`,
info:'Third-party archive TLS cert expired. Delivery failed silently. NDRs accumulated in unmonitored alternate journal mailbox.'}
]},

{id:'x23',cat:'exchange',icon:'🖥',title:'Mail Relay Rejected — App Server IP Not in Connector',difficulty:'Medium',
desc:'On-prem ERP returns SMTP 550 5.7.54: "SMTP relay not allowed" after a connector was rebuilt.',
steps:[
{title:'Identify the Sending IP',desc:'Find the application server outbound IP.',
code:`# Check ERP server network config for its outbound IP
# This IP appears in Exchange Online connection logs when relay is attempted`},
{title:'Check Connector IP Allowlist',desc:'Verify application server IP is in SenderIPAddresses.',
code:`Connect-ExchangeOnline
Get-InboundConnector | FL Name,ConnectorType,SenderIPAddresses,Enabled`},
{title:'Add IP to Connector',desc:'Add the application server IP to the relay connector.',
code:`Set-InboundConnector -Identity "AppRelayConnector" -SenderIPAddresses @{Add="10.10.5.22"}
# Or for subnet: use 10.10.5.0/24`},
{title:'Verify Connector Type and Test',desc:'Connector must be type OnPremises — not Default.',
code:`Get-InboundConnector | Select-Object Name,ConnectorType,SenderIPAddresses
New-InboundConnector -Name "AppRelay" -ConnectorType OnPremises -SenderIPAddresses "10.10.5.0/24"`,
info:'Inbound connector rebuild omitted ERP server IP. EOP rejected SMTP relay with 5.7.54.'}
]},

{id:'x24',cat:'exchange',icon:'👥',title:'Users Receiving Duplicate Emails',difficulty:'Easy',
desc:'Several users receive every external email twice — once directly, once via a distribution group.',
steps:[
{title:'Examine Duplicate Headers',desc:'Compare Message-ID — if identical, true duplication. Check To/CC/BCC.',
code:`# Compare raw headers of both copies
# Look for one copy showing a group address in To/CC`},
{title:'Check Group Membership Overlap',desc:'Affected users may be both direct recipients and members of a group also receiving the mail.',
code:`Connect-ExchangeOnline
Get-DistributionGroupMember -Identity "GroupName" | Select-Object Name,PrimarySmtpAddress`},
{title:'Check for Nested Group Overlap',desc:'If Group A includes Group B and both contain the same users, duplicates occur.',
code:`Get-DistributionGroup -ResultSize Unlimited | ForEach-Object {
    Get-DistributionGroupMember $_.Identity | Where-Object{$_.PrimarySmtpAddress -eq "user@domain.com"} |
    ForEach-Object{Write-Host "Found in: $($_.DisplayName)"}
}`},
{title:'Clean Group Membership',desc:'Remove direct memberships where user is already covered by nested group.',
code:`Remove-DistributionGroupMember -Identity "GroupName" -Member "user@domain.com" -Confirm:$false`,
info:'Reorganization created group including users already in parent group. Double membership path = duplicate delivery.'}
]},

{id:'x25',cat:'exchange',icon:'➡️',title:'External Forwarding Blocked — Anti-Exfiltration Policy',difficulty:'Medium',
desc:'Legitimate vendor requires auto-forwarding of support tickets externally. Inbox rules forward but mail never arrives externally.',
steps:[
{title:'Confirm Automatic Forwarding Block',desc:'Check outbound spam policy AutoForwardingMode.',
code:`Connect-ExchangeOnline
Get-HostedOutboundSpamFilterPolicy | Select-Object Name,AutoForwardingMode`},
{title:'Create Scoped Exception for Specific Users',desc:'New outbound spam filter policy applied to specific users only.',
code:`New-HostedOutboundSpamFilterPolicy -Name "AllowVendorForwarding" -AutoForwardingMode On
New-HostedOutboundSpamFilterRule -Name "VendorForwardRule" -HostedOutboundSpamFilterPolicy "AllowVendorForwarding" -SentTo "supportteam@domain.com"`},
{title:'Or Use a Transport Rule Instead',desc:'More secure: transport rule forwards specific messages rather than user-level permission.',
code:`New-TransportRule "ForwardToVendor" -SenderAddressLocation Header -FromScope InOrganization -SentToScope NotInOrganization -RedirectMessageTo "vendor@external.com"`},
{title:'Enable Forwarding Activity Alert',desc:'Monitor for unexpected forwarding even after exception is in place.',
code:`# Defender portal > Alert policies > New forwarding activity alert
Get-HostedOutboundSpamFilterPolicy | Select-Object Name,AutoForwardingMode`,
info:'Default outbound spam policy blocks all auto-forwarding (AutoForwardingMode: Automatic). Fix: scoped outbound policy for the specific user.'}
]},

{id:'x26',cat:'exchange',icon:'🎭',title:'CEO Display Name Spoofed — BEC Impersonation Attack',difficulty:'Advanced',
desc:'Users received emails appearing from CEO (Gmail address) asking for wire transfers. Display name matches exactly.',
steps:[
{title:'Analyze the Attack Emails',desc:'From header shows external address but Display Name matches CEO exactly.',
code:`# Raw headers: From: "CEO Name" <ceo.name@gmail.com>
# Real CEO: ceo@yourdomain.com
# This is display name spoofing, not domain spoofing`},
{title:'Enable Anti-Phishing Impersonation Protection',desc:'Add CEO to protected users list in anti-phishing policy.',
code:`Connect-ExchangeOnline
Get-AntiPhishPolicy | FL EnableTargetedUserProtection,TargetedUsersToProtect
Set-AntiPhishPolicy -Identity "Default" -EnableTargetedUserProtection $true -TargetedUsersToProtect @("CEO Name;ceo@yourdomain.com")`},
{title:'Enable Mailbox Intelligence',desc:'Learns communication patterns and flags external senders mimicking internal display names.',
code:`Set-AntiPhishPolicy -Identity "Default" -EnableMailboxIntelligence $true -EnableMailboxIntelligenceProtection $true`},
{title:'Enable First Contact Safety Tip & Run Attack Simulator',desc:'Visual tip for users + targeted training for finance and executive assistants.',
code:`Set-AntiPhishPolicy -Identity "Default" -EnableFirstContactSafetyTips $true
# Defender portal > Attack Simulation Training > BEC simulation`,
info:'Anti-phishing impersonation protection was not enabled. Fix: enable for C-level + mailbox intelligence + user training.'}
]},

{id:'x27',cat:'exchange',icon:'📊',title:'SPF Permerror — Record Exceeds 10-Lookup Limit',difficulty:'Medium',
desc:'Inbound mail from a specific domain fails SPF with "permerror — too many DNS lookups." They added a new include.',
steps:[
{title:'Count Current Lookups in SPF Record',desc:'Each include, a, mx, ptr, exists, redirect counts. Includes within includes add recursively.',
code:`Resolve-DnsName "yourdomain.com" -Type TXT | Select-Object Strings
# Use SPF checker at mxtoolbox.com/spf.aspx to count total lookups`},
{title:'Identify and Remove Redundant Mechanisms',desc:'Find outdated email service includes no longer in use.',
code:`nslookup -type=TXT yourdomain.com 8.8.8.8
# Check each include for current relevance`},
{title:'Flatten the SPF Record',desc:'Replace include mechanisms with their actual IP ranges.',
code:`Resolve-DnsName "_spf.google.com" -Type TXT
# Convert include:sendgrid.net to actual IPs — reduces lookup count to zero for those entries`},
{title:'Use SPF Management Service or Validate',desc:'Services like dmarcian handle SPF flattening automatically.',
code:`# After fix:
Resolve-DnsName "yourdomain.com" -Type TXT
# Validate at mxtoolbox.com/spf.aspx`,
info:'SPF accumulated 14 lookups after three new SaaS includes. Fix: flatten to IPs, reduce lookups below 10.'}
]},

{id:'x28',cat:'exchange',icon:'🏷',title:'Message Classification Label Causing Mail Blocks',difficulty:'Advanced',
desc:'"Project Confidential" sensitivity label is blocking external delivery even when external sharing is intended.',
steps:[
{title:'Identify the Blocking Transport Rule',desc:'Extended trace shows "Transport Rule" as block event. Get rule name.',
code:`Connect-ExchangeOnline
Get-TransportRule | Where-Object{$_.MessageContainsDataClassifications -ne $null} | FL Name,State,Conditions,Actions`},
{title:'Review Rule Conditions',desc:'Check if rule blocks all external delivery for the label without exceptions.',
code:`Get-TransportRule "ConfidentialBlock" | FL`},
{title:'Add Approved Domain Exception',desc:'Modify transport rule to exclude approved external partners.',
code:`Set-TransportRule "ConfidentialBlock" -ExceptIfSentTo @("trustedpartner@domain.com")
# Or: -ExceptIfSentToScope NotInOrganization for trusted domains list`},
{title:'Adjust Label Scope in Purview or Audit Usage',desc:'Edit sensitivity label external sharing permission or audit auto-labeling scope.',
code:`# Microsoft Purview > Information Protection > Labels > Edit label
# Specify whether external sharing is allowed
# Run Content Explorer report to see label usage`,
info:'Transport rule blocked all external delivery for label without exception for approved partners. Fix: add exception for approved domains.'}
]},

{id:'x29',cat:'exchange',icon:'📎',title:'Attachment Stripped by Safe Attachments Policy',difficulty:'Medium',
desc:'Recipients get emails with no attachment. Senders confirm they attached files. Email body arrives, attachment missing.',
steps:[
{title:'Check Safe Attachments Policy Action',desc:'If Action is Block, detected attachments are deleted with no notification.',
code:`Connect-ExchangeOnline
Get-SafeAttachmentPolicy | FL Name,Enable,Action,Redirect,RedirectAddress`},
{title:'Check Verdict in Threat Explorer',desc:'In Defender > Threat Explorer, search the message. Attachments column shows verdict.',
code:`# Defender portal > Threat Explorer > search by recipient/sender
# Check Attachments tab for: Malware, Suspicious, or Clean verdict`},
{title:'Enable Redirect Instead of Block',desc:'Send suspicious attachments to admin for review instead of silently dropping.',
code:`Set-SafeAttachmentPolicy -Identity "Default" -Redirect $true -RedirectAddress "securityadmin@domain.com" -Action Redirect`},
{title:'Submit False Positive for Reclassification',desc:'If file is known clean, submit for Microsoft re-evaluation.',
code:`Get-SafeAttachmentRule | FL Name,Priority,SafeAttachmentPolicy,RecipientDomainIs
# Defender portal > Submissions > Email Attachments > Submit for reclassification`,
info:'Safe Attachments Block mode silently removed macro-enabled Excel. No notification configured. Fix: enable redirect to admin.'}
]},

{id:'x30',cat:'exchange',icon:'📁',title:'Emails Appearing in Wrong Folder — Suspicious Inbox Rule',difficulty:'Advanced',
desc:'Emails from manager always go to subfolder "Archive-Old." User did not create this rule.',
steps:[
{title:'List Inbox Rules',desc:'Find the suspicious rule redirecting emails.',
code:`Connect-ExchangeOnline
Get-InboxRule -Mailbox "user@domain.com" | FL Name,Description,From,MoveToFolder,Enabled,RuleIdentity`},
{title:'Check Rule Creation in Audit Log',desc:'Find when and from where the rule was created.',
code:`Search-UnifiedAuditLog -Operations "New-InboxRule","Set-InboxRule" -UserIds "user@domain.com" -StartDate (Get-Date).AddDays(-30) |
  Select-Object CreationDate,UserIds,@{N='ClientIP';E={($_.AuditData | ConvertFrom-Json).ClientIP}}`},
{title:'Assess for Compromise Indicators',desc:'If unexpected geography or odd-hours creation — treat as compromise.',
code:`# Check Entra ID sign-in logs for suspicious activity
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'user@domain.com'" -Top 50 |
  Select-Object CreatedDateTime,IpAddress,Location | Format-Table -AutoSize`},
{title:'Remove the Rule & Secure Account',desc:'Delete suspicious rule, force password reset, revoke sessions.',
code:`Remove-InboxRule -Mailbox "user@domain.com" -Identity "RuleIdHere" -Confirm:$false
Connect-MgGraph -Scopes "User.ReadWrite.All"
Invoke-MgInvalidateUserRefreshToken -UserId "user@domain.com"
Update-MgUser -UserId "user@domain.com" -PasswordProfile @{ForceChangePasswordNextSignIn=$true}`,
warning:'Inbox rule created during compromised session redirecting mail to hidden subfolder — classic BEC monitoring tactic.'}
]},

{id:'x31',cat:'exchange',icon:'🌏',title:'Mail Arriving with Broken Encoding — Japanese Characters Garbled',difficulty:'Easy',
desc:'Japanese partner reports receiving emails with garbled characters — question marks replacing Asian text.',
steps:[
{title:'Read Raw Headers for Charset Declaration',desc:'Check Content-Type and Content-Transfer-Encoding headers.',
code:`# In raw headers look for:
# Content-Type: text/plain; charset=utf-8
# Content-Transfer-Encoding: base64
# Incorrect: charset=windows-1252 or charset=iso-2022-jp on UTF-8 content`},
{title:'Check Outlook Encoding Setting',desc:'Verify Outlook is set to use Unicode for outgoing messages.',
code:`# Outlook > File > Options > Advanced > International Options
# Enable: "Use Unicode (UTF-8) for outgoing messages"`},
{title:'Check Remote Domain Encoding Setting',desc:'Custom charset for the partner domain may conflict with UTF-8 content.',
code:`Connect-ExchangeOnline
Get-RemoteDomain | Select-Object DomainName,CharacterSet,NonMimeCharacterSet`},
{title:'Set Remote Domain to Unicode',desc:'Force UTF-8 encoding for messages to this domain.',
code:`Set-RemoteDomain -Identity "jp-partner.co.jp" -CharacterSet "utf-8" -NonMimeCharacterSet "iso-2022-jp"`,
info:'Remote domain setting forced ISO-2022-JP. UTF-8 Japanese content was re-encoded incorrectly. Fix: set CharacterSet to utf-8 for partner domain.'}
]},

{id:'x32',cat:'exchange',icon:'📜',title:'Mail Flow Rule Not Triggering — Condition Mismatch',difficulty:'Medium',
desc:'Compliance transport rule to add legal disclaimer to all outbound mail is not appending the footer.',
steps:[
{title:'Check Rule Conditions Including Scope',desc:'A scope of InOrganization means rule only triggers for internal mail.',
code:`Connect-ExchangeOnline
Get-TransportRule "DisclaimerRule" | FL Conditions,Exceptions,State,Priority,SentToScope`},
{title:'Fix SentToScope to NotInOrganization',desc:'For outbound mail, scope must be NotInOrganization.',
code:`Set-TransportRule "DisclaimerRule" -SentToScope NotInOrganization`},
{title:'Check Rule Priority for Stop Processing',desc:'Higher priority rule may have Stop Processing action blocking this rule.',
code:`Get-TransportRule | Sort-Object Priority | Select-Object Name,Priority,State | Format-Table -AutoSize`},
{title:'Verify Disclaimer Action & FallbackAction',desc:'FallbackAction should be Wrap, not Ignore or Reject.',
code:`Get-TransportRule "DisclaimerRule" | Select-Object ApplyHtmlDisclaimerText,ApplyHtmlDisclaimerFallbackAction
# Test by sending to external address and verify disclaimer appears`,
info:'SentToScope was InOrganization — external messages excluded. Disclaimer never applied. Fix: change to NotInOrganization.'}
]},

{id:'x33',cat:'exchange',icon:'📮',title:'Distribution List Not Receiving External Mail — NDR 5.7.133',difficulty:'Easy',
desc:'External vendor emails to DL bounce with NDR 5.7.133: "Group does not accept external messages."',
steps:[
{title:'Check DL External Sender Setting',desc:'RequireSenderAuthenticationEnabled=$true blocks all external senders.',
code:`Connect-ExchangeOnline
Get-DistributionGroup -Identity "groupname@domain.com" | Select-Object RequireSenderAuthenticationEnabled,ModerationEnabled,ModeratedBy`},
{title:'Allow External Senders',desc:'Set RequireSenderAuthenticationEnabled to false.',
code:`Set-DistributionGroup -Identity "groupname@domain.com" -RequireSenderAuthenticationEnabled $false`},
{title:'Check for Moderation Issues',desc:'If moderation on and no moderators assigned, external mail pends then auto-declines.',
code:`Get-DistributionGroup -Identity "groupname@domain.com" | Select-Object ModeratedBy,BypassModerationFromSendersOrMembers`},
{title:'Check AcceptMessagesOnlyFrom List',desc:'If populated, only listed senders can send to the group.',
code:`Get-DistributionGroup -Identity "groupname@domain.com" | Select-Object AcceptMessagesOnlyFrom,AcceptMessagesOnlyFromSendersOrMembers`,
info:'Policy modification enabled RequireSenderAuthenticationEnabled=$true, blocking external senders. Fix: set to $false.'}
]},

{id:'x34',cat:'exchange',icon:'🎣',title:'Phishing Bypassed All Filters — Whitelisted Sender Domain',difficulty:'Advanced',
desc:'Phishing email with credential-harvesting link delivered to multiple users. Domain was allowlisted 6 months ago.',
steps:[
{title:'Confirm Delivery Path in Threat Explorer',desc:'Check Overrides column — shows "Allowed Sender" as bypass reason.',
code:`# Defender portal > Threat Explorer > search message
# Check "Overrides" column for "Allowed Sender" bypass reason`},
{title:'Identify and Remove from Allowlist',desc:'Find the domain in AllowedSenderDomains and remove it.',
code:`Connect-ExchangeOnline
Get-HostedContentFilterPolicy | Select-Object AllowedSenders,AllowedSenderDomains | FL
Set-HostedContentFilterPolicy -Identity "Default" -AllowedSenderDomains @{Remove="compromiseddomain.com"}`},
{title:'Remediate Affected Users',desc:'Find all users who received mail from that domain in past 90 days and soft-delete.',
code:`New-ComplianceSearch -Name "PhishCleanup" -ExchangeLocation All -ContentMatchQuery "from:bad-domain.com"
Start-ComplianceSearch -Identity "PhishCleanup"
New-ComplianceSearchAction -SearchName "PhishCleanup" -Purge -PurgeType SoftDelete`},
{title:'Audit All Allowlist Entries',desc:'Remove entries without current documented business justification.',
code:`Get-HostedContentFilterPolicy | Select-Object AllowedSenders,AllowedSenderDomains | FL
# Review each entry — implement quarterly allowlist review process`,
warning:'Allowlisted domains bypass ALL anti-spam and anti-phishing checks. Never allowlist without documented justification and expiry date.'}
]},

{id:'x35',cat:'exchange',icon:'🔒',title:'Quarantine Release Not Working — User Cannot Self-Release',difficulty:'Medium',
desc:'End user quarantine release requests fail silently. Admins see requests but released messages never arrive.',
steps:[
{title:'Check Quarantine Policy on Anti-Spam Rule',desc:'QuarantineTag defines what end-users can do with quarantined items.',
code:`Connect-ExchangeOnline
Get-HostedContentFilterPolicy | Select-Object Name,SpamQuarantineTag,HighConfidenceSpamQuarantineTag | FL`},
{title:'Verify QuarantinePolicy Allows Release',desc:'AdminOnlyAccessPolicy blocks all end-user action.',
code:`Get-QuarantinePolicy | Select-Object Name,PermissionToRelease,PermissionToViewHeader,EsnEnabled | FL`},
{title:'Assign Appropriate Policy',desc:'Assign DefaultFullAccessPolicy to allow self-release.',
code:`Set-HostedContentFilterPolicy -Identity "Default" -SpamQuarantineTag "DefaultFullAccessPolicy"`},
{title:'Enable End-User Spam Notifications',desc:'Without ESN enabled, users never receive notification emails.',
code:`Set-QuarantinePolicy -Identity "DefaultFullAccessPolicy" -EsnEnabled $true
# Test: trigger spam quarantine on test message, log in to protection.office.com/quarantine`,
info:'QuarantineTag was AdminOnlyAccessPolicy — prevents end-user action. Fix: change to DefaultFullAccessPolicy + enable ESN.'}
]},

{id:'x36',cat:'exchange',icon:'🚚',title:'Migration Cutover — Some Users Unreachable After Cutover',difficulty:'Advanced',
desc:'After cutover migration to Exchange Online, mail to newly migrated users bounces with 5.1.1 NDR.',
steps:[
{title:'Confirm Mailbox Location',desc:'Check RecipientTypeDetails for successfully migrated users.',
code:`Connect-ExchangeOnline
Get-Mailbox -Identity "user@domain.com" | Select-Object RecipientTypeDetails,ServerName,ExchangeGuid`},
{title:'Check MX Record Propagation',desc:'MX must point to EOP — still pointing to on-prem blocks cloud mailbox delivery.',
code:`Resolve-DnsName "domain.com" -Type MX
# Should resolve to: tenant.mail.protection.outlook.com`},
{title:'Verify On-Prem Hybrid Routing',desc:'On-prem send connector must route cloud mailboxes to EOP during cutover period.',
code:`# On Exchange Server: Get-SendConnector to verify hybrid connector routing to EOP`},
{title:'Update Accepted Domain to Authoritative',desc:'After MX cutover, change from InternalRelay to Authoritative.',
code:`Get-AcceptedDomain | Select-Object DomainName,DomainType
Set-AcceptedDomain -Identity "yourdomain.com" -DomainType Authoritative`,
info:'MX pointed to EOP but Accepted Domain remained InternalRelay. EOP tried to relay to on-prem which no longer had mailbox. Fix: change to Authoritative after MX cutover.'}
]},

{id:'x37',cat:'exchange',icon:'🔐',title:'Sensitivity Label Encryption Preventing External Reply',difficulty:'Advanced',
desc:'Encrypt-Only label email cannot be replied to by external recipient. They receive "Access Denied."',
steps:[
{title:'Identify the Label Applied',desc:'Check email headers for MIP label GUID.',
code:`# In raw headers look for:
# msip_labels: or x-ms-exchange-organization-mip-label
# Identify label name and GUID`},
{title:'Check Label Rights in Purview',desc:'Review what rights external recipients receive — they may not be listed.',
code:`Connect-ExchangeOnline
Get-Label | Select-Object DisplayName,Guid,IsActive | Format-Table -AutoSize
# Microsoft Purview > Information Protection > Labels > Edit label > Assign Permissions Now`},
{title:'Add External Recipient Rights to Label',desc:'Edit label to include external recipients with Reply + Read rights.',
code:`# Purview > Labels > Edit > Assign permissions now > Add external users with Reviewer rights
Get-AIPFileStatus -Path "testfile.docx"  # If AIP PowerShell installed`},
{title:'Test with External Account',desc:'Send test protected message and attempt reply from external.',
code:`Get-RMSTemplate | Select-Object TemplateId,DefaultRightsDefinitions
# Verify Rights Management cert issued and permissions accessible`,
info:'Encrypt-Only label did not include external recipients in Rights Definition. Fix: edit label to add external users with Reviewer rights.'}
]},

{id:'x38',cat:'exchange',icon:'📤',title:'Shared Mailbox Auto-Mapping Missing in Outlook',difficulty:'Easy',
desc:'User granted Full Access to shared mailbox but it does not auto-appear in Outlook profile.',
steps:[
{title:'Check Auto-Mapping Status on the Permission',desc:'AutoMapping is set when permission is granted — cannot be changed in-place.',
code:`Connect-ExchangeOnline
Get-MailboxPermission -Identity "sharedmailbox@domain.com" | Where-Object{$_.User -like "user@domain.com"} | FL User,AccessRights,AutoMapping`},
{title:'Remove and Re-Add Permission with AutoMapping Enabled',desc:'AutoMapping=False is permanent — must remove and re-grant.',
code:`Remove-MailboxPermission -Identity "sharedmailbox@domain.com" -User "user@domain.com" -AccessRights FullAccess -Confirm:$false
Add-MailboxPermission -Identity "sharedmailbox@domain.com" -User "user@domain.com" -AccessRights FullAccess -AutoMapping $true`},
{title:'Restart Outlook and Wait for Autodiscover',desc:'Full close and reopen Outlook — allow up to 60 minutes after permission grant.',
code:`# User must fully close Outlook (not just minimize) and reopen
# Auto-mapping relies on Autodiscover service to add mailbox to profile`},
{title:'Test Autodiscover Chain if Still Missing',desc:'Run Outlook built-in autodiscover test.',
code:`# Hold Ctrl > Right-click Outlook in system tray > Test E-mail AutoConfiguration
# Verify MAPI URL resolves correctly`,
info:'Full Access granted with -AutoMapping $false. This is immutable. Fix: remove and re-add permission with AutoMapping $true.'}
]},

{id:'x39',cat:'exchange',icon:'⚖️',title:'Email Disclaimer Duplicating on Every Reply',difficulty:'Medium',
desc:'Legal disclaimer appended correctly to first send, but every reply in chain adds another copy.',
steps:[
{title:'Check Transport Rule for Missing Exceptions',desc:'Rule fires on every message including reply chains if no exception set.',
code:`Connect-ExchangeOnline
Get-TransportRule "DisclaimerRule" | FL Conditions,Exceptions`},
{title:'Add Exception for Existing Disclaimer Text',desc:'Skip if disclaimer text already exists in body.',
code:`Set-TransportRule "DisclaimerRule" -ExceptIfBodyContainsWords @("CONFIDENTIAL NOTICE","This email and any files")`},
{title:'Add Exception Based on Reply Header',desc:'References header exists only in replies — use to detect reply chains.',
code:`Set-TransportRule "DisclaimerRule" -ExceptIfHeaderContainsMessageHeader "In-Reply-To" -ExceptIfHeaderContainsWords "@"`},
{title:'Test Reply Chain Behavior',desc:'Verify disclaimer added on first send but not on subsequent replies.',
code:`Get-TransportRule | Sort-Object Priority | Select-Object Name,Priority,State | Format-Table -AutoSize
# Send new message > verify disclaimer added > reply > verify NOT added again`,
info:'No exception for reply chains or existing disclaimer text. Fix: add body-content exception matching disclaimer opening text.'}
]},

{id:'x40',cat:'exchange',icon:'🗄',title:'Archive Mailbox Items Not Visible in OWA',difficulty:'Easy',
desc:'User sees Online Archive in Outlook desktop but not in OWA. OWA shows archive folder as empty.',
steps:[
{title:'Verify Archive Provisioning & Auto-Expanding',desc:'Check if auto-expanding archive is enabled.',
code:`Connect-ExchangeOnline
Get-Mailbox "user@domain.com" | Select-Object ArchiveStatus,ArchiveGuid,AutoExpandingArchiveEnabled,ArchiveName`},
{title:'Understand Auto-Expanding Archive OWA Limitation',desc:'OWA can only display primary archive — auxiliary partitions from auto-expanding are not shown.',
code:`Get-MailboxStatistics "user@domain.com" -Archive | Select-Object TotalItemSize,ItemCount
# This is EXPECTED BEHAVIOR — not a bug`},
{title:'Use Outlook Desktop for Archive Access',desc:'Full MAPI client (Outlook desktop) accesses all archive partitions.',
code:`Enable-Mailbox "user@domain.com" -AutoExpandingArchive`},
{title:'Use Content Search for Compliance Needs',desc:'Purview Content Search accesses all archive partitions including auxiliary.',
code:`# Microsoft Purview > Content Search > include user as custodian
# Content Search is the correct tool for compliance searches across auto-expanded archives`,
info:'Auto-expanding archive auxiliary partitions only accessible via Outlook desktop (MAPI) and compliance tools. OWA limitation — expected behavior.'}
]},

{id:'x41',cat:'exchange',icon:'📱',title:'Mobile Device Cannot Sync Email — ActiveSync Blocked',difficulty:'Easy',
desc:'New smartphone cannot sync Exchange email — shows "Account verification failed." Other devices work fine.',
steps:[
{title:'Check Device Access State',desc:'New device may show as Quarantined or Blocked.',
code:`Connect-ExchangeOnline
Get-MobileDeviceStatistics -Mailbox "user@domain.com" | Select-Object DeviceFriendlyName,DeviceModel,Status,LastSyncAttemptTime`},
{title:'Check Organization Default Access Level',desc:'If Quarantine, new devices need admin approval. If Block, no new devices allowed.',
code:`Get-ActiveSyncOrganizationSettings | Select-Object DefaultAccessLevel`},
{title:'Allow the Specific Device',desc:'Approve quarantined device via EAC or PowerShell.',
code:`Set-CASMailbox -Identity "user@domain.com" -ActiveSyncAllowedDeviceIDs @{Add="DeviceIDHere"}
# Or approve via EAC mobile device quarantine portal`},
{title:'Check Device Access Rules & Verify After Allow',desc:'Rules may block specific device types or OS versions.',
code:`Get-ActiveSyncDeviceAccessRule | FL AccessLevel,QueryString
# After allowing, wait up to 1 hour then check:
Get-MobileDeviceStatistics -Mailbox "user@domain.com" | Select-Object DeviceFriendlyName,Status,LastSyncAttemptTime`,
info:'DefaultAccessLevel=Quarantine. New device quarantined pending admin approval. Fix: approve in EAC or add DeviceID to AllowedDeviceIDs.'}
]},

{id:'x42',cat:'exchange',icon:'📈',title:'Bulk Mail Campaign Triggering High Complaint Rate Alert',difficulty:'Medium',
desc:'Outbound spam alert fires for marketing mailbox. Sender approaching hourly limit. Campaign is legitimate but poorly configured.',
steps:[
{title:'Check Outbound Spam Policy Thresholds',desc:'Verify current limits and what action triggers.',
code:`Connect-ExchangeOnline
Get-HostedOutboundSpamFilterPolicy | FL RecipientLimitPerHour,RecipientLimitPerDay,ActionWhenThresholdReached`},
{title:'Review Campaign Configuration',desc:'Check for required elements: List-Unsubscribe header, proper From/Reply-To, plain text alternative.',
code:`Get-MessageTrace -SenderAddress "marketing@domain.com" -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) | Measure-Object`},
{title:'Move Campaign to Dedicated Sending Platform',desc:'Exchange Online is not designed for bulk marketing. Use SendGrid, Mailchimp, etc.',
code:`# Exchange Online sending limits per mailbox:
# 10,000 recipients/day; 500 recipients/message
# Dedicated platforms have proper IP pools and reputation management`},
{title:'Monitor IP Reputation',desc:'Check Microsoft SNDS for outbound IP complaint rate.',
code:`Get-HostedOutboundSpamFilterPolicy | Select-Object AutoForwardingMode,BccSuspiciousOutboundMail
# Check SNDS: https://sendersupport.olc.protection.outlook.com/snds/
# Complaint rate > 0.3% = address immediately`,
warning:'Complaint rate > 0.3% can lead to de-listing of EOP outbound IPs affecting your entire tenant. Move bulk mail to dedicated platform.'}
]},

{id:'x43',cat:'exchange',icon:'🔗',title:'Safe Links Breaking Third-Party SSO Links',difficulty:'Medium',
desc:'Users clicking SSO links in email get "Page Not Found." URL works when pasted directly in browser.',
steps:[
{title:'Confirm Safe Links Rewriting',desc:'Broken URL will start with https://nam.safelinks.protection.outlook.com/?url=...',
code:`Connect-ExchangeOnline
Get-SafeLinksPolicy | Select-Object Name,DoNotRewriteUrls,EnableForInternalSenders | FL`},
{title:'Test Decoded Original URL',desc:'Decode the wrapped URL — if original works, Safe Links wrapping is the issue.',
code:`# URL-decode the url= parameter from the safelinks URL
# Test decoded URL directly in browser
# If it works = Safe Links altered embedded SSO state token`},
{title:'Add SSO URL Pattern to Do Not Rewrite List',desc:'Exclude the SSO provider domain from URL rewriting.',
code:`Set-SafeLinksPolicy -Identity "Default" -DoNotRewriteUrls @{Add="https://sso.identityprovider.com/*"}
Get-SafeLinksRule | Select-Object Name,Priority,SafeLinksPolicy,RecipientDomainIs`},
{title:'Test End-to-End SSO Flow',desc:'Have user receive fresh SSO link email — verify URL is not wrapped.',
code:`Get-SafeLinksPolicy | Select-Object Name,DoNotRewriteUrls | FL
# Verify: URL starts with sso.identityprovider.com NOT safelinks.protection.outlook.com`,
info:'Safe Links wrapped SSO redirect URL, altering embedded SAML state token. IdP received malformed request. Fix: add SSO domain to DoNotRewriteUrls.'}
]},

{id:'x44',cat:'exchange',icon:'🔎',title:'Mailbox Audit Log Not Capturing Delegate Actions',difficulty:'Advanced',
desc:'Compliance investigation finds no audit events for delegate access to executive mailbox despite known access.',
steps:[
{title:'Check Mailbox Audit Status and Configured Actions',desc:'Verify audit is enabled and which delegate actions are logged.',
code:`Connect-ExchangeOnline
Get-Mailbox "exec@domain.com" | Select-Object AuditEnabled,AuditDelegate,AuditOwner,AuditAdmin`},
{title:'Understand Default vs Full Audit Actions',desc:'Default delegate actions logged: SendAs, SendOnBehalf, SoftDelete, HardDelete. FolderBind and Create are NOT logged by default.',
code:`# Default AuditDelegate actions do NOT include:
# FolderBind (reading mail), Create, Update, Move
# These must be explicitly added`},
{title:'Enable Additional Delegate Audit Actions',desc:'Add FolderBind to capture every time delegate opens a folder.',
code:`Set-Mailbox "exec@domain.com" -AuditDelegate @{Add="FolderBind","Create","Update","Move"}`,
warning:'FolderBind generates very high log volume. Historical access before enabling is not recoverable.'},
{title:'Search Audit Log for Delegate Activity',desc:'Query for newly enabled actions going forward.',
code:`Search-UnifiedAuditLog -Operations "FolderBind","SendAs" -UserIds "delegate@domain.com" -StartDate (Get-Date).AddDays(-30) |
  Select-Object CreationDate,UserIds,Operations | Format-Table -AutoSize
# For E5: Advanced Audit extends retention to 10 years`,
info:'AuditDelegate did not include FolderBind or Create. Historical access before enablement is permanently unrecoverable. Fix: add FolderBind to AuditDelegate.'}
]},

{id:'x45',cat:'exchange',icon:'🔗',title:'Hybrid Free/Busy Not Working After Tenant Migration',difficulty:'Advanced',
desc:'After tenant-to-tenant migration, source tenant users cannot see destination tenant free/busy.',
steps:[
{title:'Check Organization Relationship',desc:'Migration breaks existing Organization Relationships by default.',
code:`Connect-ExchangeOnline
Get-OrganizationRelationship | FL DomainNames,FreeBusyAccessEnabled,FreeBusyAccessLevel,TargetApplicationUri`},
{title:'Verify Federation Trust',desc:'Both tenants must have federation trusts with Microsoft Federation Gateway.',
code:`Get-FederationTrust | FL`},
{title:'Create New Organization Relationship',desc:'Create relationship pointing to destination tenant.',
code:`New-OrganizationRelationship -Name "CrossTenant" -DomainNames "destinationtenant.com" -FreeBusyAccessEnabled $true -FreeBusyAccessLevel LimitedDetails -TargetApplicationUri "outlook.com"`},
{title:'Test and Configure OAuth if Needed',desc:'Run test-OrganizationRelationship to identify exact failure point.',
code:`Test-OrganizationRelationship -Identity "CrossTenant" -UserIdentity "user@sourcetenant.com"
New-IntraOrganizationConnector -Name "CrossTenantConnector" -DiscoveryEndpoint "https://autodiscover.domain.com/autodiscover/autodiscover.svc" -Enabled $true`,
info:'Tenant migration invalidated existing Organization Relationship. Fix: create new Org Relationship pointing to destination tenant + test OAuth flow.'}
]}

];
