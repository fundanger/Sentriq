import type { RuleSeed } from "../types";

export const cloudSaasRules: RuleSeed[] = [
  // --- Impossible Travel (KQL) ---
  {
    family: {
      id: "fam-impossible-travel",
      name: "Impossible Travel - Geographically Improbable Sign-Ins",
      slug: "impossible-travel-geographic-anomaly",
      categoryId: "cat-cloud-saas",
      conceptDescription:
        "Impossible travel detection identifies when the same user account successfully authenticates from two geographically distant locations within a timeframe that makes physical travel between them infeasible - for example, a sign-in from New York followed 20 minutes later by a sign-in from Singapore. This is one of the foundational cloud identity detections because it directly indicates that credentials are being used from two different physical locations/devices simultaneously, which - barring VPN usage explaining the apparent location - means the credentials are compromised and in use by both the legitimate user and an attacker (or solely by an attacker who has the credentials while the legitimate user is also active elsewhere).\n\nThe calculation requires: (1) geolocation of the source IP for each sign-in event (via IP-to-geo databases, often built into the identity provider's risk-detection like Entra ID Identity Protection or Okta's ThreatInsight), (2) calculating the great-circle distance between the two locations, and (3) comparing the time elapsed between sign-ins against the maximum plausible travel speed (commercial aviation, roughly 500-900 km/h, is the usual benchmark - distances that would require faster-than-commercial-flight travel are flagged).\n\nThe most significant source of false positives is corporate VPN usage and cloud-based services that route traffic through geographically distributed egress points (e.g., a user's traffic appearing to originate from a cloud VPN exit node in a different country than their physical location, combined with their phone's mobile app authenticating from their actual location via cellular data). Modern identity providers' built-in risk engines (Entra ID Identity Protection, Okta) incorporate additional signals beyond raw geo-velocity - device trust, IP reputation, sign-in patterns - and should be preferred over a purely geo-velocity calculation where available; the KQL approach below is most useful for environments without those premium features, or as a secondary/validation detection.",
    },
    variants: [
      {
        id: "rule-impossible-travel-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel / Entra ID",
        title: "Impossible Travel - Sign-Ins from Distant Locations Within Implausible Timeframe",
        slug: "impossible-travel-signin-velocity-kql",
        descriptionSummary:
          "Detects successful sign-ins by the same user from two different countries within a time window shorter than plausible travel time, using Entra ID SigninLogs location data.",
        ruleBody: `// Impossible Travel: successive sign-ins from different countries
// within an implausible timeframe for physical travel
// Data source: SigninLogs (Entra ID / Azure AD)
let TimeWindow = 4h;
let MaxPlausibleSpeedKmh = 1000.0; // generous upper bound (commercial flight + margin)
SigninLogs
| where TimeGenerated >= ago(1d)
| where ResultType == 0 // successful sign-ins only
| where isnotempty(LocationDetails)
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    Latitude = todouble(LocationDetails.geoCoordinates.latitude),
    Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(Country)
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend
    PrevCountry = prev(Country),
    PrevTime = prev(TimeGenerated),
    PrevLat = prev(Latitude),
    PrevLon = prev(Longitude),
    PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser and Country != PrevCountry
| extend
    DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000.0,
    HoursElapsed = datetime_diff('second', TimeGenerated, PrevTime) / -3600.0
| where HoursElapsed > 0 and HoursElapsed < TimeWindow
| extend RequiredSpeedKmh = DistanceKm / HoursElapsed
| where RequiredSpeedKmh > MaxPlausibleSpeedKmh
| extend
    AccountCustomEntity = UserPrincipalName,
    Verdict = strcat("Impossible travel: ", PrevCountry, " -> ", Country, " in ", round(HoursElapsed * 60, 1), " minutes (", round(RequiredSpeedKmh,0), " km/h required)")
| project TimeGenerated, UserPrincipalName, PrevCountry, Country, PrevTime, DistanceKm, HoursElapsed, RequiredSpeedKmh, Verdict
| order by RequiredSpeedKmh desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (KQL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "The single largest source of false positives is corporate or consumer VPN usage - a user connecting through a VPN exit node in a different country than their physical location, especially if they toggle the VPN on/off, can produce a 'travel' pattern between their real location and the VPN exit location. Maintain a list of known corporate VPN egress IP ranges and exclude sign-ins from those IPs from the location calculation (or normalize them to a single 'Corporate VPN' location). Mobile carrier IP geolocation can also be imprecise (large carriers sometimes geolocate to a regional hub far from the user's actual location), causing apparent short-distance 'travel' that's actually just IP geolocation noise - the 1000 km/h threshold is intentionally conservative (above the speed of commercial aircraft) to reduce this noise, but environments with heavy VPN/mobile usage may need to raise it further or, better, switch to Entra ID Identity Protection's built-in 'Atypical travel' risk detection, which incorporates additional context (named locations, travel history per user) beyond raw velocity.",
        dataSourceRequirements:
          "Entra ID SigninLogs table (requires Azure AD Premium P1/P2 for full SigninLogs ingestion into Sentinel) with geo-coordinate enrichment enabled.",
        mitreTechniqueIds: ["T1078"],
        cveIds: [],
        tags: ["Impossible Travel", "Entra ID", "Identity Protection"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1078/",
            title: "MITRE ATT&CK - Valid Accounts",
            referenceType: "mitre_page",
          },
          {
            url: "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks",
            title: "Microsoft - Entra ID Protection Risk Detections",
            referenceType: "documentation",
          },
        ],
      },
    ],
  },

  // --- MFA Fatigue / Push Bombing (KQL) ---
  {
    family: {
      id: "fam-mfa-fatigue",
      name: "MFA Fatigue / Push Notification Bombing",
      slug: "mfa-fatigue-push-bombing",
      categoryId: "cat-cloud-saas",
      conceptDescription:
        "MFA fatigue (also called push bombing or MFA bombing) is a social-engineering technique where an attacker who has already obtained a user's primary credentials (password) repeatedly triggers MFA push notifications to the user's registered authenticator app, hoping the user will eventually approve one - either out of annoyance, confusion, or because they're tricked into believing it's a legitimate system prompt (sometimes combined with a phone call from the attacker posing as IT support, telling the user to 'approve the request to fix the issue'). This technique gained significant notoriety following its use in several major breaches (Uber 2022, Cisco 2022) where attackers gained initial access primarily through MFA fatigue rather than any technical vulnerability.\n\nThe attack is detectable purely through volume: a legitimate user triggers, at most, a handful of MFA prompts per day (typically one per sign-in session). An attacker conducting MFA fatigue will generate many MFA challenge requests for the same user in a short period - sometimes dozens within minutes - most of which will be denied or time out, until (if the attack succeeds) one is approved.\n\nDetection focuses on counting MFA 'requested' events (regardless of outcome) per user within a short window and alerting when the count exceeds a threshold that no legitimate workflow would produce - a single failed-then-retried sign-in might generate 2-3 MFA prompts, but 5+ within 10 minutes is highly anomalous. A secondary, higher-confidence pattern is a sequence of MFA denials followed by a single approval, especially if the approval occurs from a different device/location than the denials (suggesting the attacker is the one receiving prompts while the legitimate user, on a different device, eventually approves out of confusion) - though this specific sub-pattern requires correlating device IDs across the MFA events, which not all identity providers expose cleanly.",
    },
    variants: [
      {
        id: "rule-mfa-fatigue-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel / Entra ID",
        title: "MFA Fatigue - High Volume of MFA Prompts for Single User in Short Window",
        slug: "mfa-fatigue-high-volume-prompts-kql",
        descriptionSummary:
          "Detects a user receiving an abnormally high number of MFA push notifications within a short time window, with multiple denials/timeouts followed by an approval - the signature of MFA fatigue/push-bombing attacks.",
        ruleBody: `// MFA Fatigue / Push Bombing detection
// Data source: SigninLogs (Entra ID) - MFA detail captured in AuthenticationDetails
let TimeWindow = 15m;
let PromptThreshold = 5;
SigninLogs
| where TimeGenerated >= ago(1d)
| mv-expand AuthDetail = parse_json(AuthenticationDetails)
| where tostring(AuthDetail.authenticationMethod) has_any ("Mobile app notification", "Microsoft Authenticator")
| extend AuthResult = tostring(AuthDetail.authenticationStepResultDetail)
| summarize
    PromptCount = count(),
    DenialCount = countif(AuthResult has_any ("Denied", "Timeout", "declined")),
    ApprovalCount = countif(AuthResult has "succeeded"),
    Results = make_list(AuthResult),
    IPAddresses = make_set(IPAddress),
    FirstPrompt = min(TimeGenerated),
    LastPrompt = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, TimeWindow)
| where PromptCount >= PromptThreshold
| extend
    AccountCustomEntity = UserPrincipalName,
    SuspiciousPattern = (DenialCount >= 3 and ApprovalCount >= 1),
    Severity = iff(DenialCount >= 3 and ApprovalCount >= 1, "Critical", "High")
| project FirstPrompt, LastPrompt, UserPrincipalName, PromptCount, DenialCount, ApprovalCount, IPAddresses, SuspiciousPattern, Severity
| order by PromptCount desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (KQL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Users with poor connectivity (spotty Wi-Fi/cellular) may trigger multiple MFA prompts as sign-in attempts repeatedly fail and retry transparently - this typically produces 2-4 prompts, below the default threshold of 5. Users switching between multiple devices in quick succession (laptop, then phone, then a second laptop) during normal work can also generate several prompts; this is why `SuspiciousPattern` weights the denial-then-approval sequence more heavily than raw count alone. When this alert fires, the response should always include directly contacting the affected user via a channel OTHER than the one potentially compromised (e.g., a phone call, not email if email access is in question) to confirm whether they recognize the activity - this is one of the few detections where user self-report is a critical and fast verification step.",
        dataSourceRequirements:
          "Entra ID SigninLogs with AuthenticationDetails populated (requires Azure AD Premium P1/P2), ingested into Sentinel.",
        mitreTechniqueIds: ["T1621", "T1078"],
        cveIds: [],
        tags: ["MFA Fatigue", "Push Bombing", "Entra ID"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1621/",
            title: "MITRE ATT&CK - Multi-Factor Authentication Request Generation",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Suspicious OAuth Grant (KQL) ---
  {
    family: {
      id: "fam-suspicious-oauth-grant",
      name: "Suspicious OAuth Application Consent Grant",
      slug: "suspicious-oauth-consent-grant",
      categoryId: "cat-cloud-saas",
      conceptDescription:
        "OAuth consent phishing (also called 'illicit consent grant attacks') is a technique where an attacker tricks a user into granting an attacker-controlled or attacker-registered OAuth application access to their account data - mail, files, contacts, calendar - via the standard OAuth consent flow. Unlike credential phishing, this technique doesn't require stealing a password at all: the user clicks a malicious link, is redirected to a legitimate Microsoft/Google consent page (which can make it appear trustworthy since the URL is genuinely microsoft.com or google.com), and grants permissions to an application with a deceptive name (e.g., 'Office 365 Upgrade' or 'Document Viewer') that requests broad scopes like `Mail.Read`, `Files.ReadWrite.All`, or `offline_access`.\n\nOnce consent is granted, the attacker's application receives an OAuth token that persists independently of the user's password - changing the password does NOT revoke the OAuth grant, which is what makes this technique particularly persistent and dangerous. The attacker can then use the token to read the victim's mailbox, search for sensitive information, set up mail-forwarding rules, or access files, all without further interaction and without triggering MFA (since the OAuth token itself is the credential at this point).\n\nDetection focuses on Entra ID audit log events for 'Consent to application' and 'Add OAuth2PermissionGrant', filtering for: (1) applications not in a curated allowlist of known-good/verified publishers, (2) high-risk permission scopes (`Mail.Read`, `Mail.ReadWrite`, `Files.ReadWrite.All`, `offline_access`, `Directory.ReadWrite.All`), (3) consent granted by a single user (rather than an admin consenting on behalf of the organization, which goes through a different, more deliberate workflow), and (4) the application being newly registered or having a very low installation count across the tenant/Microsoft's broader ecosystem.",
    },
    variants: [
      {
        id: "rule-suspicious-oauth-grant-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel / Entra ID",
        title: "User-Consented OAuth Application Requesting High-Risk Permission Scopes",
        slug: "user-consent-high-risk-oauth-scopes-kql",
        descriptionSummary:
          "Detects user (non-admin) consent grants to OAuth applications requesting high-risk permission scopes such as Mail.Read, Files.ReadWrite.All, or offline_access - a common OAuth consent phishing pattern.",
        ruleBody: `// Suspicious OAuth consent grant detection
// Data source: AuditLogs (Entra ID)
let HighRiskScopes = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.ReadWrite.All", "Files.Read.All",
    "Directory.ReadWrite.All", "Directory.Read.All",
    "offline_access", "User.Read.All"
]);
AuditLogs
| where TimeGenerated >= ago(1d)
| where OperationName in ("Consent to application", "Add OAuth2PermissionGrant", "Add app role assignment to service principal")
| extend
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    AppDisplayName = tostring(TargetResources[0].displayName),
    AppId = tostring(TargetResources[0].id)
| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties
| where tostring(ModifiedProperty.displayName) in ("ConsentAction.Permissions", "DelegatedPermissionGrant.Scope", "Scope")
| extend GrantedScopes = tostring(ModifiedProperty.newValue)
| where GrantedScopes has_any (HighRiskScopes)
| extend
    IsAdminConsent = OperationName has "admin" or InitiatedByUser == "" // admin/app-only consents typically lack a single user UPN in this context
| where not(IsAdminConsent)
| extend
    AccountCustomEntity = InitiatedByUser,
    Verdict = strcat("User-consented OAuth grant to '", AppDisplayName, "' with high-risk scopes: ", GrantedScopes)
| project TimeGenerated, InitiatedByUser, AppDisplayName, AppId, GrantedScopes, Verdict
| order by TimeGenerated desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (KQL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Many legitimate productivity integrations (calendar add-ins, e-signature tools like DocuSign, CRM email integrations like Salesforce/HubSpot connectors) legitimately request `Mail.Read` or `Files.ReadWrite.All` scopes and are consented to by individual users as part of normal software adoption. Build and maintain an allowlist of approved/verified publisher app IDs for commonly-used legitimate integrations to suppress these; for everything else, the alert should prompt a quick review of the app's publisher verification status (Microsoft 'Verified Publisher' badge) and installation count. Consider also implementing Entra ID admin-consent workflows (`Require admin consent for applications` policy) as a preventive control - this detection becomes primarily a monitor for whether that policy is being bypassed or has gaps, rather than the sole control.",
        dataSourceRequirements:
          "Entra ID AuditLogs table with application-consent audit events, ingested into Sentinel. Requires 'Enterprise Applications' audit logging enabled.",
        mitreTechniqueIds: ["T1528", "T1098.001"],
        cveIds: [],
        tags: ["OAuth", "Consent Phishing", "Entra ID"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1098/001/",
            title: "MITRE ATT&CK - Additional Cloud Credentials",
            referenceType: "mitre_page",
          },
          {
            url: "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants",
            title: "Microsoft - Detect and Remediate Illicit Consent Grants",
            referenceType: "documentation",
          },
        ],
      },
    ],
  },

  // --- AWS IAM Policy Change (Splunk) ---
  {
    family: {
      id: "fam-aws-iam-policy-change",
      name: "AWS IAM Privilege Escalation via Policy Modification",
      slug: "aws-iam-privilege-escalation-policy-change",
      categoryId: "cat-cloud-saas",
      conceptDescription:
        "AWS Identity and Access Management (IAM) privilege escalation occurs when a principal (user or role) with limited permissions modifies IAM policies - either their own, or another principal's - to grant themselves additional permissions, ultimately reaching administrative access. There are over 20 documented IAM privilege-escalation paths (cataloged extensively by security researchers), but common patterns include: `iam:CreatePolicyVersion` or `iam:SetDefaultPolicyVersion` to modify an existing policy's permissions, `iam:AttachUserPolicy`/`iam:AttachRolePolicy` to attach `AdministratorAccess` or another highly-privileged managed policy to themselves, `iam:CreateAccessKey` for another user (to obtain their credentials), or `iam:PassRole` combined with creating a new Lambda function/EC2 instance that assumes a more privileged role.\n\nThis technique is frequently observed following initial access via leaked AWS credentials (often found in public GitHub repositories, misconfigured CI/CD pipelines, or SSRF attacks against EC2 instance metadata endpoints to steal instance-role credentials). An attacker with even minimal IAM permissions on a compromised principal will often immediately attempt one of these escalation paths to convert limited access into full account control, since a single set of leaked low-privilege credentials is far less valuable than full administrative access to the AWS account.\n\nDetection via CloudTrail focuses on IAM API calls that modify permissions - `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `AddUserToGroup`, `CreateAccessKey` - performed by a principal other than a small set of known administrative roles/break-glass accounts, especially when the policy being attached is a broad managed policy (`AdministratorAccess`, `PowerUserAccess`) and especially when the modification targets the *calling principal's own* permissions (self-privilege-escalation) - the strongest single signal, since legitimate administrators virtually never need to grant additional permissions to the IAM identity they're currently authenticated as.",
    },
    variants: [
      {
        id: "rule-aws-iam-policy-change-splunk",
        language: "splunk",
        title: "AWS IAM Self-Privilege-Escalation via Policy Attachment or Modification",
        slug: "aws-iam-self-privesc-policy-attach-splunk",
        descriptionSummary:
          "SPL search detecting CloudTrail events where a principal attaches a highly-privileged managed policy to themselves, or modifies their own inline policy - a strong indicator of IAM privilege escalation following credential compromise.",
        ruleBody: `\`# AWS IAM Privilege Escalation Detection - Splunk SPL\`
\`# Detects self-targeted IAM policy modification/attachment events from CloudTrail\`

index=aws_cloudtrail sourcetype="aws:cloudtrail"
eventSource="iam.amazonaws.com"
eventName IN (
    "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AddUserToGroup", "CreateAccessKey"
)
| eval callerArn=mvindex(split(userIdentity.arn, "/"), -1)
| eval targetUser=mvindex(split(requestParameters.userName, ""), 0)
| eval targetRole=mvindex(split(requestParameters.roleName, ""), 0)
| eval isSelfTarget=if(
    (eventName="AttachUserPolicy" OR eventName="PutUserPolicy" OR eventName="AddUserToGroup" OR eventName="CreateAccessKey") AND targetUser=callerArn,
    "true",
    if((eventName="AttachRolePolicy" OR eventName="PutRolePolicy") AND targetRole=callerArn, "true", "false")
  )
| eval isHighPrivPolicy=if(
    match(requestParameters.policyArn, "(?i)(AdministratorAccess|PowerUserAccess|IAMFullAccess)"),
    "true", "false"
  )
| where isSelfTarget="true" OR isHighPrivPolicy="true"
| eval severity=case(
    isSelfTarget="true" AND isHighPrivPolicy="true", "critical",
    isSelfTarget="true" OR isHighPrivPolicy="true", "high",
    1=1, "medium"
  )
| table _time, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.userName, requestParameters.roleName, sourceIPAddress, isSelfTarget, isHighPrivPolicy, severity
| sort - _time`,
        ruleFormatVersion: "SPL (Search Processing Language)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Legitimate cloud administrators and infrastructure-as-code pipelines (Terraform, CloudFormation deployments run by a CI/CD service role) routinely perform these exact API calls as part of normal IAM management. The detection's value comes from filtering OUT known-good actors: maintain a lookup table of expected IAM-management principals (specific CI/CD roles, named human administrators) and exclude `userIdentity.arn` values matching that list - alert only on IAM policy changes from principals NOT on that list. The `isSelfTarget=true` condition is the highest-confidence signal regardless of allowlist status: even a legitimate administrator's role/user should essentially never need to grant *itself* additional permissions during normal operations (permission grants flow from a more-privileged admin to a less-privileged target, not self-directed), so self-targeting should always be reviewed even from otherwise-trusted principals.",
        dataSourceRequirements:
          "AWS CloudTrail logs (management events, specifically IAM API calls) ingested into Splunk via the AWS Add-on for Splunk or equivalent.",
        mitreTechniqueIds: ["T1098.003", "T1078"],
        cveIds: [],
        tags: ["AWS", "IAM", "Privilege Escalation", "CloudTrail"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1098/003/",
            title: "MITRE ATT&CK - Additional Cloud Roles",
            referenceType: "mitre_page",
          },
          {
            url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
            title: "AWS IAM - Policies and Permissions",
            referenceType: "documentation",
          },
        ],
      },
    ],
  },
];
