Configuration HardenedAuditSettings
{
    Param (
        [bool]$isDomainController = $false
    )
    Import-DSCResource -ModuleName AuditPolicyDsc
    
    # based on this excellent blog - https://p0w3rsh3ll.wordpress.com/2016/11/14/audit-policy-and-dsc/
    # & Microsoft Security Baseline
    $MemberServerSettings = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Group Membership,{0cce9249-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Authorization Policy Change,{0cce9231-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit IPsec Driver,{0cce9213-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Other System Events,{0cce9214-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},Success and Failure,,3
'@

    $AdditionalDomainControllerSettings = @'
,System,Audit Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Directory Service Access,{0cce923b-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Directory Service Changes,{0cce923c-69ae-11d9-bed3-505054503030},Success and Failure,,3
'@    

    $settings = $MemberServerSettings
    if ($isDomainController)
    {
        $settings += $AdditionalDomainControllerSettings
    }

    File auditcsv {
        DestinationPath = 'C:\windows\temp\polaudit.csv'
        Force = $true
        Contents = $settings
    }

    AuditPolicyCsv auditPolicy
    {
        IsSingleInstance = 'Yes'
        CsvPath = 'C:\windows\temp\polaudit.csv'
        DependsOn = '[File]auditcsv'
    }
}
