Configuration HardenedAuditSettings
{
    Param (
        [bool]$isDomainController = $false
    )
    Import-DSCResource -ModuleName AuditPolicyDsc,PSDesiredStateConfiguration
    
    # based on this excellent blog - https://p0w3rsh3ll.wordpress.com/2016/11/14/audit-policy-and-dsc/
    # & Microsoft Security Baseline
    $MemberServerSettings = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1
,System,Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,,1
,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},Success,,1
,System,Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},Success,,1
,System,Authorization Policy Change,{0cce9231-69ae-11d9-bed3-505054503030},Success,,1
,System,Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,IPsec Driver,{0cce9213-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Other System Events,{0cce9214-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},Success,,1
,System,Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},Success and Failure,,3
'@

    # requires specific build, not present on Win2k12 RTM, guessed to be 2016?  TODO research
    $2016Settings = @'
,System,PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},Success,,1
,System,Group Membership,{0cce9249-69ae-11d9-bed3-505054503030},Success,,1
'@

    $AdditionalDomainControllerSettings = @'
,System,Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success,,1
,System,Directory Service Access,{0cce923b-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Directory Service Changes,{0cce923c-69ae-11d9-bed3-505054503030},Success and Failure,,3
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
