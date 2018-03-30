<#
.SYNOPSIS

This is a DSC composite resource that can be used to harden a Windows OS.  Reasonable defaults that meet
CIS requirements are supplied, but can be overridden by parameters.

.PARAMETER PasswordHistory
TODO add detail

.EXAMPLE
TODO examples are good
.EXAMPLE
TODO more than one

#>
Configuration hardenedServerConfig
{
    param (

        [string]$CompanyName = "Example Organisation Ltd"

        #region: Common configurable parameters
        [string]$PreLogonMessageTitle = "Logon policy for $CompanyName"

        [string]$PreLogonMessageBody = @"
        This is a secured and audited system.
        Access is strictly for those persons authorised to do so, and use must be in line with $CompanyName Acceptable Use Policy.
        Attempts to access this system by unauthorised personal may result in criminal prosecution.
"@         

        [string]$renameGuestTo = 'secretGuestName'
        [string]$renameAdminTo = 'secretAdminName'

        [bool]$enableWinRM = $false

        [ValidateRange(3,24)]
        [int]$PasswordHistory = 15

        [ValidateRange(30,999)]    
        [int]$MaxPasswordAge = 42

        [ValidateRange(1,999)]        
        [int]$MinPasswordAge = 2

        [ValidateRange(8,14)]
        [int]$MinPasswordLength = 12   
        
        [int]$AccountLockoutThreshold = 5

        [ValidateRange(30,999)]
        [int]$AccountLockoutDuration = 30

        [ValidateRange(30,99999)]
        [int]$ResetAccountLockoutAfter = 30
        #endregion
        
        #region: Configurable parameters where care should be taken to understand impact
        [ValidateRange(4,10)]
        [int]$MaxLifetimeUserTkt = 4

        [ValidateRange(1,7)]
        [int]$MaxLifetimeUserTktRenewal = 1

        [ValidateSet('Enabled','Disabled')]
        $AllowShutdownWithoutLogon = 'Disabled'

        [ValidateSet('Enabled','Disabled')]
        $UACElevateSignedExecutablesOnly = 'Enabled'

        [ValidateSet('Enabled','Disabled')]
        $UACElevateLibrariesInSecureLocationsOnly = 'Enabled'
        
        #endregion
    )

    Import-DSCModule -ModuleName SecurityPolicyDsc

    #region: access settings

    # Verify the Windows folder permissions are properly setwindows-base-100
    # TODO Doesn't make sense - what does this do except check Windows is a directory?
    #win_file:
    #Key       = 'C:\windows'
    #state: directory

    # Safe DLL Search Mode is Enabled
    Registry windows-base-101
    {
        Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
        ValueName = "SafeDllSearchMode"
        ValueData = "0"
        ValueType = "dword"
    }

    # Anonymous Access to Windows Shares and Named Pipes is Disallowed
    Registry windows-base-102
    {
        Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
        ValueName = "RestrictNullSessAccess"
        ValueData = "1"
        ValueType = "dword"
    }

    # All Shares are Configured to Prevent Anonymous Access
    Registry windows-base-103
    {
        Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
        ValueName = "NullSessionShares"
        ValueData = ""
        ValueType = multistring
    }

    # Force Encrypted Windows Network Passwords
    Registry windows-base-104
    {
        Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        ValueName = "EnablePlainTextPassword"
        ValueData = "0"
        ValueType = "dword"
    }

    # Disable SMB1 to Windows Shares
    Registry windows-base-105
    {
        Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
        ValueName = "SMB1"
        ValueData = "0"
        ValueType = "dword"
    }

    # Strong Windows NTLMv2 Authentication Enabled; Weak LM Disabled
    Registry windows-base-201
    {
        Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
        ValueName = "LmCompatibilityLevel"
        ValueData = "4"
        ValueType = "dword"
    }

    # Enable Strong Encryption for Windows Network Sessions on Clients
    Registry windows-base-202
    {
        Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
        ValueName = "NtlmMinClientSec"
        ValueData = "537395200"
        ValueType = "dword"
    }

    # Enable Strong Encryption for Windows Network Sessions on Servers
    Registry windows-base-203
    {
        Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
        ValueName = "NtlmMinServerSec"
        ValueData = "537395200"
        ValueType = "dword"
    }

    #endregion

    #region: account policies

    # enforce password policy
    AccountPolicy AccountPolicies
    {
        Name = 'AccountPolicies'
        Enforce_password_history = $PasswordHistory
        Maximum_Password_Age = $MaxPasswordAge
        Minimum_Password_Age = $MinPasswordAge
        Minimum_Password_Length = $MinPasswordLength
        Password_must_meet_complexity_requirements = 'Enabled'
        Store_passwords_using_reversible_encryption = 'Disabled'
        Account_lockout_duration = $AccountLockoutDuration
        Account_lockout_threshold = $AccountLockoutThreshold
        Reset_account_lockout_counter_after = $ResetAccountLockoutAfter
        Maximum_lifetime_for_user_ticket = $MaxLifetimeUserTkt  
        Maximum_lifetime_for_user_ticket_renewal = 1
        Maximum_lifetime_for_service_ticket = 600
        Maximum_tolerance_for_computer_clock_synchronization = 5
    }

    # rename accounts & auditing global system objects
    SecurityOption AccountSecurityOptions
    {
        Name = 'AccountSecurityOptions'
        Accounts_Guest_account_status = 'Disabled'
        Accounts_Rename_guest_account = $renameGuestTo
        Accounts_Rename_administrator_account = $renameAdminTo
        Accounts_Block_Microsoft_accounts = 'This policy is disabled'
        Audit_Audit_the_access_of_global_system_objects = 'Enabled'
    }
    #endregion

    #region: security policies
    
    # this section contains most of the security policies, UAC and the interactive logon message follows this block
    SecurityOption NetworkSecurityOptions    
    {
        Name = 'NetworkSecurityOptions'        
        Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
        Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        Interactive_logon_Display_user_information_when_the_session_is_locked = 'Do not display user information'
        Interactive_logon_Do_not_display_last_user_name = 'Enabled'
        Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation = 'Enabled'
        Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
        Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = $SessionIdleTimeout
        Microsoft_network_server_Server_SPN_target_name_validation_level = 'Required from client'
        Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
        Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Enabled'
        Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        Network_security_LDAP_client_signing_requirements = 'Require Signing'
        Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = $AllowShutdownWithoutLogon
        Shutdown_Clear_virtual_memory_pagefile = 'Enabled'
        System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'Enabled'
        System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
    }    

    # UAC settings
    SecurityOption UACSecurityOptions
    {
        Name = 'UACSecurityOptions'
        User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Disabled'
        User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
        User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for credentials on the secure desktop'
        User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = $UACElevateSignedExecutablesOnly
        User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = $UACElevateLibrariesInSecureLocationsOnly
        User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
    }

    # display if either the title or the body is not null.
    if ($PreLogonMessageTitle -ne $null -or $PreLogonMessageBody -ne $null)
    {
        SecurityOption LogonMessage
        {
            Name = "LogonMessage"
            Interactive_logon_Message_text_for_users_attempting_to_log_on = $PreLogonMessageTitle
            Interactive_logon_Message_title_for_users_attempting_to_log_on = $PreLogonMessageBody
        }
    }
    #endregion

    #region: RDP settings

    # Windows Remote Desktop Configured to Always Prompt for Password
    Registry windows-rdp-100
    {
        Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        ValueName = 'fPromptForPassword'
        ValueData = '1'
        ValueType = '"dword"'
    }

    # Strong Encryption for Windows Remote Desktop Required 
    Registry windows-rdp-101
    {
        Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        ValueName = 'MinEncryptionLevel'
        ValueData = '3'
        ValueType = '"dword"'        
    }
    #endregion

    #region: User Rights

    # Assign shutdown privileges to only Builtin\Administrators
    UserRightsAssignment AssignShutdownPrivilegesToAdmins
    {
        Policy   = "Shut_down_the_system"
        Identity = "Builtin\Administrators"
        Force    = $true
    }

    # SeRemoteInteractiveLogonRight
    UserRightsAssignment LogonUsingRDS
    {
        Policy   = "Allow_log_on_through_Remote_Desktop_Services"
        Identity = "BUILTIN\Administrators" # S-1-5-32-544
        Force    = $true
    }

    # SeTcbPrivilege
    UserRightsAssignment ActAsTheOS
    {
        Policy   = "Act_as_part_of_the_operating_system"
        Identity = "NULL SID" # S-1-0-0 (Nobody)
        Force    = $true
    }
    
    # SeMachineAccountPrivilege
    UserRightsAssignment AddWorkstationToDomain
    {
        Policy   = "Add_workstations_to_domain"
        Identity = "BUILTIN\Administrators" # S-1-5-32-544
        Force    = $true
    }

    # SeTrustedCredManAccessPrivilege
    UserRightsAssignment TrustedCredManAccess
    {
        Policy   = "Access_Credential_Manager_as_a_trusted_caller"
        Identity = "NULL SID" # S-1-0-0 (Nobody)
        Force    = $true
    }     

    # SeNetworkLogonRight
    if ($enableWinRM)
    {
        UserRightsAssignment AccessOverNetwork
        {
            Policy   = "Access_this_computer_from_the_network"
            Identity = "BUILTIN\Administrators" # S-1-5-32-544
            Force    = $true
        }             
    }
    else {
        UserRightsAssignment AccessOverNetwork
        {
            Policy   = "Access_this_computer_from_the_network"
            Identity = "NULL SID" # S-1-0-0 (Nobody)
            Force    = $true
        }                  
    }
    #endregion

    #region: IE lockdown

    #TODO

    #endregion

    #region: WinRM

    #TODO

    #endregion
}
