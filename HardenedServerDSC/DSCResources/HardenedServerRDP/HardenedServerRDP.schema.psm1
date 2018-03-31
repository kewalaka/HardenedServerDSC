Configuration hardenedServerRDP
{
    param (
        [bool]$enableRDPRestrictedAdmin  = $false,

        [ValidateSet('Disabled', 'Require Restricted Admin', 'Require Remote Credential Guard', 'Restrict credential delegation')]
        [string]$enforceRDPRestrictedAdmin = 'Disabled'
    )

    Import-DSCResource -ModuleName xNetworking

    xFirewall Firewall-RDP
    {
        Name                  = "Remote Desktop - User Mode (TCP-In)"
        Ensure                = "Present"
        Enabled               = "True"
        Profile               = ("Domain", "Private")
    }

    # Windows Remote Desktop Configured to Always Prompt for Password
    Registry windows-rdp-100
    {
        Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        ValueName = 'fPromptForPassword'
        ValueData = '1'
        ValueType = 'Dword'
    }

    # Strong Encryption for Windows Remote Desktop Required 
    Registry windows-rdp-101
    {
        Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        ValueName = 'MinEncryptionLevel'
        ValueData = '3'
        ValueType = 'Dword'        
    }

    #region: restricted Admin Mode
    # for Win8 & Win2012 and below, see required update - https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2871997
    
    # enable server side
    if ($enableRDPRestrictedAdmin)
    {
        Registry EnableRestrictedAdmin
        {
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa'
            ValueName = 'DisableRestrictedAdmin'
            ValueData = '0'
            ValueType = 'Dword' 
        }   
    }

    # enforce client side
    # see https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsSSP::RestrictedRemoteAdministration
    switch ($enforceRDPRestrictedAdmin)
    {
        'Require Restricted Admin' { $RaSetting = '1' }
        'Require Remote Credential Guard' { $RaSetting = '2' }
        'Restrict credential delegation' { $RaSetting = '3' }
        Default { $RaSetting = '0' }
    }

    Registry EnableRestrictedAdmin
    {
        Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation'
        ValueName = 'RestrictedRemoteAdministration'
        ValueData = $RaSetting
        ValueType = 'dword'        
    }    

    #endregion
}