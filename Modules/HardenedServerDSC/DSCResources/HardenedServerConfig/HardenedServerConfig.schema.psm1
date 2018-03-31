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
        [string]$CompanyName = "Example Organisation Ltd",

        [string]$PreLogonMessageTitle = "Logon policy for $CompanyName",

        [string]$PreLogonMessageBody = @"
        This is a secured and audited system.
        Access is strictly for those persons authorised to do so, and use must be in line with $CompanyName Acceptable Use Policy.
        Attempts to access this system by unauthorised personal may result in criminal prosecution.
"@,

        [bool]$isDomainController = $false,

        [string]$renameGuestTo = 'secretGuestName',
        [string]$renameAdminTo = 'secretAdminName',

        [bool]$enableWinRM = $false,

        [ValidateRange(3,24)]
        [int]$PasswordHistory = 15,

        [ValidateRange(30,999)]    
        [int]$MaxPasswordAge = 42,

        [ValidateRange(1,999)]        
        [int]$MinPasswordAge = 2,

        [ValidateRange(8,14)]
        [int]$MinPasswordLength = 12,
        
        [int]$AccountLockoutThreshold = 5,

        [ValidateRange(30,999)]
        [int]$AccountLockoutDuration = 30,

        [ValidateRange(30,99999)]
        [int]$ResetAccountLockoutAfter = 30     
    )

    HardenedAuditSettings AuditPolicySettings {
        isDomainController = $isDomainController
    }

    HardenedServerPolicy ServerPolicySettings {}

    HardenedServerRDP RDPSettings {}

<#
    TODO
      IE lockdown
      WinRM
#>

}
