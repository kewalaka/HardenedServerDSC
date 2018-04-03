Configuration HardenedServerMisc
{
    param ()

    # TODO can do better than this - put into object & foreach the Registry blocks

    # ValueName = IE 64-bit tab | windows-ie-101
    Registry windows-ie-101
    {
        Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
        ValueName = "Isolation64Bit"
        ValueData = "1"
        ValueType = 'Dword'
    }

    # ValueName = Run antimalware programs against ActiveX controls | windows-ie-102
    Registry windows-ie-102
    {
        Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        ValueName = "270C"
        ValueData = "0"
        ValueType = 'Dword'
    }

    # Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts
    Registry powershell-script-blocklogging
    {
        Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        ValueName = "EnableScriptBlockLogging"
        ValueData = "0"
        ValueType = 'Dword'
    }

    # Transcription creates a unique record of every PowerShell session, including all input and output, exactly as it appears in the session.
    Registry powershell-transcription
    {
        Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        ValueName = "EnableTranscripting"
        ValueData = "0"
        ValueType = 'Dword'
    }

    # Microsoft Online Accounts | microsoft-online-accounts
    Registry microsoft-online-accounts
    {
        Key       = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount'
        ValueName = "value"
        ValueData = "0"
        ValueType = 'Dword'
    }
  
    # Disable Windows Store | 
    Registry disable-windows-store
    {
        Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
        ValueName = "AutoDownload"
        ValueData = "4"
        ValueType = 'Dword'
    }
  
    # Ensure Turn off Automatic Download and Install of Updates is set to Disabled
    Registry store-os-upgrade
    {
        Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
        ValueName = "DisableOSUpgrade"
        ValueData = "1"
        ValueType = 'Dword'
    }
  
    # Disable indexing encrypted files | disable-index-encrypted-files
    Registry disable-index-encrypted-files
    {
        Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        ValueName = "AllowIndexingEncryptedStoresOrItems"
        ValueData = "0"
        ValueType = 'Dword'
    }

}
