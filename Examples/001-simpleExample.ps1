<#

  This is a simple example that calls the hardenedServerConfig resource
  & optionally installs IIS.

#>
configuration mySecureServer
{
    param
    (
        $buildAWebsite = $false
    )
    $PreLogonMessageTitle = 'Welcome to Stu Corp!'
    $PreLogonMessageBody = @'
    
    ---------------------------------------------------------------------------------
    This is a random message that will be displayed prior to logging into the server.
        
    Please play nicely!
    ---------------------------------------------------------------------------------
    
'@
    
    Import-DscResource -ModuleName hardenedServerConfig

    hardenedServerConfig securebuild {
        PreLogonMessageTitle = $PreLogonMessageTitle
        PreLogonMessageBody  = $PreLogonMessageBody
        MinPasswordAge       = 1
    } 

    if ($buildAWebsite)
    {
        # Install a website too, just to illustrate that this is a composite resource
        # that can be built upon.
        WindowsFeature IIS 
        { 
            Ensure = “Present” 
            Name = “Web-Server” 
        } 
    }
}

# somewhere for the configuration document to live
$DSCFolder = 'C:\Admin\DSC'
New-Item -ItemType Directory -Path $DSCFolder -ErrorAction SilentlyContinue

# create the MOF:
mySecureServer -buildAWebsite $true -OutputPath $DSCFolder -Verbose

# Make the server compliant
Start-DscConfiguration -Wait -Verbose -Path $DSCFolder -Force -ComputerName $env:COMPUTERNAME

# Test compliance with
#    Test-DscConfiguration -ComputerName $env:COMPUTERNAME -Path $DSCFolder -Verbose