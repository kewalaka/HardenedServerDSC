<#

  This is a simple example showing how to use the hardenedServerConfig resource

#>
configuration simpleExample
{
    
    Import-DscResource -ModuleName HardenedServerConfig

    HardenedServerConfig securebuild {
        CompanyName          = 'Stu Corp'
    } 
}

# somewhere for the configuration document to live
$DSCFolder = 'C:\Admin\DSC'
New-Item -ItemType Directory -Path $DSCFolder -ErrorAction SilentlyContinue

# create the MOF:
simpleExample -OutputPath $DSCFolder

# Make the server compliant
Start-DscConfiguration -Wait -Verbose -Path $DSCFolder -Force -ComputerName $env:COMPUTERNAME

# Test compliance with
#    Test-DscConfiguration -ComputerName $env:COMPUTERNAME -Path $DSCFolder -Verbose