<#
  This is a simple example showing how to use the hardenedServerConfig resource
  All the defaults are used, except for the Company Name
#>
Configuration SimpleExample
{
    
    Import-DscResource -ModuleName HardenedServerConfig

    Node 'localhost'
    {
        HardenedServerConfig securebuild {
            CompanyName          = 'Stu Corp'
        } 
    }
}

SimpleExample