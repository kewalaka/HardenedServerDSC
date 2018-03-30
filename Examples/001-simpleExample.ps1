<#

  This is a simple example showing how to use the hardenedServerConfig resource

#>
configuration simpleExample
{
    
    Import-DscResource -ModuleName HardenedServerConfig

    Node 'localhost'
    {
        HardenedServerConfig securebuild {
            CompanyName          = 'Stu Corp'
        } 
    }
}

simpleExample