Configuration HardenedServerConfig_Config
{
    
    Import-DscResource -ModuleName HardenedServerDSC

    Node 'localhost'
    {
        HardenedServerConfig securebuild { } 
    }
}