Configuration SimpleExample
{
    
    Import-DscResource -ModuleName HardenedServerDSC

    Node 'localhost'
    {
        HardenedServerConfig securebuild { } 
    }
}