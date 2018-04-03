[![Build status](https://ci.appveyor.com/api/projects/status/sn716it1n4fcy2xu/branch/master?svg=true)](https://ci.appveyor.com/project/kewalaka/hardenedserverdsc)

# Windows server hardening using PowerShell DSC

This is a composite DSC resource that can be used to harden a Windows OS.  There are a number of configurable parameters,
A few of which you should set, others have been set to reasonable defaults (based on CIS where it is specific)

This is incomplete work in progress, feedback is welcome, PRs gladly considered.

## Requirements

This uses the SecurityPolicyDSC resource.

I have not tested it on anything older than Windows Server 2012R2 & 2016

Requires Powershell 4 on the target server to be secured (primarily tested against PS5.1).

## Example usage

Some examples are provided Examples subfolder, if you're unfamiliar with DSC see the instructions section below for a
walkthrough.  Here's a simple example:

```
Configuration SimpleExample
{
    
    Import-DscResource -ModuleName HardenedServerDSC

    Node 'localhost'
    {
        HardenedServerConfig securebuild {
            CompanyName          = 'Stu Corp'
        } 
    }
}

SimpleExample
# optionally kick off compliance automatically - this will run on localhost
# so be careful not to run accidentally on your PC!
#Start-DscConfiguration -Wait -Verbose -Path .\SimpleExample -Force
```

## Instructions

TODO complete instructions for people less familiar with DSC.

To use, you need to install the AuditPolicyDSC, SecurityPolicyDSC, xNetworking modules.  This can be done from a machine with internet access & then transfered to the machine that you'd like to secure.  (Powershell modules are simply files & folders)

These installation steps require PowerShell 5 (to access the PS Gallery), the target host needs to be at least Powershell v4 (please, make it 5.1 if you can!).

To install the module dependencies:
```
Install-Module AuditPolicyDSC,SecurityPolicyDSC,xNetworking -Scope -CurrentUser -Force
```


## Copyright

Windows hardening DSC resource.

Copyright 2018 Stu Mace 'kewalaka', released under an Apache License.
