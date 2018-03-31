# Versions

## Unreleased

Initial release.

- First release of the following composite modules:
  - **HardenedAuditSettings** - taken from Microsoft Security Baseline
  - **HardenedServerConfig** - a meta module that combines the others using sensible defaults
  - **HardenedServerPolicy** - local security policies, account policies & user rights assignments
  - **HardenedServerRDP** - settings to hardened RDP and optionally enable restricted admin
- Integration tests using Inspec baseline. 