# Chocolatey publisher control

This public control repository accepts one fixed eight-field source-release
dispatch at an immutable `release-control-vN` tag. It independently verifies
the source repository, release, dispatching workflow commit, signed source tag,
publication contract, and Chocolatey package before claiming an idempotency
record. The community feed API key is exposed only to the final protected,
no-checkout push job.

A `PREPARING` claim left by an interrupted run is resumed only by a retry that
carries the identical request identity (including `request_uuid`); a claim for
any different request or package fails closed and needs manual reconciliation.
A completed identical claim skips publication. Public
configuration policy is declared without operator IDs, fingerprints,
credentials, or provisioning evidence.

Publisher CI exercises the final PowerShell boundary with a mock Chocolatey
CLI. Real package submission is never used as a test path.
