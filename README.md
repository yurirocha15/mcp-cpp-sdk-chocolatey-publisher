# Chocolatey publisher control

This public control repository accepts one fixed source-release dispatch,
independently verifies the signed immutable release and Chocolatey package,
claims an idempotency record without credentials, and exposes the community
feed API key only to a final no-checkout push job.

A `PREPARING` claim left by an interrupted push is deliberately ambiguous and
blocks automatic retry. A completed identical claim skips publication. Public
configuration policy is declared without operator IDs, fingerprints,
credentials, or provisioning evidence.
