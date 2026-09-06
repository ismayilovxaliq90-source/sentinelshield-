# SentinelShield

SentinelShield is a policy, monitoring, audit, alert, recovery and resource-safety system.

## Safety

The production-safe configuration uses dry-run mode by default.

Destructive actions and process termination must remain disabled until separately reviewed and explicitly enabled.

## Testing

Run:

PYTHONPATH=src python -m pytest -q

## Release

Build the package with:

python -m build

The wheel is created in the dist/ directory.

## Rollback

Maintain a verified backup before deployment and test rollback in a sandbox before production rollout.
