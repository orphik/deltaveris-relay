# DeltaVeris Institutional Execution Relay (Tier 3 - BYOK)

Non-custodial algorithmic execution client for DeltaVeris prediction market signals on Kalshi API v2.

## Deployment Options
- **1-Click Cloud (Zero Setup):** Deploy via [Railway Template](https://railway.app/template/deltaveris-relay)
- **Self-Hosted Workstation (CLI):** Run `python3 deltaveris_relay.py`

## Compliance & Security
- 100% Non-Custodial: Private RSA keys and capital remain strictly within subscriber environment.
- Enforces client-side order ceilings (<= 92¢) and capital allocation limits.
