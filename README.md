# DeltaVeris Institutional Execution Relay (Tier 3 - BYOK)

Non-custodial algorithmic execution client for DeltaVeris prediction market signals on Kalshi API v2.

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template?template=https%3A%2F%2Fgithub.com%2Forphik%2Fdeltaveris-relay)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/orphik/deltaveris-relay)

## Overview
DeltaVeris Relay runs autonomously on subscriber infrastructure (cloud containers, worker nodes, or on-premise hardware). It evaluates incoming deterministic weather breach signals against strict subscriber risk boundaries, signs limit orders using client-held RSA credentials, and routes execution to Kalshi API v2 with sub-second latency and strict 3.0-second network timeouts.

## 1-Click Cloud Deployment Options
- **Railway:** Click the **Deploy on Railway** button above for automated container deployment with `railway.json`.
- **Render:** Click the **Deploy to Render** button above or link your GitHub repository using the included `render.yaml` worker blueprint.
- **Self-Hosted Workstation (CLI):**
  ```bash
  pip install -r requirements.txt
  python3 deltaveris_relay.py
  ```

## Environment Variables & Configuration
| Variable | Description | Default | Required |
| :--- | :--- | :--- | :--- |
| `KALSHI_KEY_ID` | Kalshi API Key UUID | None | **Yes** |
| `KALSHI_PRIVATE_KEY_B64` | Base64-encoded RSA Private Key (`.pem`) | None | **Yes** (or local file) |
| `RSA_PRIVATE_KEY_PATH` | Path to local private key file | `kalshi_key.pem` | No |
| `MAX_ORDER_SIZE_USD` | Maximum capital deployed per breach setup | `10.00` | No |
| `MAX_ACCEPTABLE_ASK_CENTS` | Hard price ceiling in cents (<= 92¢) | `92` | No |
| `MIN_IMPLIED_MARGIN_CENTS` | Minimum profit hurdle in cents | `8` | No |
| `WHITELISTED_STATIONS` | Comma-separated list of airport stations | `KNYC,KMDW,KAUS,KMIA...` | No |
| `RELAY_LIVE_EXECUTION` | Set `true` to enable live Kalshi order submission | `false` | No |

## CFTC Compliance & Security (Non-Custodial BYOK)
- **100% Non-Custodial Architecture:** DeltaVeris operates strictly under a Bring-Your-Own-Key (BYOK) paradigm. Subscriber private keys and account funds remain solely within the subscriber's private execution container. DeltaVeris never handles, stores, or transmits subscriber private keys or funds.
- **Client-Side Risk Enforcement:** Every order is validated client-side against the resting ask ceiling (<= 92¢), capital allocation limits ($10.00 hard cap), and minimum margin hurdles before cryptographic signing.
- **Sentinel Kill-Switch:** Touching `/tmp/deltaveris.kill` triggers instant, graceful halting of all evaluation and routing.
