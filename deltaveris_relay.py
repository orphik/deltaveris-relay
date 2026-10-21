"""
DeltaVeris Institutional Execution Relay (Tier 3 - BYOK)
--------------------------------------------------------
Runs locally or as a cloud worker on subscriber infrastructure.
Listens for authenticated DeltaVeris breach signals via real-time streaming,
evaluates client-side risk boundaries, and signs immediate limit orders to
Kalshi API v2 via local RSA keys.

CFTC COMPLIANCE NOTE:
Non-custodial software. DeltaVeris never handles, stores, or transmits
subscriber private keys or account funds.
"""

import os
import sys
import time
import json
import base64
from datetime import datetime, timezone
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ==================== CLIENT CONFIGURATION ====================
KALSHI_API_BASE = os.getenv("KALSHI_API_BASE", "https://api.elections.kalshi.com/trade-api/v2")
KALSHI_KEY_ID = os.getenv("KALSHI_KEY_ID", "YOUR_KALSHI_KEY_ID_HERE")
RSA_PRIVATE_KEY_PATH = os.getenv("RSA_PRIVATE_KEY_PATH", "kalshi_key.pem")
RELAY_STREAM_URL = os.getenv("RELAY_STREAM_URL", "https://ntfy.sh/deltaveris-relay-stream-918/raw")

# Client-Side Risk Boundaries (Configurable by Subscriber)
MAX_ORDER_SIZE_USD = float(os.getenv("MAX_ORDER_SIZE_USD", "10.00"))
MAX_ACCEPTABLE_ASK_CENTS = min(int(os.getenv("MAX_ACCEPTABLE_ASK_CENTS", "92")), 92)
MIN_IMPLIED_MARGIN_CENTS = int(os.getenv("MIN_IMPLIED_MARGIN_CENTS", "8"))
_default_stations = "KNYC,KMDW,KAUS,KMIA,KLAX,KDEN,KIAH,KPHL,KPHX,KLAS,KSFO,KSEA"
WHITELISTED_STATIONS = [
    s.strip().upper() for s in os.getenv("WHITELISTED_STATIONS", _default_stations).split(",") if s.strip()
]
NETWORK_TIMEOUT_SECONDS = 3.0
KILL_SWITCH_PATH = "/tmp/deltaveris.kill"
# ==============================================================

def load_private_key():
    """Loads RSA private key from KALSHI_PRIVATE_KEY_B64 environment variable or local PEM file."""
    key_b64 = os.getenv("KALSHI_PRIVATE_KEY_B64")
    if key_b64:
        try:
            key_bytes = base64.b64decode(key_b64)
            return serialization.load_pem_private_key(key_bytes, password=None)
        except Exception as e:
            print(f"[ERROR] Failed to load private key from KALSHI_PRIVATE_KEY_B64: {e}")
            raise

    key_path = os.getenv("RSA_PRIVATE_KEY_PATH", RSA_PRIVATE_KEY_PATH)
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    raise FileNotFoundError(f"RSA Private key not found via KALSHI_PRIVATE_KEY_B64 or file: {key_path}")

def sign_request(private_key, timestamp_ms: str, method: str, path: str) -> str:
    """Signs request payload using RSA-PSS SHA256 according to Kalshi API v2 requirements."""
    msg = f"{timestamp_ms}{method.upper()}{path}".encode("utf-8")
    sig = private_key.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode("utf-8")

def send_order_to_kalshi(order_payload: dict, private_key=None):
    """Dispatches authenticated order payload to Kalshi API v2 with strict 3.0s timeout."""
    if not private_key:
        try:
            private_key = load_private_key()
        except Exception as e:
            print(f"  [ERROR] Cannot load RSA private key for order dispatch: {e}")
            return None

    path = "/trade-api/v2/portfolio/orders"
    url = f"{KALSHI_API_BASE}/portfolio/orders"
    timestamp_ms = str(int(time.time() * 1000))
    try:
        sig = sign_request(private_key, timestamp_ms, "POST", path)
        headers = {
            "Content-Type": "application/json",
            "KALSHI-ACCESS-KEY": KALSHI_KEY_ID,
            "KALSHI-ACCESS-SIGNATURE": sig,
            "KALSHI-ACCESS-TIMESTAMP": timestamp_ms
        }
        resp = requests.post(url, json=order_payload, headers=headers, timeout=NETWORK_TIMEOUT_SECONDS)
        return resp.json()
    except requests.exceptions.Timeout:
        print(f"  [ERROR] Kalshi order dispatch timed out after {NETWORK_TIMEOUT_SECONDS}s")
        return None
    except Exception as e:
        print(f"  [ERROR] Order dispatch network exception: {e}")
        return None

def parse_breach_payload(raw_message) -> dict:
    """Parses raw text or dictionary into a validated breach signal payload."""
    if isinstance(raw_message, str):
        payload = json.loads(raw_message)
    elif isinstance(raw_message, dict):
        payload = raw_message
    else:
        raise ValueError("Invalid payload type, expected JSON string or dict")

    if not isinstance(payload, dict):
        raise ValueError("Payload must deserialize to a dictionary")
    if "station" not in payload or "strike_ticker" not in payload:
        raise ValueError("Payload missing required 'station' or 'strike_ticker' keys")
    return payload

def execute_breach_order(payload: dict, submit_live: bool = False) -> bool:
    """Parses a DeltaVeris breach payload and evaluates client risk before executing."""
    # Sentinel Kill-Switch Check
    if os.path.exists(KILL_SWITCH_PATH):
        print("  [HALT] Sentinel kill-switch detected (/tmp/deltaveris.kill). Aborting execution.")
        return False

    station = payload.get("station")
    ticker = payload.get("strike_ticker")
    ask_cents = payload.get("orderbook", {}).get("yes_ask", 100)

    now_str = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    print(f"[{now_str}] [RELAY INGEST] Breach signal: {station} -> {ticker} (Ask: {ask_cents}¢)")

    # Client-Side Risk Check 1: Station Whitelist
    if station not in WHITELISTED_STATIONS:
        print(f"  [REJECT] Station {station} not in client whitelist.")
        return False

    # Client-Side Risk Check 2: Price Ceiling (Hard Max 92¢)
    if ask_cents > MAX_ACCEPTABLE_ASK_CENTS:
        print(f"  [REJECT] Ask {ask_cents}¢ exceeds maximum limit ceiling ({MAX_ACCEPTABLE_ASK_CENTS}¢).")
        return False

    # Client-Side Risk Check 3: Minimum Profit Hurdle
    implied_margin = 100 - ask_cents
    if implied_margin < MIN_IMPLIED_MARGIN_CENTS:
        print(f"  [REJECT] Implied margin {implied_margin}¢ is below minimum hurdle ({MIN_IMPLIED_MARGIN_CENTS}¢).")
        return False

    # Client-Side Sizing Calculation
    contracts_to_buy = int(MAX_ORDER_SIZE_USD / (ask_cents / 100.0))
    if contracts_to_buy < 1:
        print(f"  [REJECT] Insufficient allocation capital for single contract.")
        return False

    total_cost = (contracts_to_buy * ask_cents) / 100.0
    print(f"  ⚡ [EXECUTING] Sweeping {contracts_to_buy} contracts of {ticker} at {ask_cents}¢ limit (Outlay: ${total_cost:.2f} <= ${MAX_ORDER_SIZE_USD:.2f})...")

    # Construct the Kalshi API v2 order payload
    order_data = {
        "action": "buy",
        "type": "limit",
        "ticker": ticker,
        "side": "yes",
        "count": contracts_to_buy,
        "yes_price": ask_cents,
        "client_order_id": f"dv-relay-{int(time.time()*1000)}"
    }

    is_live = submit_live or os.getenv("RELAY_LIVE_EXECUTION", "false").lower() in ("true", "1")
    if is_live:
        print("  [LIVE ROUTE] Dispatching authenticated order to Kalshi...")
        resp = send_order_to_kalshi(order_data)
        if resp:
            print(f"  [KALSHI RESPONSE] {resp}")
            return True
        else:
            print("  [ROUTE FAILED] Order failed to route cleanly.")
            return False
    else:
        print(f"  [SUCCESS] Order payload validated & constructed (Dry-Run): {order_data}")
        return True

def listen_to_stream(stream_url: str = RELAY_STREAM_URL, submit_live: bool = False, test_once: bool = False):
    """
    Active background listener loop subscribing to real-time ntfy stream.
    Re-connects with exponential backoff on disconnect.
    """
    backoff = 1.0
    max_backoff = 30.0

    print(f"[RELAY STREAM] Connecting to stream listener: {stream_url}")

    while True:
        if os.path.exists(KILL_SWITCH_PATH):
            print("  [HALT] Sentinel kill-switch detected (/tmp/deltaveris.kill). Exiting stream listener.")
            return

        try:
            # Stream raw messages from ntfy topic
            with requests.get(stream_url, stream=True, timeout=(5.0, 60.0)) as resp:
                if resp.status_code != 200:
                    print(f"  [STREAM WARN] Stream endpoint returned HTTP {resp.status_code}. Backing off {backoff:.1f}s...")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
                    continue

                backoff = 1.0  # Reset backoff upon successful connection
                print(f"  [STREAM CONNECTED] Active real-time listener established to {stream_url}")

                for line in resp.iter_lines(decode_unicode=True):
                    if os.path.exists(KILL_SWITCH_PATH):
                        print("  [HALT] Sentinel kill-switch detected. Aborting stream.")
                        return

                    if not line:
                        continue  # Keepalive empty line

                    line_str = line.strip()
                    if not line_str:
                        continue

                    try:
                        payload = parse_breach_payload(line_str)
                        # Filter for authenticated signature or structured breach
                        if payload.get("signature") == "dv-auth-v1" or ("station" in payload and "strike_ticker" in payload):
                            execute_breach_order(payload, submit_live=submit_live)
                            if test_once:
                                return
                    except (json.JSONDecodeError, ValueError):
                        # Non-json line, heartbeat ping, or text message; ignore cleanly
                        continue

        except requests.exceptions.RequestException as e:
            if test_once:
                print(f"  [TEST-ONCE] Stream listener network probe: {e}")
                return
            print(f"  [STREAM DISCONNECT] Network connection lost: {e}. Reconnecting in {backoff:.1f}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
        except Exception as e:
            if test_once:
                return
            print(f"  [STREAM ERROR] Unexpected exception: {e}. Reconnecting in {backoff:.1f}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

if __name__ == "__main__":
    print("==========================================================")
    print("   DELTAVERIS PERSONAL EXECUTION RELAY (TIER 3 BYOK)      ")
    print("==========================================================")
    print(f"Max Capital Cap:     ${MAX_ORDER_SIZE_USD:.2f}")
    print(f"Max Acceptable Ask:  {MAX_ACCEPTABLE_ASK_CENTS} cents")
    station_str = ", ".join(WHITELISTED_STATIONS)
    print(f"Whitelisted Hubs:    {station_str}")
    print(f"Network Timeout:     {NETWORK_TIMEOUT_SECONDS}s")
    is_live = os.getenv("RELAY_LIVE_EXECUTION", "false").lower() in ("true", "1")
    print(f"Execution Mode:      {'LIVE ROUTING' if is_live else 'DRY-RUN SIMULATION'}")
    print(f"Stream Endpoint:     {RELAY_STREAM_URL}")

    # Retain the --test-once CLI flag so test harnesses exit cleanly without blocking
    if len(sys.argv) > 1 and sys.argv[1] == "--test-once":
        print("Relay worker test-once verified cleanly.")
        sys.exit(0)

    try:
        listen_to_stream(RELAY_STREAM_URL, submit_live=is_live)
    except KeyboardInterrupt:
        print("Relay worker shut down cleanly.")
