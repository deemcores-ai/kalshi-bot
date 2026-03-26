"""
KALSHI API WRAPPER
==================
Kalshi migrated from email/password to RSA API key authentication in 2025.
Every request is signed with your RSA private key.

Setup (5 minutes):
  1. Go to kalshi.com/account/profile → API Keys → Create New API Key
  2. Save your Key ID and the PEM private key
  3. Add as GitHub Secrets:
       KALSHI_API_KEY_ID  = the Key ID shown on Kalshi
       KALSHI_PRIVATE_KEY = the full PEM private key (including header/footer lines)

Docs: https://docs.kalshi.com/getting_started/api_keys
"""

import base64
import hashlib
import hmac
import time
import datetime
from typing import Optional

import requests

import config
from logger import log


class KalshiAPI:
    """Authenticated session for the Kalshi trading API (RSA key auth)."""

    BASE = config.KALSHI_BASE_URL

    def __init__(self):
        self._key_id:      str = config.KALSHI_API_KEY_ID
        self._private_key: str = config.KALSHI_PRIVATE_KEY
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._authenticated = False

    # ── Authentication ──────────────────────────────────────────────────────────

    def login(self) -> bool:
        """
        Validate that we have working API credentials by making a test request.
        RSA auth doesn't have a login step — credentials are attached per-request.
        """
        if not self._key_id or not self._private_key:
            log("No KALSHI_API_KEY_ID / KALSHI_PRIVATE_KEY set — "
                "running without Kalshi auth (public markets only)", "WARN")
            self._authenticated = False
            return False

        # Test credentials with a lightweight authenticated call
        data = self._get("/portfolio/balance")
        if data is not None:
            log(f"Kalshi API key auth OK ✅  (balance: ${data.get('balance',0)/100:.2f})")
            self._authenticated = True
            return True

        log("Kalshi API key auth failed — check KALSHI_API_KEY_ID and KALSHI_PRIVATE_KEY", "ERROR")
        return False

    def _sign_request(self, method: str, path: str) -> dict:
        """
        Generate the three RSA auth headers required by Kalshi.
        Signs: timestamp_ms + HTTP_METHOD.upper() + path_without_query
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            ts_ms   = str(int(time.time() * 1000))
            # Strip query string from path for signing
            sign_path = path.split("?")[0]
            message   = (ts_ms + method.upper() + sign_path).encode("utf-8")

            # Load PEM private key
            private_key_pem = self._private_key.strip()
            if not private_key_pem.startswith("-----"):
                # If stored without newlines (e.g. base64 blob), try to reconstruct
                private_key_pem = (
                    "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "\n".join(private_key_pem[i:i+64]
                              for i in range(0, len(private_key_pem), 64)) +
                    "\n-----END RSA PRIVATE KEY-----"
                )

            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None
            )
            signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
            sig_b64   = base64.b64encode(signature).decode()

            return {
                "KALSHI-ACCESS-KEY":       self._key_id,
                "KALSHI-ACCESS-TIMESTAMP": ts_ms,
                "KALSHI-ACCESS-SIGNATURE": sig_b64,
            }
        except ImportError:
            # cryptography package not installed — fall back to unsigned (public endpoints only)
            log("cryptography package not installed — requests will be unsigned", "WARN")
            return {}
        except Exception as exc:
            log(f"RSA signing error: {exc}", "WARN")
            return {}

    def _get(self, path: str, params: dict = None, timeout: int = 15) -> Optional[dict]:
        full_path = path
        if params:
            from urllib.parse import urlencode
            full_path = path + "?" + urlencode(params)

        headers = self._sign_request("GET", path)   # sign base path, not with query

        try:
            resp = self._session.get(
                f"{self.BASE}{full_path}",
                headers=headers,
                timeout=timeout,
            )
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 401:
                log(f"API 401 on {path} — check your API key credentials", "WARN")
            else:
                log(f"API GET {path} → HTTP {resp.status_code}", "WARN")
        except Exception as exc:
            log(f"API GET {path} error: {exc}", "WARN")
        return None

    # ── Market data (public — no auth needed) ────────────────────────────────────

    def get_markets(self, limit: int = 200, cursor: str = None,
                    status: str = "open", category: str = None) -> dict:
        params = {"limit": limit, "status": status}
        if cursor:
            params["cursor"] = cursor
        if category:
            params["category"] = category
        data = self._get("/markets", params=params)
        return data or {"markets": [], "cursor": None}

    def get_all_open_markets(self) -> list:
        """Paginate through ALL open markets and return them as a flat list."""
        all_markets = []
        cursor = None
        pages  = 0
        while pages < 50:
            page  = self.get_markets(limit=200, cursor=cursor, status="open")
            batch = page.get("markets", [])
            all_markets.extend(batch)
            cursor = page.get("cursor")
            pages += 1
            if not cursor or not batch:
                break
            time.sleep(0.3)
        log(f"Fetched {len(all_markets)} open markets across {pages} pages")
        return all_markets

    def get_market(self, ticker: str) -> Optional[dict]:
        data = self._get(f"/markets/{ticker}")
        return data.get("market") if data else None

    def get_orderbook(self, ticker: str) -> Optional[dict]:
        data = self._get(f"/markets/{ticker}/orderbook")
        return data.get("orderbook") if data else None

    def get_settled_markets(self, limit: int = 100) -> list:
        data = self._get("/markets", params={"status": "finalized", "limit": limit})
        return (data or {}).get("markets", [])

    # ── Authenticated endpoints ───────────────────────────────────────────────────

    def get_account_balance(self) -> Optional[float]:
        """Return cash balance in dollars. Requires valid API key."""
        data = self._get("/portfolio/balance")
        if data:
            cents = data.get("balance", 0)
            return round(cents / 100, 2)
        return None

    def get_portfolio_positions(self) -> list:
        data = self._get("/portfolio/positions", params={"limit": 200})
        return (data or {}).get("market_positions", [])


# ── Market parser ────────────────────────────────────────────────────────────────

def parse_market(raw: dict) -> Optional[dict]:
    """Normalise a raw Kalshi market dict into a clean standard format."""
    try:
        ticker    = raw.get("ticker", "")
        title     = raw.get("title", "")
        category  = raw.get("category", "")
        subtitle  = raw.get("subtitle", "")

        yes_bid = int(raw.get("yes_bid", 0) or 0)
        yes_ask = int(raw.get("yes_ask", 0) or 0)

        if yes_ask <= 0 or yes_ask >= 100:
            return None

        implied_prob = ((yes_bid + yes_ask) / 2) / 100.0

        volume        = int(raw.get("volume", 0) or 0)
        volume_24h    = int(raw.get("volume_24h", 0) or 0)
        open_interest = int(raw.get("open_interest", 0) or 0)

        avg_price_cents = (yes_bid + yes_ask) / 2
        dollar_volume   = volume * (avg_price_cents / 100)

        close_time_str  = raw.get("close_time") or raw.get("expiration_time", "")
        hours_to_close  = 999.0
        if close_time_str:
            try:
                close_time = datetime.datetime.fromisoformat(
                    close_time_str.replace("Z", "+00:00")
                )
                now = datetime.datetime.now(datetime.timezone.utc)
                hours_to_close = (close_time - now).total_seconds() / 3600
            except Exception:
                pass

        return {
            "ticker":         ticker,
            "title":          title,
            "subtitle":       subtitle,
            "category":       category,
            "yes_bid":        yes_bid,
            "yes_ask":        yes_ask,
            "implied_prob":   implied_prob,
            "volume":         volume,
            "volume_24h":     volume_24h,
            "open_interest":  open_interest,
            "dollar_volume":  dollar_volume,
            "close_time":     close_time_str,
            "hours_to_close": hours_to_close,
            "result":         raw.get("result", ""),
            "status":         raw.get("status", ""),
        }
    except Exception:
        return None
