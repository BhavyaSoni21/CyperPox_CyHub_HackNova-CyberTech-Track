"""
CyHub — Domain Intelligence Layer

Pre-filters URLs and domains before ML model processing.
Implements blocklist checking, DNS validation, heuristics, and Model 4 integration.

MongoDB-optional: works with in-memory cache when DB is unavailable.

Architecture:
  URL Input → Extract Domain → Normalize → Whitelist → Blocklist → DNS Validation
    → Heuristics → Extract Model 4 Features → Call Model 4 → Cache Result
"""

from __future__ import annotations

import os
import socket
import asyncio
import logging
from typing import Dict, Optional, Tuple, List
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
import httpx

logger = logging.getLogger(__name__)


class DomainIntelligence:
    """Domain validation and classification engine.

    Works with or without MongoDB — falls back to in-memory caches.
    """

    SUSPICIOUS_KEYWORDS = {
        "login", "secure", "update", "verify", "confirm", "validate",
        "auth", "account", "bank", "paypal", "amazon", "apple", "microsoft",
        "admin", "panel", "dashboard", "signin", "signup", "confirm"
    }

    SUSPICIOUS_PATTERNS = {
        "defacement": ["hacked", "defaced", "deface"],
        "phishing": ["phish", "fake", "spoof"],
        "malware": ["malware", "virus", "trojan", "worm", "bot"],
        "betting": ["bet", "casino", "poker", "gamble", "slots", "bingo"]
    }

    MAJOR_DOMAINS_WHITELIST = {
        "google.com", "github.com", "stackoverflow.com", "linkedin.com",
        "facebook.com", "twitter.com", "reddit.com", "youtube.com",
        "wikipedia.org", "aws.amazon.com", "microsoft.com", "apple.com",
        "netflix.com", "slack.com", "discord.com", "twitch.tv"
    }

    def __init__(self, db=None):
        """Initialize with optional MongoDB database connection.

        Args:
            db: motor.motor_asyncio.AsyncIOMotorDatabase or None.
                If None, uses in-memory caches only.
        """
        self.db = db
        self.dns_timeout = float(os.getenv("DNS_VALIDATION_TIMEOUT", 5.0))
        self.cache_ttl = int(os.getenv("DOMAIN_CACHE_TTL", 2592000))  # 30 days
        self.hf_model4_url = os.getenv("HF_MODEL4_URL", "https://bhavyasoni21-model4.hf.space/predict")
        self.hf_model4_timeout = float(os.getenv("HF_MODEL4_TIMEOUT", 8.0))

        # In-memory caches (used when MongoDB is unavailable)
        self._mem_cache: Dict[str, Dict] = {}  # domain → {classification, cached_at}
        self._mem_blocklist: Dict[str, Dict] = {}  # domain → {category, source, confidence}

    # ===== DOMAIN EXTRACTION & NORMALIZATION =====

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            parsed = urlparse(url)
            return parsed.netloc.lower() if parsed.netloc else None
        except Exception as e:
            logger.warning(f"Failed to extract domain from URL '{url}': {e}")
            return None

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain for consistent comparison."""
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        domain = domain.rstrip(".")
        return domain

    # ===== WHITELIST CHECKING =====

    async def check_whitelist(self, domain: str) -> bool:
        """Check if domain is whitelisted (fast-track to 'normal')."""
        # Check environment variable whitelist
        env_whitelist = os.getenv("WHITELIST_DOMAINS", "")
        if env_whitelist:
            whitelist_domains = set(d.strip() for d in env_whitelist.split(","))
            if domain in whitelist_domains:
                return True

        # Check hardcoded whitelist
        if domain in self.MAJOR_DOMAINS_WHITELIST:
            return True

        # Check MongoDB whitelist collection (if available)
        if self.db is not None:
            try:
                whitelist_record = await self.db["whitelisted_domains"].find_one({"domain": domain})
                if whitelist_record:
                    return True
            except Exception as e:
                logger.warning(f"Error checking whitelist for '{domain}': {e}")

        return False

    # ===== BLOCKLIST CHECKING =====

    async def check_blocklist(self, domain: str) -> Optional[Dict]:
        """Check if domain is blocked."""
        # Check in-memory blocklist first
        if domain in self._mem_blocklist:
            return self._mem_blocklist[domain]

        # Check MongoDB (if available)
        if self.db is not None:
            try:
                blocked = await self.db["blocked_domains"].find_one({"domain": domain})
                if blocked:
                    logger.warning(f"Domain '{domain}' found in blocklist: {blocked.get('category')}")
                    result = {
                        "category": blocked.get("category", "unknown"),
                        "source": blocked.get("source", "local"),
                        "confidence": blocked.get("confidence", 0.9)
                    }
                    self._mem_blocklist[domain] = result
                    return result
            except Exception as e:
                logger.warning(f"Error checking blocklist for '{domain}': {e}")

        return None

    # ===== DNS VALIDATION =====

    async def validate_dns(self, domain: str) -> bool:
        """Validate domain exists via DNS resolution."""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, domain),
                timeout=self.dns_timeout
            )
            logger.info(f"DNS validation passed for '{domain}' → {result}")
            return True
        except asyncio.TimeoutError:
            logger.warning(f"DNS timeout for '{domain}' (timeout: {self.dns_timeout}s)")
            return False
        except socket.gaierror:
            logger.warning(f"DNS resolution failed for '{domain}' (non-existent)")
            return False
        except Exception as e:
            logger.warning(f"DNS validation error for '{domain}': {e}")
            return False

    # ===== HEURISTIC CHECKS =====

    @staticmethod
    def heuristic_check(domain: str) -> Tuple[bool, Optional[str]]:
        """Check for suspicious domain characteristics."""
        if domain.count("-") > 4:
            return True, "excessive_hyphens"

        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            return True, "excessive_subdomains"

        if len(domain) > 63:
            return True, "domain_too_long"

        domain_parts = domain.replace("-", ".").split(".")
        for part in domain_parts:
            if part in DomainIntelligence.SUSPICIOUS_KEYWORDS:
                return True, f"suspicious_keyword_{part}"

        for pattern_type, patterns in DomainIntelligence.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if pattern in domain:
                    return True, f"suspicious_pattern_{pattern_type}"

        return False, None

    # ===== THREAT FLAG EXTRACTION =====

    def extract_threat_flags(self, domain: str, blocklist_info: Optional[Dict] = None) -> Dict[str, float]:
        """Determine threat type flags for Model 4 feature vector."""
        flags = {
            "type_defacement": 0.0,
            "type_malware": 0.0,
            "type_phishing": 0.0
        }

        if blocklist_info:
            category = blocklist_info.get("category", "").lower()
            if "defacement" in category or "deface" in category:
                flags["type_defacement"] = 1.0
            elif "malware" in category:
                flags["type_malware"] = 1.0
            elif "phishing" in category or "phish" in category:
                flags["type_phishing"] = 1.0

        domain_lower = domain.lower()
        for keyword in ["phish", "fake", "spoof"]:
            if keyword in domain_lower:
                flags["type_phishing"] = 1.0

        for keyword in ["malware", "virus", "trojan", "bot"]:
            if keyword in domain_lower:
                flags["type_malware"] = 1.0

        for keyword in ["deface", "hack"]:
            if keyword in domain_lower:
                flags["type_defacement"] = 1.0

        return flags

    # ===== MODEL 4 API INTEGRATION =====

    async def call_model4(self, features: List[float]) -> Dict:
        """Call Model 4 (domain classification) on HuggingFace Space.

        Returns dict with 'classification' key (normalized from 'predicted_label')
        to match threat_engine.py expectations.
        """
        payload = {"features": features}

        try:
            async with httpx.AsyncClient(timeout=self.hf_model4_timeout) as client:
                response = await client.post(self.hf_model4_url, json=payload)
                if response.status_code == 200:
                    result = response.json()
                    logger.debug(f"Model 4 raw response keys: {list(result.keys()) if isinstance(result, dict) else type(result)}")
                    # FIX: Normalize key — M4 returns 'predicted_label',
                    # threat_engine expects 'classification'
                    predicted_label = result.get("predicted_label", "unknown")
                    # Try multiple common confidence key names used by HF endpoints
                    raw_confidence = None
                    for key in ("confidence", "score", "probability", "confidence_score", "prob"):
                        if key in result:
                            raw_confidence = result[key]
                            break
                    if raw_confidence is None:
                        # HF Model 4 may not return a confidence key.
                        # If a valid prediction was made, assign a reasonable default
                        # confidence so the score is not silently zeroed.
                        if predicted_label and predicted_label != "unknown":
                            raw_confidence = 0.85
                            logger.info(f"Model 4 response has no confidence key; using default {raw_confidence} for label '{predicted_label}'")
                        else:
                            logger.warning(f"Model 4 response missing confidence key. Keys: {list(result.keys())}. Defaulting to 0.0")
                            raw_confidence = 0.0
                    # Normalize confidence to 0.0–1.0 — HF endpoint may return 0–100 scale
                    if isinstance(raw_confidence, (int, float)) and raw_confidence > 1.0:
                        raw_confidence = raw_confidence / 100.0
                    return {
                        "classification": predicted_label,
                        "confidence": round(float(raw_confidence), 4),
                        "raw_prediction_encoded": result.get("raw_prediction_encoded", -1),
                    }
                else:
                    error_msg = f"Model 4 HTTP {response.status_code}"
                    logger.error(error_msg)
                    return {"classification": "unknown", "confidence": 0.0}
        except asyncio.TimeoutError:
            logger.error(f"Model 4 timeout ({self.hf_model4_timeout}s)")
            return {"classification": "unknown", "confidence": 0.0}
        except Exception as e:
            logger.error(f"Model 4 error: {str(e)}")
            return {"classification": "unknown", "confidence": 0.0}

    # ===== DOMAIN CACHE MANAGEMENT =====

    async def get_cached_classification(self, domain: str) -> Optional[Dict]:
        """Retrieve cached Model 4 classification (MongoDB or in-memory)."""
        # Check in-memory cache first
        if domain in self._mem_cache:
            entry = self._mem_cache[domain]
            age = (datetime.now(timezone.utc) - entry["cached_at"]).total_seconds()
            if age < self.cache_ttl:
                return {
                    "classification": entry["classification"],
                    "from_cache": True,
                    "age_seconds": int(age),
                }
            else:
                del self._mem_cache[domain]

        # Check MongoDB cache (if available)
        if self.db is not None:
            try:
                cache_entry = await self.db["domain_cache"].find_one({"domain": domain})
                if cache_entry:
                    cached_at = cache_entry.get("cached_at", datetime.now(timezone.utc))
                    age_seconds = (datetime.now(timezone.utc) - cached_at).total_seconds()
                    if age_seconds < self.cache_ttl:
                        # Populate in-memory cache too
                        self._mem_cache[domain] = {
                            "classification": cache_entry.get("classification"),
                            "cached_at": cached_at,
                        }
                        return {
                            "classification": cache_entry.get("classification"),
                            "from_cache": True,
                            "age_seconds": int(age_seconds),
                        }
                    else:
                        await self.db["domain_cache"].delete_one({"domain": domain})
            except Exception as e:
                logger.warning(f"Error retrieving cache for '{domain}': {e}")

        return None

    async def cache_classification(self, domain: str, classification: str, raw_score: int = 0) -> None:
        """Store Model 4 classification in cache (MongoDB + in-memory)."""
        now = datetime.now(timezone.utc)

        # Always update in-memory cache
        self._mem_cache[domain] = {
            "classification": classification,
            "cached_at": now,
        }

        # Also persist to MongoDB if available
        if self.db is not None:
            try:
                await self.db["domain_cache"].update_one(
                    {"domain": domain},
                    {
                        "$set": {
                            "classification": classification,
                            "model4_raw_score": raw_score,
                            "cached_at": now,
                        }
                    },
                    upsert=True,
                )
            except Exception as e:
                logger.warning(f"Error caching classification for '{domain}': {e}")

    # ===== BLOCKLIST LOADING =====

    async def load_blocklists_from_sources(self) -> None:
        """Fetch and load blocklists from public sources."""
        if self.db is None:
            logger.warning("Skipping blocklist loading — no MongoDB configured")
            return

        sources = [
            ("urlhaus", os.getenv("URLHAUS_API_URL", "https://urlhaus.abuse.ch/downloads/csv_recent/")),
            ("phishtank", os.getenv("PHISHTANK_API_URL", "https://phishtank.com/phish_download.php")),
            ("spamhaus", os.getenv("SPAMHAUS_API_URL", "https://www.spamhaus.org/drop/drop.txt")),
        ]

        for source_name, source_url in sources:
            try:
                await self._fetch_and_load_blocklist(source_name, source_url)
            except Exception as e:
                logger.error(f"Failed to load {source_name} blocklist: {e}")

    async def _fetch_and_load_blocklist(self, source_name: str, source_url: str) -> None:
        """Fetch and parse a blocklist from a source."""
        logger.info(f"Loading {source_name} blocklist from {source_url}")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(source_url)
                if response.status_code != 200:
                    logger.error(f"Failed to fetch {source_name}: HTTP {response.status_code}")
                    return

                content = response.text
                domains_added = 0

                for line in content.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    domain = self._parse_blocklist_line(line, source_name)
                    if domain:
                        try:
                            await self.db["blocked_domains"].update_one(
                                {"domain": domain},
                                {
                                    "$set": {
                                        "category": self._categorize_threat(domain),
                                        "source": source_name,
                                        "confidence": 0.9,
                                        "last_updated": datetime.now(timezone.utc)
                                    }
                                },
                                upsert=True
                            )
                            domains_added += 1
                        except Exception as e:
                            logger.debug(f"Error adding domain {domain}: {e}")

                logger.info(f"Loaded {domains_added} domains from {source_name}")

        except Exception as e:
            logger.error(f"Error fetching {source_name} blocklist: {e}")

    @staticmethod
    def _parse_blocklist_line(line: str, source_name: str) -> Optional[str]:
        """Parse domain from blocklist line."""
        line = line.strip()
        if not line:
            return None

        if source_name == "urlhaus":
            line = line.strip('"')
            if line and not line.startswith("http"):
                return DomainIntelligence.normalize_domain(line)

        elif source_name == "phishtank":
            domain = DomainIntelligence.extract_domain(line)
            return DomainIntelligence.normalize_domain(domain) if domain else None

        elif source_name == "spamhaus":
            if not any(c.isalpha() for c in line):
                return None
            return DomainIntelligence.normalize_domain(line)

        return None

    @staticmethod
    def _categorize_threat(domain: str) -> str:
        """Infer threat category from domain keywords."""
        domain_lower = domain.lower()

        if any(kw in domain_lower for kw in ["bet", "casino", "poker", "gamble", "slots"]):
            return "betting"
        if any(kw in domain_lower for kw in ["phish", "fake", "spoof"]):
            return "phishing"
        if any(kw in domain_lower for kw in ["malware", "virus", "trojan", "bot"]):
            return "malware"
        if any(kw in domain_lower for kw in ["deface", "hack"]):
            return "defacement"

        return "unknown"

    # ===== MAIN INTELLIGENCE CHECK =====

    async def check_domain(self, url: str, raw_request: str = "") -> Dict:
        """Complete domain intelligence check.

        Returns dict with 'classification' key (consistent with threat_engine).
        """
        result = {
            "url": url,
            "domain": None,
            "passes_domain_filter": False,
            "classification": "unknown",
            "blocked_reason": None,
            "threat_flags": {"type_defacement": 0.0, "type_malware": 0.0, "type_phishing": 0.0},
            "model4_features": None,
            "from_cache": False,
        }

        # 1. Extract domain
        domain = self.extract_domain(url)
        if not domain:
            result["blocked_reason"] = "invalid_domain"
            return result

        domain = self.normalize_domain(domain)
        result["domain"] = domain

        # 2. Check whitelist (fast-track)
        if await self.check_whitelist(domain):
            result["passes_domain_filter"] = True
            result["classification"] = "normal"
            return result

        # 3. Check blocklist
        blocklist_info = await self.check_blocklist(domain)
        if blocklist_info:
            result["blocked_reason"] = blocklist_info.get("category")
            result["classification"] = blocklist_info.get("category")
            result["threat_flags"] = self.extract_threat_flags(domain, blocklist_info)
            return result

        # 4. Validate DNS
        if not await self.validate_dns(domain):
            result["blocked_reason"] = "dns_failed"
            result["classification"] = "non_existent_domain"
            return result

        # 5. Heuristic checks
        is_suspicious, reason = self.heuristic_check(domain)
        if is_suspicious:
            result["blocked_reason"] = reason
            result["classification"] = "suspicious"
            result["threat_flags"] = self.extract_threat_flags(domain)
            return result

        # 6. Check cache for Model 4 classification
        cached = await self.get_cached_classification(domain)
        if cached:
            result["passes_domain_filter"] = cached["classification"] == "normal"
            result["classification"] = cached["classification"]
            result["from_cache"] = True
            return result

        # 7. Passed all filters, awaiting Model 4
        result["passes_domain_filter"] = True
        return result
