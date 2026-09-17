"""
GeoIP Intelligence & VPN / Threat Origin Detection Service.
Resolves incoming IP addresses to geographic coordinates, cities, and VPN/datacenter reputation scores.
Includes an in-memory high-speed cache and offline presets for presentation demos.
"""
import logging
import urllib.request
import json
from typing import Dict, Any, Optional

logger = logging.getLogger("AWSSecurity.GeoIP")

# Pre-calibrated high-fidelity presets for live demonstrations and testing
KNOWN_GEO_PRESETS: Dict[str, Dict[str, Any]] = {
    "133.242.18.5": {
        "city": "Tokyo",
        "country": "Japan",
        "lat": 35.6762,
        "lon": 139.6503,
        "ip_reputation": 0.85,
        "is_vpn": True,
        "provider": "SAKURA Cloud / Datacenter VPN",
        "region_code": "JP"
    },
    "185.220.101.5": {
        "city": "London",
        "country": "United Kingdom",
        "lat": 51.5074,
        "lon": -0.1278,
        "ip_reputation": 0.95,
        "is_vpn": True,
        "provider": "Tor Exit Node / Privacy Relay",
        "region_code": "GB"
    },
    "45.33.32.1": {
        "city": "Frankfurt",
        "country": "Germany",
        "lat": 50.1109,
        "lon": 8.6821,
        "ip_reputation": 0.80,
        "is_vpn": True,
        "provider": "Linode / Commercial Datacenter VPN",
        "region_code": "DE"
    },
    "103.253.144.1": {
        "city": "Singapore",
        "country": "Singapore",
        "lat": 1.3521,
        "lon": 103.8198,
        "ip_reputation": 0.75,
        "is_vpn": True,
        "provider": "SingNet / Commercial VPN",
        "region_code": "SG"
    },
    "185.100.87.5": {
        "city": "Amsterdam",
        "country": "Netherlands",
        "lat": 52.3676,
        "lon": 4.9041,
        "ip_reputation": 0.85,
        "is_vpn": True,
        "provider": "M247 / Datacenter Proxy",
        "region_code": "NL"
    },
    "198.51.100.1": {
        "city": "New York",
        "country": "United States",
        "lat": 40.7128,
        "lon": -74.0060,
        "ip_reputation": 0.05,
        "is_vpn": False,
        "provider": "Primary Office / Residential ISP",
        "region_code": "US"
    },
    "198.51.100.42": {
        "city": "Philadelphia",
        "country": "United States",
        "lat": 39.9526,
        "lon": -75.1652,
        "ip_reputation": 0.10,
        "is_vpn": False,
        "provider": "Regional ISP (Human Coverable - 150 km)",
        "region_code": "US"
    },
    "198.51.100.88": {
        "city": "Boston",
        "country": "United States",
        "lat": 42.3601,
        "lon": -71.0589,
        "ip_reputation": 0.10,
        "is_vpn": False,
        "provider": "Regional ISP (Human Coverable - 300 km)",
        "region_code": "US"
    },
    "198.98.56.2": {
        "city": "Zurich",
        "country": "Switzerland",
        "lat": 47.3769,
        "lon": 8.5417,
        "ip_reputation": 0.90,
        "is_vpn": True,
        "provider": "Swiss Privacy VPN Relay",
        "region_code": "CH"
    },
    "162.247.74.200": {
        "city": "Sydney",
        "country": "Australia",
        "lat": -33.8688,
        "lon": 151.2093,
        "ip_reputation": 0.80,
        "is_vpn": True,
        "provider": "Cloudflare WARP / Datacenter",
        "region_code": "AU"
    },
    "192.88.99.1": {
        "city": "Los Angeles",
        "country": "United States",
        "lat": 34.0522,
        "lon": -118.2437,
        "ip_reputation": 0.65,
        "is_vpn": True,
        "provider": "US West Coast VPN Exit",
        "region_code": "US"
    }
}

# In-memory GeoIP cache to avoid repeated network lookups
_GEO_CACHE: Dict[str, Dict[str, Any]] = dict(KNOWN_GEO_PRESETS)


def is_private_or_local_ip(ip: Optional[str]) -> bool:
    """Returns True if the IP is local, loopback, or private RFC1918."""
    if not ip or ip in ("127.0.0.1", "localhost", "::1", "testclient"):
        return True
    parts = ip.split(".")
    if len(parts) == 4 and parts[0].isdigit():
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10:
            return True
        if p0 == 172 and 16 <= p1 <= 31:
            return True
        if p0 == 192 and p1 == 168:
            return True
    return False


def resolve_ip_geolocation(ip: str) -> Dict[str, Any]:
    """
    Resolves an IP address to geographic coordinates, city, country, and VPN indicators.
    Priority:
    1. In-memory / Preset cache (instant, reliable for presentations)
    2. Online GeoIP lookup via ip-api.com (1.2s timeout for real commercial VPNs)
    3. Default New York fallback
    """
    clean_ip = (ip or "").strip()
    if not clean_ip or clean_ip == "testclient":
        clean_ip = "127.0.0.1"

    # 1. Check Cache / Presets
    if clean_ip in _GEO_CACHE:
        return dict(_GEO_CACHE[clean_ip])

    # Check prefix matches for known subnets
    for preset_ip, data in KNOWN_GEO_PRESETS.items():
        prefix = ".".join(preset_ip.split(".")[:2]) + "."
        if clean_ip.startswith(prefix):
            return dict(data)

    # 2. If private / local IP, return baseline local location
    if is_private_or_local_ip(clean_ip):
        return {
            "city": "New York",
            "country": "United States",
            "lat": 40.7128,
            "lon": -74.0060,
            "ip_reputation": 0.0,
            "is_vpn": False,
            "provider": "Local Host / Private Network",
            "region_code": "US"
        }

    # 3. Dynamic Lookup for Public / VPN IPs
    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,city,lat,lon,hosting,proxy,query"
        req = urllib.request.Request(url, headers={"User-Agent": "AWSSecurityAI-GeoIP/2.0"})
        with urllib.request.urlopen(req, timeout=1.2) as response:
            if response.status == 200:
                payload = json.loads(response.read().decode("utf-8"))
                if payload.get("status") == "success":
                    is_hosting = bool(payload.get("hosting") or payload.get("proxy"))
                    geo_res = {
                        "city": payload.get("city", "Unknown City"),
                        "country": payload.get("country", "Unknown Country"),
                        "lat": float(payload.get("lat", 40.7128)),
                        "lon": float(payload.get("lon", -74.0060)),
                        "ip_reputation": 0.80 if is_hosting else 0.15,
                        "is_vpn": is_hosting,
                        "provider": "Commercial VPN / Hosting" if is_hosting else "Public ISP",
                        "region_code": payload.get("countryCode", "US")
                    }
                    _GEO_CACHE[clean_ip] = geo_res
                    return dict(geo_res)
    except Exception as err:
        logger.debug(f"Dynamic GeoIP lookup timed out or failed for {clean_ip}: {err}")

    # 4. Fallback Default
    fallback = {
        "city": "New York",
        "country": "United States",
        "lat": 40.7128,
        "lon": -74.0060,
        "ip_reputation": 0.1,
        "is_vpn": False,
        "provider": "Standard Internet Access",
        "region_code": "US"
    }
    _GEO_CACHE[clean_ip] = fallback
    return fallback


def get_available_vpn_presets() -> Dict[str, Dict[str, Any]]:
    """Returns the list of presentation presets for the UI."""
    return KNOWN_GEO_PRESETS
