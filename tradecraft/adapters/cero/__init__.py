"""
Cero adapter package: Certificate Transparency subdomain discovery.
"""
from tradecraft.adapters.cero.execute import RawCeroResult, execute
from tradecraft.adapters.cero.parse import parse_domains

__all__ = ["execute", "parse_domains", "RawCeroResult"]
