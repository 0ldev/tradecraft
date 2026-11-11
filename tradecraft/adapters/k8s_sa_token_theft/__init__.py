"""
k8s_sa_token_theft adapter package.
"""
from __future__ import annotations

from tradecraft.adapters.k8s_sa_token_theft.execute import execute
from tradecraft.adapters.k8s_sa_token_theft.parse import parse

__all__ = ["execute", "parse"]
