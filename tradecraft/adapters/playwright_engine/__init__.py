"""
Playwright engine adapter package: model-directed headless browser interaction.
"""
from tradecraft.adapters.playwright_engine.execute import RawPlaywrightResult, execute
from tradecraft.adapters.playwright_engine.parse import parse_result

__all__ = ["execute", "parse_result", "RawPlaywrightResult"]
