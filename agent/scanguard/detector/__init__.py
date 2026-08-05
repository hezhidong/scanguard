"""Detector package."""
from .engine import Hit, scan
from .parser import parse_line

__all__ = ["Hit", "scan", "parse_line"]
