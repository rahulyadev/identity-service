"""Standalone reference browser-facing application."""

from reference_bff.app import create_app
from reference_bff.config import BffEnvironment, Settings

__all__ = ["BffEnvironment", "Settings", "create_app"]
