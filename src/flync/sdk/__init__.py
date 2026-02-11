"""
This package provides the core functionality for interacting \
with the FLYNC core modules, including utilities for workspace managment.
It exposes a clean, Pythonic API for developers to integrate FLYNC \
capabilities into their applications.
"""

from .workspace.flync_workspace import FLYNCWorkspace

__all__ = [
    "FLYNCWorkspace",
]
