"""Installable URL risk analyzer CLI package."""

from .analyzer import analyze_url, check_similarity

__all__ = ["analyze_url", "check_similarity"]
