"""Semantic layer over the serving DB (docs/agentic-briefs.md)."""

from .layer import SemanticLayer
from .models import SEMANTIC_VERSION
from .playbooks import PLAYBOOK_VERSION, playbook_for

__all__ = ["SemanticLayer", "SEMANTIC_VERSION", "PLAYBOOK_VERSION", "playbook_for"]
