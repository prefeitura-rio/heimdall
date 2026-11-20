"""
Conversion of an endpoint path_pattern into the anchored regex used to match it.

Shared by the database fallback (MappingService) and the Redis fast path
(RedisMappingService), so both resolve a request path by the same rule
(DEV-680): the raw column text is never matched directly.
"""

import re
from functools import lru_cache


@lru_cache(maxsize=4096)
def convert_pattern_to_regex(path_pattern: str) -> str:
    """
    Convert a simple path pattern to a full regex pattern.
    Supports:
    - * for any characters within a path segment
    - ** for any path segments
    - Raw regex patterns with parentheses for capture groups
    Named ":param" segments are not supported (DEV-186): creation and
    update refuse them (see MappingService._has_named_param_segment).
    """
    # Check if this looks like a raw regex pattern (contains unescaped parentheses)
    if "(" in path_pattern and ")" in path_pattern:
        # Treat as raw regex, just ensure anchors
        pattern = path_pattern
        if not pattern.startswith("^"):
            pattern = "^" + pattern
        if not pattern.endswith("$"):
            pattern = pattern + "$"
        return pattern

    # A leading "^" and a trailing "$" are regex anchors, not literal path
    # characters: scripts/manage_openapi_mappings.py stores routes without
    # {param} as "<path>$". Strip them before escaping so they are not turned
    # into "\^" / "\$".
    body = path_pattern
    if body.startswith("^"):
        body = body[1:]
    if body.endswith("$") and not body.endswith("\\$"):
        body = body[:-1]

    # Escape special regex characters
    pattern = re.escape(body)

    # Handle ** for multiple path segments
    pattern = pattern.replace(r"\*\*", ".*")

    # Handle * for single path segment
    pattern = pattern.replace(r"\*", "[^/]*")

    # Ensure exact match. The anchors were stripped above, so a "\$" left at
    # the end is an escaped literal and must not count as an anchor.
    return "^" + pattern + "$"
