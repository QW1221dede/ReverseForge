#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rf.snippets · 代码积木

    from rf.snippets import get_library
    lib = get_library()
    lib.get("patch.apply").card()
"""

from .library import Library, get_library
from .model import CATEGORIES, LEVEL_NAMES, Snippet, analyze_code, parse_user_snippet

__all__ = ["Library", "get_library", "Snippet", "CATEGORIES", "LEVEL_NAMES",
           "parse_user_snippet", "analyze_code"]
