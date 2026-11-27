#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 rf.server · 本地 HTTP API（给 AI / 外部脚本调用）
============================================================================

    from rf.server import ApiServer
    srv = ApiServer(port=8765, allow_write=False).start()
    print(srv.url)
    srv.stop()

接口说明见 http://127.0.0.1:8765/ 或 api_server.py 文件头。
============================================================================
"""

from .api_server import TOOLS, ApiServer, tool_schema

__all__ = ["ApiServer", "TOOLS", "tool_schema"]
