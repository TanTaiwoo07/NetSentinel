#!/usr/bin/env python3
"""NetSentinel 启动入口。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from netsentinel.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
