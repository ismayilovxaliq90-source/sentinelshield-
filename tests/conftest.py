from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

src_text = str(SRC_ROOT)

if src_text not in sys.path:
    sys.path.insert(0, src_text)
