from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PersistentState:
    last_decision: str
    last_reason: str
    recovery_count: int


class StateStore:
    """
    Small atomic JSON state store.

    The state file is replaced atomically so an interrupted write
    does not normally leave a partially written state file.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()

    def save(self, state: PersistentState) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = json.dumps(
            asdict(state),
            sort_keys=True,
        )

        fd, temporary = tempfile.mkstemp(
            prefix=".sentinelshield-",
            suffix=".tmp",
            dir=str(self.path.parent),
        )

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(
                temporary,
                self.path,
            )
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def load(self) -> PersistentState | None:
        if not self.path.exists():
            return None

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            data = json.load(handle)

        return PersistentState(
            last_decision=str(
                data["last_decision"]
            ),
            last_reason=str(
                data["last_reason"]
            ),
            recovery_count=int(
                data["recovery_count"]
            ),
        )

    def exists(self) -> bool:
        return self.path.exists()
