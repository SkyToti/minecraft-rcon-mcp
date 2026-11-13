from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from pathlib import Path

from minecraft_rcon_mcp.audit import AuditLog


def read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_appends_json_lines_with_utc_ts(tmp_path: Path) -> None:
    path = tmp_path / "state" / "nested" / "audit.jsonl"
    log = AuditLog(path)
    log.record(server="test", tool="run_command", command="list", tier="read", outcome="executed", detail="len=12")
    log.record(server="test", tool="run_command", command="stop", tier="confirm", outcome="ticket_issued")
    entries = read_lines(path)
    assert len(entries) == 2
    assert list(entries[0])[0] == "ts"
    assert entries[0]["command"] == "list" and entries[1]["outcome"] == "ticket_issued"
    ts = datetime.fromisoformat(entries[0]["ts"])
    assert ts.utcoffset() == timezone.utc.utcoffset(None)


def test_file_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record(outcome="executed")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_existing_file_tightened_to_0600(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    path.chmod(0o644)
    AuditLog(path).record(outcome="executed")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_password_and_secret_fields_dropped(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record(
        server="test",
        password="hunter2",
        rcon_password="hunter2",
        Client_Secret="hunter2",
        detail={"nested_password": "hunter2", "ok": 1},
    )
    text = path.read_text(encoding="utf-8")
    assert "hunter2" not in text
    (entry,) = read_lines(path)
    assert entry["server"] == "test"
    assert entry["detail"] == {"ok": 1}


def test_caller_cannot_forge_ts(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record(ts="1999-01-01T00:00:00", outcome="executed")
    (entry,) = read_lines(path)
    assert not entry["ts"].startswith("1999")


def test_non_json_values_stringified(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record(path=tmp_path, unicode="ñ ✓")
    (entry,) = read_lines(path)
    assert entry["path"] == str(tmp_path)
    assert entry["unicode"] == "ñ ✓"
