"""Shared fixtures. A ``fake_repo`` builds a minimal compliant tree that tests then break.

The rule checkers are only worth having if they fail on real violations, so every checker test
follows the same shape: start from a clean tree, plant exactly one violation, assert that the
checker reports it and names the right rule. Asserting a checker passes on a clean tree proves
almost nothing on its own.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

#: A cut-down standards document. ``check_structure`` reads the documented directory names out of
#: the real document's section 2.1 tree, so the fixture must supply one in the same shape.
STANDARDS_STUB = """# Talos -- Engineering Standards

### 2.1 Full repository tree

```
Talos/
├── config/
├── db/
│   ├── schema/
│   ├── migrations/
│   │   └── rollback/
│   ├── seeds/
│   └── queries/
├── docs/
│   ├── architecture/
│   ├── features/
│   ├── standards/
│   └── planning/
├── scripts/
├── src/
│   └── talos/
│       ├── core/
│       ├── schemas/
│       ├── domains/
│       │   └── web/
│       │       └── injection/
│       └── llm/
│           └── prompts/
├── tests/
│   ├── unit/
│   └── fixtures/
└── tools/
    └── checks/
```

Trailing prose so the block above is unambiguously closed.
"""


def write(path: Path, content: str = "") -> Path:
    """Create ``path`` and any missing parents, then write ``content``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def write_file() -> Callable[..., Path]:
    """Expose :func:`write` as a fixture.

    Tests reach it this way rather than by importing ``conftest``: with no ``__init__.py`` under
    ``tests/``, pytest puts each test file's own directory on ``sys.path``, so a direct
    ``from conftest import write`` would resolve only for tests sitting beside this file.
    """
    return write


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """A minimal tree that passes every checker, ready to have one violation planted in it."""
    write(tmp_path / "pyproject.toml", '[project]\nname = "talos"\n')
    write(tmp_path / "README.md", "# Talos\n")
    write(tmp_path / ".gitignore", "__pycache__/\n")
    write(tmp_path / "docs" / "standards" / "Talos_Engineering_Standards.md", STANDARDS_STUB)
    write(tmp_path / "src" / "talos" / "__init__.py", '"""Talos."""\n')
    write(tmp_path / "src" / "talos" / "py.typed")
    write(tmp_path / "src" / "talos" / "core" / "__init__.py")
    (tmp_path / "docs" / "features").mkdir(parents=True, exist_ok=True)
    (tmp_path / "db" / "migrations" / "rollback").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture
def feature_dir(fake_repo: Path) -> Path:
    """A complete, compliant feature folder under ``docs/features/``."""
    feature = fake_repo / "docs" / "features" / "web-sql-injection-detection"
    write(
        feature / "README.md",
        "# Feature -- Web SQL Injection Detection\n\n"
        "**Status:** in-progress\n"
        "**Code:** `src/talos/domains/web/injection/sql_injection_detector.py`\n",
    )
    for name in ("design.md", "testing.md", "changelog.md", "detection-logic.md"):
        write(feature / name, f"# {name}\n")
    return feature
