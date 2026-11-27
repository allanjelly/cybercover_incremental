"""Compatibility with the Artemis internals this package relies on (requirements R4.2).

cybercover_ops runs this suite against every upgrade candidate (./ops update), so a change in Artemis
that breaks the modules is found before the upgrade is applied. Example: Artemis 2fee327d removed
ScanUsing and changed Nuclei._scan.

Generic part: every `from artemis... import name` and every `Config.<Section>.<SETTING>` in the package
must resolve. Imports inside `try: ... except ImportError:` are optional and skipped.
Explicit part: the stock methods the modules override or call, with the arguments they pass.
"""

import ast
import importlib
import inspect
import re
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "cybercover"


def _guarded(node: ast.AST, parents: dict) -> bool:
    """Inside a `try` whose handlers catch ImportError: an optional import."""
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                names = [handler.type] if not isinstance(handler.type, ast.Tuple) else list(handler.type.elts)
                if any(isinstance(n, ast.Name) and n.id in ("ImportError", "ModuleNotFoundError") for n in names):
                    return True
    return False


def artemis_imports() -> Iterator[Tuple[str, str, Optional[str]]]:
    for file in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(file.read_text(), str(file))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            if _guarded(node, parents):
                continue
            if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] == "artemis":
                for alias in node.names:
                    yield file.name, node.module, alias.name
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "artemis":
                        yield file.name, alias.name, None


def config_settings() -> List[str]:
    found = set()
    for file in PACKAGE.rglob("*.py"):
        found.update(re.findall(r"\bConfig((?:\.[A-Za-z_][A-Za-z0-9_]*){2,})", file.read_text()))
    return sorted(found)


IMPORTS = sorted(set(artemis_imports()))


def test_the_package_imports_something_from_artemis():
    assert len(IMPORTS) > 10, IMPORTS


@pytest.mark.parametrize("file,module,name", IMPORTS, ids=[f"{m}.{n or ''} ({f})" for f, m, n in IMPORTS])
def test_artemis_import_resolves(file, module, name):
    mod = importlib.import_module(module)
    if name is None or hasattr(mod, name):
        return
    try:
        importlib.import_module(f"{module}.{name}")  # a submodule, e.g. `from artemis import load_risk_class`
    except ImportError:
        pytest.fail(f"{file} imports {name} from {module}, which this Artemis no longer has")


@pytest.mark.parametrize("setting", config_settings())
def test_config_setting_exists(setting):
    from artemis.config import Config

    obj = Config
    for part in setting.strip(".").split("."):
        assert hasattr(obj, part), f"Config{setting}: no {part}"
        obj = getattr(obj, part)


def _bind(func, *args, **kwargs) -> None:
    """The stock function accepts the arguments our code passes (by count and keyword)."""
    inspect.signature(func).bind(*args, **kwargs)


def test_nuclei_methods_we_override_or_call():
    from artemis.modules import nuclei as nuclei_module
    from artemis.modules.nuclei import NUCLEI_TEMPLATES_LOCATION, Nuclei

    assert isinstance(NUCLEI_TEMPLATES_LOCATION, str) and NUCLEI_TEMPLATES_LOCATION
    # The shared template lock of cybercover_nuclei is keyed by this identity.
    assert Nuclei.identity == "nuclei-module"
    _bind(Nuclei.run_multiple, "self", ["tasks"])
    _bind(Nuclei._get_links, "self", "https://example.com")
    assert callable(nuclei_module.check_output_log_on_error_with_stderr)

    params = list(inspect.signature(Nuclei._scan).parameters)
    try:
        from artemis.modules.nuclei import ScanUsing  # Artemis before 2fee327d
    except ImportError:
        ScanUsing = None
    if ScanUsing is None:
        assert params[:3] == ["self", "templates", "targets"], params
        _bind(Nuclei._scan, "self", ["t.yaml"], ["https://example.com"], extra_nuclei_args=[])
    else:
        assert params[:4] == ["self", "templates_or_workflows", "scan_using", "targets"], params
        assert {"TEMPLATES", "WORKFLOWS"} <= set(ScanUsing.__members__)
        _bind(Nuclei._scan, "self", ["t.yaml"], ScanUsing.TEMPLATES, ["https://example.com"], extra_nuclei_args=[])


def test_port_scanner_and_base_methods():
    from artemis.module_base import ArtemisBase
    from artemis.modules.port_scanner import PortScanner

    _bind(PortScanner.run_multiple, "self", ["tasks"])
    _bind(ArtemisBase.add_task, "self", "current_task", "new_task")
    _bind(ArtemisBase.add_task_if_domain_exists, "self", "current_task", "new_task")
    _bind(ArtemisBase.save_task_result, "self", task="task", status="status", status_reason=None, data={})
    # A failed batch must still save a result for each task (cybercover_nuclei relies on it).
    assert hasattr(ArtemisBase, "process_multiple")


def test_shared_infrastructure():
    from artemis.redis_cache import RedisCache
    from artemis.resource_lock import ResourceLock

    _bind(ResourceLock, res_name="nuclei-module")  # as cybercover_nuclei creates the shared template lock
    assert RedisCache is not None


def test_task_result_columns():
    from artemis.db import TaskResult

    columns = set(TaskResult.__table__.columns.keys())
    assert {"receiver", "target_string", "status", "task", "result", "created_at"} <= columns, columns
