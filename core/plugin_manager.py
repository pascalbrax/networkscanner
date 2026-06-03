import sys
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Tuple, List, Optional

PLUGINS_DIR = Path(__file__).parent.parent / 'plugins'
CONFIG_FILE = Path(__file__).parent.parent / 'config.json'

RECENT_TARGETS_MAX = 10


@dataclass
class Plugin:
    name: str
    path: Path
    enabled: bool = False
    description: str = ''
    column_title: str = ''   # populated by querying the plugin with --title


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def _load_raw_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(config: dict) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)


# ---------------------------------------------------------------------------
# Recent targets
# ---------------------------------------------------------------------------

def get_recent_targets() -> List[str]:
    return _load_raw_config().get('recent_targets', [])


def add_recent_target(target: str) -> None:
    """Prepend target to the recent list (max RECENT_TARGETS_MAX, no duplicates)."""
    target = target.strip()
    if not target:
        return
    config = _load_raw_config()
    recent = [t for t in config.get('recent_targets', []) if t != target]
    recent.insert(0, target)
    config['recent_targets'] = recent[:RECENT_TARGETS_MAX]
    save_config(config)


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------

def _make_wrapper(plugin_path: Path) -> str:
    """Return the -c wrapper string used to run a plugin in a clean sys.path."""
    return (
        "import sys, runpy; "
        f"plugin_dir = {str(plugin_path.parent)!r}; "
        "sys.path = [p for p in sys.path if p and p != plugin_dir]; "
        f"runpy.run_path({str(plugin_path)!r}, run_name='__main__')"
    )


def _subprocess_kwargs() -> dict:
    kwargs: dict = {}
    if sys.platform == 'win32':
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    return kwargs


def _run_wrapper(plugin_path: Path, *args: str, timeout: int = 5) -> Optional[dict]:
    """
    Run a plugin via the sys.path-clean wrapper and return parsed JSON, or None on failure.
    Extra positional args are appended after '-c <wrapper>' and become sys.argv[1], [2], …
    """
    try:
        proc = subprocess.run(
            [sys.executable, '-c', _make_wrapper(plugin_path), *args],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            **_subprocess_kwargs(),
        )
        return json.loads(proc.stdout.strip())
    except Exception:
        return None


def get_plugin_title(plugin_path: Path) -> str:
    """
    Ask the plugin for its preferred column title by calling it with --title.
    The plugin must respond with {"title": "..."}.
    Falls back to the filename stem if the plugin does not support the flag.
    """
    data = _run_wrapper(plugin_path, '--title', timeout=5)
    if data and isinstance(data.get('title'), str) and data['title'].strip():
        return data['title'].strip()
    return Path(plugin_path).stem.upper()


def _read_description(path: Path) -> str:
    """Read the first comment line of a plugin file as its description."""
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith('#'):
                    return stripped.lstrip('#').strip()
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    return stripped.strip('"\'').strip()
                if stripped:
                    break
    except Exception:
        pass
    return ''


def discover_plugins(plugins_dir: Optional[Path] = None) -> List[Plugin]:
    """Return all .py files in the plugins folder as Plugin objects."""
    d = Path(plugins_dir) if plugins_dir else PLUGINS_DIR
    plugins: List[Plugin] = []
    if not d.exists():
        return plugins
    for fpath in sorted(d.glob('*.py')):
        if fpath.name.startswith('_'):
            continue
        plugins.append(Plugin(
            name=fpath.stem,
            path=fpath,
            description=_read_description(fpath),
        ))
    return plugins


def get_enabled_plugins() -> List[Plugin]:
    """
    Return all discovered plugins with enabled state and column titles resolved.
    Column titles are fetched by calling each plugin with --title.
    """
    config = _load_raw_config()
    enabled_set = set(config.get('enabled_plugins', []))
    plugins = discover_plugins()
    for p in plugins:
        p.enabled = p.name in enabled_set
        p.column_title = get_plugin_title(p.path)
    return plugins


def set_enabled_plugins(names: List[str]) -> None:
    config = _load_raw_config()
    config['enabled_plugins'] = names
    save_config(config)


# ---------------------------------------------------------------------------
# Plugin execution
# ---------------------------------------------------------------------------

def run_plugin(plugin_path: Path, ip: str, timeout: int = 10) -> Tuple[str, str]:
    """
    Run a plugin script with an IP address argument.

    Plugin protocol
    ---------------
    Called as:  python <plugin>.py --title
      Response: {"title": "<column header>"}

    Called as:  python <plugin>.py <ip>
      Response: {"short": "<brief result>", "long": "<detailed result>"}

    Returns (short_answer, long_answer).
    Returns ('ERR', reason) on any failure.
    """
    try:
        proc = subprocess.run(
            [sys.executable, '-c', _make_wrapper(plugin_path), ip],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            **_subprocess_kwargs(),
        )

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        if not stdout:
            detail = f'\nstderr: {stderr}' if stderr else ''
            return ('ERR', f'Plugin produced no output.{detail}')

        data = json.loads(stdout)
        short = str(data.get('short', '')).strip()
        long_ = str(data.get('long', '')).strip()
        return (short, long_)

    except subprocess.TimeoutExpired:
        return ('TIMEOUT', f'Plugin did not respond within {timeout}s.')
    except json.JSONDecodeError as exc:
        raw = locals().get('stdout', '')
        return ('ERR', f'Invalid JSON: {exc}\nRaw output: {raw}')
    except FileNotFoundError:
        return ('ERR', f'Plugin not found: {plugin_path}')
    except Exception as exc:
        return ('ERR', str(exc))
