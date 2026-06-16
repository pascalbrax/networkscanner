import sys
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple, List, Optional

PLUGINS_DIR = Path(__file__).parent.parent / 'plugins'
CONFIG_FILE = Path(__file__).parent.parent / 'config.json'

RECENT_TARGETS_MAX = 10


@dataclass
class Plugin:
    name: str
    path: Path
    enabled: bool = False
    description: str = ''
    column_title: str = ''                       # populated via --title
    options: List[Dict[str, Any]] = field(default_factory=list)       # schema, via --options
    selected_options: Dict[str, Any] = field(default_factory=dict)    # saved user choices


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
# Plugin option values (user-selected, persisted)
# ---------------------------------------------------------------------------

def get_plugin_option_values(name: str) -> Dict[str, Any]:
    """Return the saved option selections for a plugin (empty dict if none)."""
    config = _load_raw_config()
    return config.get('plugin_options', {}).get(name, {})


def set_plugin_option_values(name: str, values: Dict[str, Any]) -> None:
    """Persist the option selections for a single plugin."""
    config = _load_raw_config()
    all_options = config.get('plugin_options', {})
    all_options[name] = values
    config['plugin_options'] = all_options
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


def _plugin_declares_options(plugin_path: Path) -> bool:
    """
    Cheaply check whether a plugin's source even mentions '--options',
    without executing it.

    Plugins that don't implement the --options verb have no early-exit
    check for it, so calling them with --options falls through to their
    scan() function, which then tries to treat the literal string
    "--options" as a scan target (DNS lookups, socket connects, ...) —
    costing several seconds per plugin. Pre-filtering on the source text
    avoids ever spawning that subprocess for plugins that can't use it.
    """
    try:
        text = plugin_path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return False
    return "'--options'" in text or '"--options"' in text


def get_plugin_options(plugin_path: Path) -> List[Dict[str, Any]]:
    """
    Ask the plugin which configurable options it supports by calling it
    with --options. The plugin must respond with:
        {"options": [
            {"name": "mode", "label": "Display", "type": "choice",
             "choices": ["mac", "vendor"], "default": "mac"},
            ...
        ]}

    This is entirely optional — plugins that don't recognise --options
    simply fail to produce a valid {"options": [...]} response (the same
    way old plugins ignore --title), and this function returns [].
    Existing plugins require zero changes to keep working.
    """
    if not _plugin_declares_options(plugin_path):
        return []
    data = _run_wrapper(plugin_path, '--options', timeout=5)
    if data and isinstance(data.get('options'), list):
        return data['options']
    return []


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


def get_enabled_plugins(progress_callback=None) -> List[Plugin]:
    """
    Return all discovered plugins with enabled state, column title, option
    schema, and saved option selections resolved.

    Selected values are the saved choice if present, otherwise the schema's
    declared default, otherwise omitted (the plugin uses its own internal
    default — this is what keeps plugins without --options support working
    unmodified: their `options` list is simply empty).

    Each plugin requires up to two subprocess calls (--title, --options),
    so this can take a noticeable amount of time with many plugins. Callers
    on a GUI thread should run this in a background thread. Pass
    progress_callback(index, total, plugin_name) to report progress as
    each plugin finishes — called once per plugin, in order.
    """
    config = _load_raw_config()
    enabled_set = set(config.get('enabled_plugins', []))
    plugins = discover_plugins()
    total = len(plugins)
    for idx, p in enumerate(plugins, 1):
        p.enabled = p.name in enabled_set
        p.column_title = get_plugin_title(p.path)
        p.options = get_plugin_options(p.path)

        saved = get_plugin_option_values(p.name)
        selected: Dict[str, Any] = {}
        for opt in p.options:
            opt_name = opt.get('name')
            if not opt_name:
                continue
            selected[opt_name] = saved.get(opt_name, opt.get('default'))
        p.selected_options = selected

        if progress_callback:
            progress_callback(idx, total, p.name)
    return plugins


def set_enabled_plugins(names: List[str]) -> None:
    config = _load_raw_config()
    config['enabled_plugins'] = names
    save_config(config)


# ---------------------------------------------------------------------------
# Plugin execution
# ---------------------------------------------------------------------------

def run_plugin(
    plugin_path: Path,
    ip: str,
    timeout: int = 10,
    options: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """
    Run a plugin script with an IP address argument.

    Plugin protocol
    ---------------
    Called as:  python <plugin>.py --title
      Response: {"title": "<column header>"}

    Called as:  python <plugin>.py --options
      Response: {"options": [{"name": ..., "label": ..., "type": "choice",
                               "choices": [...], "default": ...}, ...]}
      Optional — plugins that don't support this simply have no options.

    Called as:  python <plugin>.py <ip> [--opts <json>]
      Response: {"short": "<brief result>", "long": "<detailed result>"}
      --opts is only appended when the user has configured option values
      for this plugin. Plugins that don't read sys.argv[2:] are unaffected —
      this keeps every existing plugin working without modification.

    Returns (short_answer, long_answer).
    Returns ('ERR', reason) on any failure.
    """
    try:
        args = [ip]
        if options:
            args += ['--opts', json.dumps(options)]

        proc = subprocess.run(
            [sys.executable, '-c', _make_wrapper(plugin_path), *args],
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
