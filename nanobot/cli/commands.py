"""CLI commands for nanobot."""
# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        _base = url.rstrip("/")
        if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)

# pyright: reportConstantRedefinition=false, reportMissingTypeStubs=false, reportPrivateUsage=false, reportUnusedFunction=false, reportUnusedImport=false

import asyncio
import os
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

# Force UTF-8 encoding for Windows console
if sys.platform == "win32":
    if sys.stdout.encoding != "utf-8":
        os.environ["PYTHONIOENCODING"] = "utf-8"
        # Re-open stdout/stderr with UTF-8 encoding
        with suppress(Exception):
            for stream in (sys.stdout, sys.stderr):
                reconfigure = getattr(stream, "reconfigure", None)
                if callable(reconfigure):
                    reconfigure(encoding="utf-8", errors="replace")

# Keep console encoding setup before importing CLI UI/logging libraries.
import typer  # noqa: E402
from loguru import logger  # noqa: E402
from typer.core import TyperGroup  # noqa: E402

# Remove default handler and re-add with unified nanobot format
logger.remove()
_log_handler_id = logger.add(
    sys.stderr,
    format=(
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <5}</level> | "
        "<cyan>{extra[channel]}</cyan> | "
        "<level>{message}</level>"
    ),
    level="INFO",
    colorize=None,
    filter=lambda record: record["extra"].setdefault("channel", "-") or True,
)


from rich.console import Console  # noqa: E402
from rich.markup import escape  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

from nanobot import __logo__, __version__  # noqa: E402
from nanobot import optional_features as feature_support  # noqa: E402
from nanobot.agent.hooks import create_file_edit_activity_hook  # noqa: E402
from nanobot.agent.loop import AgentLoop  # noqa: E402
from nanobot.agent.tools.mcp import MCPProvider  # noqa: E402
from nanobot.agent.tools.registry import ToolRegistry  # noqa: E402
from nanobot.cli import terminal as cli_terminal  # noqa: E402
from nanobot.cli.agent import agent  # noqa: E402
from nanobot.cli.gateway import create_gateway_app  # noqa: E402
from nanobot.cli.gateway_runtime import _run_gateway  # noqa: E402
from nanobot.cli.log_control import _set_nanobot_logs  # noqa: E402
from nanobot.cli.process_identity import set_cli_process_identity  # noqa: E402
from nanobot.cli.provider import provider_app  # noqa: E402
from nanobot.cli.runtime_config import (  # noqa: E402
    _load_inspection_config,
    _load_runtime_config,
    _model_display,
    _print_config_error,
    _print_model_setup_steps,
    _provider_setup_error,
)
from nanobot.cli.webui import webui  # noqa: E402
from nanobot.cli.webui_support import (  # noqa: E402
    _prepare_webui_bundle_for_gateway,
    _validate_gateway_startup,
)
from nanobot.config.paths import get_workspace_path  # noqa: E402
from nanobot.config.schema import Config  # noqa: E402
from nanobot.security.network import is_loopback_host  # noqa: E402
from nanobot.utils.helpers import sanitize_surrogates as _sanitize_surrogates  # noqa: E402,F401
from nanobot.utils.helpers import (  # noqa: E402
    sync_workspace_templates,
)

# Backward-compatible import for callers that used the former module location.
SafeFileHistory = cli_terminal.SafeFileHistory


class _DesktopAwareGroup(TyperGroup):
    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        # Keep exact arguments: explicitly passing even a default-valued option
        # must bypass the picker. Also covers older commands:app launchers.
        ctx.meta["desktop_target_args"] = list(args)
        return super().parse_args(ctx, args)


app = typer.Typer(
    cls=_DesktopAwareGroup,
    name="nanobot",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=f"{__logo__} nanobot - Personal AI Assistant",
    epilog=(
        "Run `nanobot` without a subcommand to start the terminal agent. "
        "Use `nanobot agent --help` for agent options."
    ),
    invoke_without_command=True,
    no_args_is_help=False,
)

console = Console()

def version_callback(value: bool):
    if value:
        _lineaje_payload = f"{__logo__} nanobot v{__version__}"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:f84accfdc6f4e6aeedd6e08d2eb3a833d2c04d2ae25eb8e7da95be46a6124cd8')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"{__logo__} nanobot v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True
    ),
):
    """nanobot - Personal AI Assistant."""
    # Editable/source installs can retain an older generated console script that
    # imports this Typer app directly instead of ``nanobot.cli.entry``. Keep the
    # role identity correct until that launcher is regenerated.
    command = ctx.invoked_subcommand
    set_cli_process_identity([command] if command else ["agent"])
    from nanobot.cli.desktop_target import dispatch_bare_desktop_target

    raw_args = ctx.meta.get("desktop_target_args")
    if isinstance(raw_args, list):
        desktop_exit = dispatch_bare_desktop_target(cast(list[str], raw_args))
        if desktop_exit is not None:
            raise typer.Exit(desktop_exit)
    if command is None:
        from nanobot.cli.entry import _run_agent

        _run_agent([], prog_name="nanobot")


# ============================================================================
# Onboard / Setup
# ============================================================================


@app.command()
def onboard(
    workspace: str | None = typer.Option(None, "--workspace", "-w", help="Workspace directory"),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
    wizard: bool = typer.Option(False, "--wizard", help="Use interactive wizard"),
    non_interactive_refresh: bool = typer.Option(False, "--refresh", help="Refresh config, preserving existing settings without prompting"),
):
    """Initialize nanobot configuration and workspace."""
    from nanobot.config.loader import get_config_path, load_config, save_config, set_config_path
    from nanobot.config.schema import Config

    explicit_config = config is not None
    if config:
        config_path = Path(config).expanduser().resolve()
        set_config_path(config_path)
        _lineaje_payload = f"[dim]Using config: {config_path}[/dim]"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:65920e323f697f2e333a382fcc29988ef18dee63c938b0d6e0919523067e9dd3')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"[dim]Using config: {config_path}[/dim]")
    else:
        config_path = get_config_path()

    def _apply_workspace_override(loaded: Config) -> Config:
        if workspace:
            loaded.agents.defaults.workspace = workspace
        try:
            loaded = gr_check(loaded, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:f30e711cfbfa201ab42b236f041c3612ce49f5f910e02b72af8934666a54bb01')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            loaded = loaded
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return loaded

    loaded_config: Config | None = None
    # Create or update config
    if config_path.exists():
        if wizard:
            loaded_config = _apply_workspace_override(load_config(config_path))
        else:
            should_refresh = non_interactive_refresh
            if not non_interactive_refresh:
                _lineaje_payload = f"[yellow]Config already exists at {config_path}[/yellow]"
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:faf17bafb8c4e3ef716acf035aacf35c4009819d03872c649a0fadae1cb52b1c')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                console.print(f"[yellow]Config already exists at {config_path}[/yellow]")
                _lineaje_payload = "  [bold]y[/bold] = overwrite with defaults (existing values will be lost)"
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:faf17bafb8c4e3ef716acf035aacf35c4009819d03872c649a0fadae1cb52b1c')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                console.print(
                    "  [bold]y[/bold] = overwrite with defaults (existing values will be lost)"
                )
                _lineaje_payload = "  [bold]N[/bold] = refresh config, keeping existing values and adding new fields"
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:faf17bafb8c4e3ef716acf035aacf35c4009819d03872c649a0fadae1cb52b1c')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                console.print(
                    "  [bold]N[/bold] = refresh config, keeping existing values and adding new fields"
                )
                if typer.confirm("Overwrite?"):
                    loaded_config = _apply_workspace_override(Config())
                    save_config(loaded_config, config_path)
                    console.print(f"[green]✓[/green] Config reset to defaults at {config_path}")
                else:
                    should_refresh = True

            if should_refresh:
                loaded_config = _apply_workspace_override(load_config(config_path))
                save_config(loaded_config, config_path)
                _lineaje_payload = f"[green]✓[/green] Config refreshed at {config_path} (existing values preserved)"
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:bc2032f34d6721b3894ce6c2eff8515da23e104f596e433bfc50c745d906b356')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                console.print(
                    f"[green]✓[/green] Config refreshed at {config_path} (existing values preserved)"
                )
    else:
        loaded_config = _apply_workspace_override(Config())
        # In wizard mode, don't save yet - the wizard will handle saving if should_save=True
        if not wizard:
            save_config(loaded_config, config_path)
            console.print(f"[green]✓[/green] Created config at {config_path}")

    assert loaded_config is not None

    # Run interactive wizard if enabled
    if wizard:
        from nanobot.cli.onboard import run_onboard

        try:
            result = run_onboard(initial_config=loaded_config)
            if not result.should_save:
                _lineaje_payload = "[yellow]Configuration discarded. No changes were saved.[/yellow]"
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:bc2032f34d6721b3894ce6c2eff8515da23e104f596e433bfc50c745d906b356')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                console.print("[yellow]Configuration discarded. No changes were saved.[/yellow]")
                return

            loaded_config = result.config
            save_config(loaded_config, config_path)
            console.print(f"[green]✓[/green] Config saved at {config_path}")
        except Exception as e:
            console.print(f"[red]✗[/red] Error during configuration: {e}")
            _lineaje_payload = "[yellow]Please run 'nanobot onboard' again to complete setup.[/yellow]"
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:bc2032f34d6721b3894ce6c2eff8515da23e104f596e433bfc50c745d906b356')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            console.print("[yellow]Please run 'nanobot onboard' again to complete setup.[/yellow]")
            raise typer.Exit(1)
    _onboard_plugins(config_path)

    # Create workspace, preferring the configured workspace path.
    workspace_path = get_workspace_path(loaded_config.workspace_path)
    if not workspace_path.exists():
        workspace_path.mkdir(parents=True, exist_ok=True)
        console.print(f"[green]✓[/green] Created workspace at {workspace_path}")

    sync_workspace_templates(workspace_path)

    webui_cmd = "nanobot webui"
    if explicit_config:
        webui_cmd += f' -c "{config_path}"'

    typer.echo(f"\n✓ nanobot is ready. Run: {webui_cmd}")


def _onboard_plugins(config_path: Path) -> None:
    """Inject default config for all discovered channels (built-in + plugins)."""
    import json

    from nanobot.channels.contracts import channel_default_config
    from nanobot.channels.registry import discover_plugins
    from nanobot.config.loader import merge_missing_defaults

    plugins = discover_plugins()
    if not plugins:
        return

    with open(config_path, encoding="utf-8") as f:
        data = json.load(f)

    channels = data.setdefault("channels", {})
    for name, plugin in plugins.items():
        defaults = channel_default_config(plugin)
        if name not in channels:
            channels[name] = defaults
        else:
            channels[name] = merge_missing_defaults(channels[name], defaults)

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _print_enable_options(
    extras: dict[str, list[str] | None],
    channel_plugins: dict[str, Any],
    config: Config,
) -> None:
    table = Table(title="Available Features")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Enabled")

    for item in sorted(set(channel_plugins) | set(extras)):
        plugin = channel_plugins.get(item)
        is_channel = plugin is not None
        enabled = (
            feature_support.channel_enabled(
                config,
                item,
                plugin,
                default_enabled=plugin.default_enabled,
            )
            if is_channel
            else feature_support.extra_installed(item, extras[item])
        )
        table.add_row(
            item,
            "channel" if is_channel else "feature",
            "[green]yes[/green]" if enabled else "[dim]no[/dim]",
        )

    try:
        table = gr_check(table, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:f923931900195cd7d6e87b62d4d11b6783536a6bfc761dc1abadb2f1cfec7bfd')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        table = table
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(table)


def _read_trigger_cli_message(message: str | None) -> str:
    """Read a trigger message from an argument or stdin."""
    if message and message.strip():
        try:
            message = gr_check(message, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:fa5cf8363064b69c5d2e355248cf8c5c78de64a65b4565b4a9ff4fc87851c765')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            message = message
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return message
    try:
        if not sys.stdin.isatty():
            content = sys.stdin.read()
            if content.strip():
                try:
                    content = gr_check(content, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:fa5cf8363064b69c5d2e355248cf8c5c78de64a65b4565b4a9ff4fc87851c765')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    content = content
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                return content
    except Exception:
        pass
    _lineaje_payload = "[red]Error: trigger message is required[/red]"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2348c8ccf1fb1b2d7b30abecb1ef2fe92a2721384c29261815eadc08d73514e2')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print("[red]Error: trigger message is required[/red]")
    raise typer.Exit(1)


@app.command()
def trigger(
    trigger_id: str = typer.Argument(..., help="Trigger ID returned by /trigger"),
    message: str | None = typer.Argument(None, help="Message to deliver; stdin is used when omitted"),
    workspace: str | None = typer.Option(None, "--workspace", "-w", help="Workspace directory"),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """Deliver a local trigger message to its bound chat session."""
    from nanobot.triggers.local_store import (
        LocalTriggerStore,
        TriggerDisabledError,
        TriggerNotFoundError,
        TriggerStoreError,
    )

    runtime_config = _load_runtime_config(config, workspace)
    content = _read_trigger_cli_message(message)
    store = LocalTriggerStore(runtime_config.workspace_path)
    try:
        delivery = store.enqueue(trigger_id, content)
    except (TriggerNotFoundError, TriggerDisabledError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc
    except (TriggerStoreError, ValueError) as exc:
        _lineaje_payload = f"[red]Error: {exc}[/red]"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:5669acfcd16dfb89bab7b7c3273fa3559dde872c02efbbe13f3468f96e3ace56')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc
    _lineaje_payload = f"[green]Queued[/green] {delivery.trigger_id} ({delivery.id})"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:5669acfcd16dfb89bab7b7c3273fa3559dde872c02efbbe13f3468f96e3ace56')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"[green]Queued[/green] {delivery.trigger_id} ({delivery.id})")


# ============================================================================
# OpenAI-Compatible API Server
# ============================================================================


@app.command()
def serve(
    port: int | None = typer.Option(None, "--port", "-p", help="API server port"),
    host: str | None = typer.Option(None, "--host", "-H", help="Bind address"),
    timeout: float | None = typer.Option(None, "--timeout", "-t", help="Per-request timeout (seconds)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show nanobot runtime logs"),
    workspace: str | None = typer.Option(None, "--workspace", "-w", help="Workspace directory"),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """Start the OpenAI-compatible API server (/v1/chat/completions)."""
    try:
        from aiohttp import web  # noqa: F401
    except ImportError:
        _lineaje_payload = "[red]aiohttp is required. Install with: nanobot plugins enable api[/red]"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:3d89741d2c07dd009ef8b66444fb756a51cd2993e937aae4d96098ff7c978c39')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print("[red]aiohttp is required. Install with: nanobot plugins enable api[/red]")
        raise typer.Exit(1)

    from nanobot.api.server import create_app
    from nanobot.bus.queue import MessageBus
    from nanobot.providers.image_generation import image_gen_provider_configs
    from nanobot.session.manager import SessionManager

    _set_nanobot_logs(verbose)

    runtime_config = _load_runtime_config(config, workspace)
    api_cfg = runtime_config.api
    host = host if host is not None else api_cfg.host
    port = port if port is not None else api_cfg.port
    timeout = timeout if timeout is not None else api_cfg.timeout
    api_key = api_cfg.api_key.strip() if api_cfg.api_key else ""
    if not is_loopback_host(host) and not api_key:
        _lineaje_payload = (f"[red]Error: host {host} is available beyond this device but api_key is not set. "
            "Set api.api_key in config to prevent unauthenticated access.[/red]")
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:c415eb285661731042535e1e23e9f4e7dd7edfd528e8f28d58ccc0cfecfb94bc')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(
            f"[red]Error: host {host} is available beyond this device but api_key is not set. "
            "Set api.api_key in config to prevent unauthenticated access.[/red]"
        )
        raise typer.Exit(1)
    sync_workspace_templates(runtime_config.workspace_path)
    bus = MessageBus()
    session_manager = SessionManager(runtime_config.workspace_path)
    tools = ToolRegistry()
    mcp_provider = MCPProvider.from_config(runtime_config, tools)
    try:
        agent_loop = AgentLoop.from_config(
            runtime_config, bus,
            session_manager=session_manager,
            image_generation_provider_configs=image_gen_provider_configs(runtime_config),
            hook_factories=[create_file_edit_activity_hook],
            tool_registry=tools,
        )
    except ValueError as exc:
        _lineaje_payload = f"[red]Error: {exc}[/red]"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:6d5acfab2b4a3ca06f801679daa5eee00a0645e764ee336087844901647dbe35')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc

    model_name, preset_tag = _model_display(runtime_config)
    _lineaje_payload = f"{__logo__} Starting OpenAI-compatible API server"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:6d5acfab2b4a3ca06f801679daa5eee00a0645e764ee336087844901647dbe35')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"{__logo__} Starting OpenAI-compatible API server")
    _lineaje_payload = f"  [cyan]Endpoint[/cyan] : http://{host}:{port}/v1/chat/completions"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:6d5acfab2b4a3ca06f801679daa5eee00a0645e764ee336087844901647dbe35')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"  [cyan]Endpoint[/cyan] : http://{host}:{port}/v1/chat/completions")
    _lineaje_payload = f"  [cyan]Model[/cyan]    : {model_name}{preset_tag}"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:6d5acfab2b4a3ca06f801679daa5eee00a0645e764ee336087844901647dbe35')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"  [cyan]Model[/cyan]    : {model_name}{preset_tag}")
    _lineaje_payload = "  [cyan]Session[/cyan]  : api:default"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:6d5acfab2b4a3ca06f801679daa5eee00a0645e764ee336087844901647dbe35')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print("  [cyan]Session[/cyan]  : api:default")
    _lineaje_payload = f"  [cyan]Timeout[/cyan]  : {timeout}s"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:6d5acfab2b4a3ca06f801679daa5eee00a0645e764ee336087844901647dbe35')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"  [cyan]Timeout[/cyan]  : {timeout}s")
    if not is_loopback_host(host):
        _lineaje_payload = ("[yellow]API is available beyond this device "
            "(authentication required).[/yellow]")
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:c415eb285661731042535e1e23e9f4e7dd7edfd528e8f28d58ccc0cfecfb94bc')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(
            "[yellow]API is available beyond this device "
            "(authentication required).[/yellow]"
        )
    console.print()

    api_app = create_app(
        agent_loop, model_name=model_name, request_timeout=timeout,
        api_key=api_key,
        prepare_agent=mcp_provider.connect,
    )

    async def on_startup(_app: Any) -> None:
        await mcp_provider.connect()

    async def on_cleanup(_app: Any) -> None:
        try:
            await agent_loop.aclose()
        finally:
            await mcp_provider.aclose()

    api_app.on_startup.append(on_startup)
    api_app.on_cleanup.append(on_cleanup)

    def _log_aiohttp(message: object) -> None:
        try:
            message = gr_check(message, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:bc74d3eaa506845b5ffe1b23329980995dc2b5620538e4bc16251c38522f5961')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            message = message
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info("{}", message)

    web.run_app(api_app, host=host, port=port, print=_log_aiohttp)


# ============================================================================
# WebUI Launcher
# ============================================================================

app.command(name="webui")(webui)


# ============================================================================
# Gateway / Server
# ============================================================================


app.add_typer(
    create_gateway_app(
        console=console,
        log_handler_id=_log_handler_id,
        load_runtime_config=_load_runtime_config,
        run_gateway=_run_gateway,
        validate_startup_config=_validate_gateway_startup,
        prepare_webui_bundle=lambda config, mode: _prepare_webui_bundle_for_gateway(
            config,
            mode=mode,
        ),
    ),
    name="gateway",
)


# ============================================================================
# Agent Commands
# ============================================================================


app.command(name="agent")(agent)


# ============================================================================
# Session Commands
# ============================================================================


sessions_app = typer.Typer(help="Manage persisted session history")
app.add_typer(sessions_app, name="sessions")


@sessions_app.command("restore-workspace")
def sessions_restore_workspace(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
    workspace: str | None = typer.Option(None, "--workspace", "-w", help="Workspace directory"),
) -> None:
    """Copy sessions back into the workspace before downgrading nanobot."""
    from nanobot.session.manager import SessionManager

    runtime_config = _load_runtime_config(config, workspace)
    data_dir = runtime_config.runtime_data_dir
    manager = SessionManager(
        runtime_config.workspace_path,
        sessions_root=data_dir / "sessions" if data_dir is not None else None,
    )
    result = manager.restore_sessions_to_workspace()
    _lineaje_payload = (f"Restored {result.restored} session file(s) to "
        f"{escape(str(runtime_config.workspace_path / 'sessions'))}; "
        f"{result.unchanged} already matched.")
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:796943403a398efabd8dd7746fd7f1178b5c7ea4f3f2e493dca1db99472d94c4')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(
        f"Restored {result.restored} session file(s) to "
        f"{escape(str(runtime_config.workspace_path / 'sessions'))}; "
        f"{result.unchanged} already matched."
    )
    if result.conflicts:
        _lineaje_payload = "[red]Rollback is incomplete: existing or invalid files require manual review.[/red]"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:796943403a398efabd8dd7746fd7f1178b5c7ea4f3f2e493dca1db99472d94c4')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(
            "[red]Rollback is incomplete: existing or invalid files require manual review.[/red]"
        )
        for path in result.conflicts:
            _lineaje_payload = Text(f"- {path}", style="red")
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:796943403a398efabd8dd7746fd7f1178b5c7ea4f3f2e493dca1db99472d94c4')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            console.print(Text(f"- {path}", style="red"))
        raise typer.Exit(1)


# ============================================================================
# Channel Commands
# ============================================================================


channels_app = typer.Typer(help="Manage channels")
app.add_typer(channels_app, name="channels")


@channels_app.command("status")
def channels_status(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """Show channel status."""
    from nanobot.channels.registry import discover_all

    _, loaded = _load_inspection_config(config=config)

    table = Table(title="Channel Status")
    table.add_column("Channel", style="cyan")
    table.add_column("Enabled")

    for name, cls in sorted(discover_all().items()):
        section = getattr(loaded.channels, name, None)
        if section is None:
            enabled = False
        elif isinstance(section, dict):
            enabled = cast(dict[str, Any], section).get("enabled", False)
        else:
            enabled = getattr(section, "enabled", False)
        table.add_row(
            cls.display_name,
            "[green]\u2713[/green]" if enabled else "[dim]\u2717[/dim]",
        )

    try:
        table = gr_check(table, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:0580669aa45edcc10f4f0f2e256765573e8f451a457a4430be7380504eb22eb6')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        table = table
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(table)


@channels_app.command("login")
def channels_login(
    channel_name: str = typer.Argument(..., help="Channel name (e.g. weixin, whatsapp)"),
    force: bool = typer.Option(False, "--force", "-f", help="Force re-authentication even if already logged in"),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """Authenticate with a channel via QR code or other interactive login."""
    from nanobot.bus.queue import MessageBus
    from nanobot.channels.registry import discover_all

    _, loaded = _load_inspection_config(config=config)
    channel_cfg: Any = getattr(loaded.channels, channel_name, None) or {}

    # Validate channel exists
    all_channels = discover_all()
    if channel_name not in all_channels:
        available = ", ".join(all_channels.keys())
        _lineaje_payload = f"[red]Unknown channel: {channel_name}[/red]  Available: {available}"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:44ad999ecd21cc42e76ff68ee20e5ec80ee7e77e74134c44677cd6b95fe1443b')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"[red]Unknown channel: {channel_name}[/red]  Available: {available}")
        raise typer.Exit(1)

    _lineaje_payload = f"{__logo__} {all_channels[channel_name].display_name} Login\n"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:44ad999ecd21cc42e76ff68ee20e5ec80ee7e77e74134c44677cd6b95fe1443b')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"{__logo__} {all_channels[channel_name].display_name} Login\n")

    channel_factory = all_channels[channel_name]
    channel = channel_factory(channel_cfg, bus=MessageBus())

    success = asyncio.run(channel.login(force=force))

    if not success:
        raise typer.Exit(1)


# ============================================================================
# Plugin Commands
# ============================================================================

plugins_app = typer.Typer(help="Manage optional nanobot features")
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def plugins_list(
    config_path: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """List optional nanobot features."""
    from nanobot.channels.registry import discover_plugins
    from nanobot.config.loader import load_config, set_config_path

    resolved_config_path = Path(config_path).expanduser().resolve() if config_path else None
    if resolved_config_path is not None:
        set_config_path(resolved_config_path)

    _print_enable_options(
        feature_support.optional_dependency_groups(),
        discover_plugins(),
        load_config(resolved_config_path),
    )


@plugins_app.command("enable")
def plugins_enable(
    name: str = typer.Argument(..., help="Feature name (e.g. weixin, matrix, bedrock)"),
    config_path: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
    logs: bool = typer.Option(False, "--logs/--no-logs", help="Show optional package install logs"),
):
    """Enable a nanobot feature."""
    from nanobot.config.loader import get_config_path, set_config_path

    resolved_config_path = Path(config_path).expanduser().resolve() if config_path else None
    if resolved_config_path is not None:
        set_config_path(resolved_config_path)
    resolved_config_path = resolved_config_path or get_config_path()
    _set_nanobot_logs(logs)

    try:
        payload = feature_support.enable_optional_feature(
            name,
            config_path=resolved_config_path,
            runner=feature_support.run_install_command,
        )
    except feature_support.OptionalFeatureError as exc:
        _lineaje_payload = f"[red]{escape(exc.message)}[/red]"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:a6cd19986c2f20481a0a19d1f67b51422988d3df19b0de2285b7d1335256652c')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"[red]{escape(exc.message)}[/red]")
        raise typer.Exit(1) from exc

    message = payload.get("last_action", {}).get("message") or f"Enabled feature '{name}'"
    _lineaje_payload = f"[green]{escape(message)}[/green]"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:a6cd19986c2f20481a0a19d1f67b51422988d3df19b0de2285b7d1335256652c')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"[green]{escape(message)}[/green]")


@plugins_app.command("disable")
def plugins_disable(
    name: str = typer.Argument(..., help="Channel name (e.g. telegram, matrix, slack)"),
    config_path: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """Disable a nanobot channel feature."""
    from nanobot.config.loader import get_config_path, set_config_path

    resolved_config_path = Path(config_path).expanduser().resolve() if config_path else None
    if resolved_config_path is not None:
        set_config_path(resolved_config_path)
    resolved_config_path = resolved_config_path or get_config_path()

    try:
        payload = feature_support.disable_optional_feature(name, config_path=resolved_config_path)
    except feature_support.OptionalFeatureError as exc:
        _lineaje_payload = f"[red]{escape(exc.message)}[/red]"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:65920e323f697f2e333a382fcc29988ef18dee63c938b0d6e0919523067e9dd3')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"[red]{escape(exc.message)}[/red]")
        raise typer.Exit(1) from exc

    message = payload.get("last_action", {}).get("message") or f"Disabled channel '{name}'"
    _lineaje_payload = f"[green]{escape(message)}[/green] in {resolved_config_path}"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:65920e323f697f2e333a382fcc29988ef18dee63c938b0d6e0919523067e9dd3')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"[green]{escape(message)}[/green] in {resolved_config_path}")


# ============================================================================
# Status Commands
# ============================================================================


@app.command()
def status(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
    workspace: str | None = typer.Option(None, "--workspace", "-w", help="Workspace directory"),
):
    """Show nanobot status."""
    config_path, loaded = _load_inspection_config(config=config, workspace=workspace)
    workspace_path = loaded.workspace_path

    _lineaje_payload = f"{__logo__} nanobot Status\n"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2f2fe37a84c483724b48a6fb4cc21719319a9b2bc39ad629e3cc30833e6ac63a')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(f"{__logo__} nanobot Status\n")

    console.print(f"Config: {config_path} {'[green]✓[/green]' if config_path.exists() else '[red]✗[/red]'}")
    _lineaje_payload = (f"Workspace: {workspace_path} "
        f"{'[green]✓[/green]' if workspace_path.exists() else '[red]✗[/red]'}")
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2f2fe37a84c483724b48a6fb4cc21719319a9b2bc39ad629e3cc30833e6ac63a')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(
        f"Workspace: {workspace_path} "
        f"{'[green]✓[/green]' if workspace_path.exists() else '[red]✗[/red]'}"
    )

    if config_path.exists():
        from nanobot.config.errors import ConfigLoadError
        from nanobot.config.loader import resolve_config_env_vars, resolve_env_refs
        from nanobot.providers.registry import PROVIDERS

        _model, _preset_tag = _model_display(loaded)
        _lineaje_payload = f"Model: {_model}{_preset_tag}"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2f2fe37a84c483724b48a6fb4cc21719319a9b2bc39ad629e3cc30833e6ac63a')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"Model: {_model}{_preset_tag}")

        provider_ready = False
        try:
            resolved = resolve_config_env_vars(
                loaded.model_copy(deep=True),
                config_path=config_path,
            )
        except ConfigLoadError as exc:
            console.print("Agent: [red]✗ configuration is not ready[/red]")
            _print_config_error(exc)
        else:
            provider_error = _provider_setup_error(resolved)
            if provider_error:
                console.print(Text(f"Agent: ✗ {provider_error}", style="red"))
                _lineaje_payload = "Complete provider/model setup:"
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:f4602b88485eaa8e76b59c5b0adeab0b386d3837488dc4670f8b5908674cc854')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                console.print("Complete provider/model setup:")
                _print_model_setup_steps(config_path)
            else:
                provider_ready = True
                console.print("Agent: [green]✓ provider/model configuration is ready[/green]")

        # Check API keys from registry
        for spec in PROVIDERS:
            p = getattr(loaded.providers, spec.name, None)
            if p is None:
                continue
            if spec.is_oauth:
                console.print(f"{spec.label}: [green]✓ (OAuth)[/green]")
            elif spec.is_local:
                # Local deployments show api_base instead of api_key
                if resolve_env_refs(p.api_base or ""):
                    console.print(f"{spec.label}: [green]✓ {p.api_base}[/green]")
                else:
                    _lineaje_payload = f"{spec.label}: [dim]not set[/dim]"
                    try:
                        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2aa0ea4b37b27eb5411bbcb5b3b723daabd83d49b41978a3d25a6ded16cfbff6')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        _lineaje_payload = _lineaje_payload
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                    console.print(f"{spec.label}: [dim]not set[/dim]")
            else:
                has_key = bool(resolve_env_refs(p.api_key or ""))
                console.print(f"{spec.label}: {'[green]✓[/green]' if has_key else '[dim]not set[/dim]'}")

        if provider_ready:
            console.print()
            _lineaje_payload = 'Next: [cyan]nanobot agent -m "Hello!"[/cyan]'
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2aa0ea4b37b27eb5411bbcb5b3b723daabd83d49b41978a3d25a6ded16cfbff6')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            console.print('Next: [cyan]nanobot agent -m "Hello!"[/cyan]')
            _lineaje_payload = "[dim]Status does not call the model or verify network access and credentials.[/dim]"
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2aa0ea4b37b27eb5411bbcb5b3b723daabd83d49b41978a3d25a6ded16cfbff6')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            console.print(
                "[dim]Status does not call the model or verify network access and credentials.[/dim]"
            )
    else:
        console.print("Agent: [red]✗ configuration file not found[/red]")
        _lineaje_payload = "Create the provider/model configuration:"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2aa0ea4b37b27eb5411bbcb5b3b723daabd83d49b41978a3d25a6ded16cfbff6')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print("Create the provider/model configuration:")
        _print_model_setup_steps(config_path)


# ============================================================================
# OAuth Login
# ============================================================================

app.add_typer(provider_app, name="provider")


if __name__ == "__main__":
    app()
