"""GitDumper exposed .git repository extraction adapter."""
from tradecraft.adapters.gitdumper.execute import (
    RawGitDumperResult,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.gitdumper.parse import (
    host_port_from_target,
    parse_gitdumper_output,
)

__all__ = [
    "RawGitDumperResult",
    "build_argv",
    "execute",
    "host_port_from_target",
    "normalize_target_url",
    "parse_gitdumper_output",
]
