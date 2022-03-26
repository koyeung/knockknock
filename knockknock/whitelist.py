import functools
import json

from . import utils

_WHITELISTS_DIR = "whitelists"

# whitelisted files
_WHITE_LISTED_FILES = "whitelistedFiles.json"

# whitelisted commands
_WHITE_LISTED_COMMANDS = "whitelistedCommands.json"

# whitelisted browser extensions
_WHITE_LISTED_EXTENSIONS = "whitelistedExtensions.json"


@functools.lru_cache
def get_file_whitelist():
    """Return whitelisted files/"""
    return json.loads(
        (utils.get_kk_directory() / _WHITELISTS_DIR / _WHITE_LISTED_FILES).read_text(
            encoding="utf-8"
        )
    )


@functools.lru_cache
def get_command_whitelist():
    """Return whitelisted commands."""
    return json.loads(
        (utils.get_kk_directory() / _WHITELISTS_DIR / _WHITE_LISTED_COMMANDS).read_text(
            encoding="utf-8"
        )
    )["commands"]


@functools.lru_cache
def get_extension_whitelist():
    """Return whitelisted extensions."""
    return json.loads(
        (
            utils.get_kk_directory() / _WHITELISTS_DIR / _WHITE_LISTED_EXTENSIONS
        ).read_text(encoding="utf-8")
    )
