import functools
import json

# project imports
from . import utils

# whitelisted files
WHITE_LISTED_FILES = "whitelists/whitelistedFiles.json"

# whitelisted commands
WHITE_LISTED_COMMANDS = "whitelists/whitelistedCommands.json"

# whitelisted browser extensions
WHITE_LISTED_EXTENSIONS = "whitelists/whitelistedExtensions.json"


@functools.lru_cache
def get_file_whitelist():
    """Return whitelisted files/"""
    return json.loads(
        (utils.get_kk_directory() / WHITE_LISTED_FILES).read_text(encoding="utf-8")
    )


@functools.lru_cache
def get_command_whitelist():
    """Return whitelisted commands."""
    return json.loads(
        (utils.get_kk_directory() / WHITE_LISTED_COMMANDS).read_text(encoding="utf-8")
    )["commands"]


@functools.lru_cache
def get_extension_whitelist():
    """Return whitelisted extensions."""
    return json.loads(
        (utils.get_kk_directory() / WHITE_LISTED_EXTENSIONS).read_text(encoding="utf-8")
    )
