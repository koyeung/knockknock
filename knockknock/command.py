__author__ = "patrick"

import json

from . import whitelist


class Command:
    """Command."""

    def __init__(self, command, file=None):
        """Init method.

        ->save command and set white list flag
        """
        # save command
        self.command = command

        # save file
        self.file = file

        # init whitelist flag
        # ->simply set to True if command is list of whitelisted commands
        self.is_whitelisted = self.command in whitelist.get_command_whitelist()

    # for json output
    def __repr__(self):

        # return obj as JSON string
        return json.dumps(self.__dict__, indent=4)

    def pretty_print(self) -> str:
        """Normal output."""
        # when cmd has file
        if self.file:

            # init
            return f"""
{self.command}
 file: {self.file}
"""

        # no file

        return f"""
{self.command}
"""
