__author__ = "patrick"

import json

from . import whitelist


class Extension:
    """Extension."""

    def __init__(self, extension_info):
        """Init method.

        ->init instance variables, hash file, etc
        """
        # init name w/ None
        self.name = None

        # init path w/ None
        self.path = None

        # init description w/ None
        self.description = None

        # init id w/ None
        self.extension_id = None

        # extract/save id
        if "id" in extension_info:

            # save
            self.extension_id = extension_info["id"]

        # extract/save name
        if "name" in extension_info:

            # save
            self.name = extension_info["name"]

        # extract/save path
        if "path" in extension_info:

            # save
            self.path = extension_info["path"]

        # extract/save description
        if "description" in extension_info:

            # save
            self.description = extension_info["description"]

        # init whitelist flag
        whitelisted_search = (
            self.extension_id if self.extension_id is not None else self.path
        )
        self.is_whitelisted = whitelisted_search in whitelist.get_extension_whitelist()

    def hash(self):
        """Return hash."""
        # hash
        return self.extension_id

    # for normal output
    def pretty_print(self):
        """Normal output."""
        return f"""
{self.name}
 description: {self.description}
 id: {self.extension_id}
 path: {self.path}
"""

    def __repr__(self):
        """JSON output."""
        # return obj as JSON string
        return json.dumps(self.__dict__, indent=4)
