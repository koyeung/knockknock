from yapsy.IPlugin import IPlugin


class KnockKnockPlugin(IPlugin):
    """KnockKnock plugin base class."""

    @staticmethod
    def init_results(name, description):
        """Init results dictionary.

        ->item name, description, and list
        """
        # results dictionary
        return {"name": name, "description": description, "items": []}
