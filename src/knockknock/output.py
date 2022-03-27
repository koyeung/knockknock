import json

from . import command, extension, file


class JSONEncoder(json.JSONEncoder):
    """JSON encoder."""

    # automatically invoked
    # ->allows custom JSON encoding
    def default(self, o):

        # for file and command objects
        # ->return the objects dictionary
        if isinstance(o, (file.File, command.Command, extension.Extension)):

            # object dictionary
            return o.__dict__

        # other objects
        # ->just super

        # super
        return super().default(o)


def format_results(results, as_json: bool) -> str:
    """Format the result.

    ->either just pretty for stdout or as JSON
    """
    # results; formatted
    formatted_results = ""

    # cumulative count of all startup objects
    startup_obj_count = 0

    # format as JSON
    # ->uses the jsonDecoder class (above) to dump the objects dictionary
    if as_json:

        # will generate JSON
        formatted_results = json.dumps(results, cls=JSONEncoder, indent=4)

    # pretty print the output for stdout
    else:

        # dbg msg
        formatted_results += "WHO'S THERE:\n"

        # iterate over all results
        for result in _sort_results(results):

            # add header (name)
            if result["items"]:

                # format name/type of startup item
                formatted_results += "\n[" + result["name"] + "]\n"

            # iterate over each startup object
            for startup_obj in _sort_startup_objs(result["items"]):

                # inc count
                startup_obj_count += 1

                # format object
                # ->files and commands both implement pretty_print()
                formatted_results += startup_obj.pretty_print()

        # none found?
        if not startup_obj_count:

            # nothing found
            formatted_results += "-> nobody :)\n"

        # add info about totals
        else:

            # add total
            formatted_results += f"\nTOTAL ITEMS FOUND: {startup_obj_count}\n"

    return formatted_results


def _sort_results(results):
    return sorted(results, key=lambda x: x["name"])


def _sort_startup_objs(startup_objs):
    return sorted(startup_objs, key=lambda x: x.name)
