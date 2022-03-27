"""Provide aliases for typing."""
from typing import Dict, Union

#: map from process attribute names (e.g. pid, path) to attribute values
ProcessInfo = Dict[str, Union[int, str]]
