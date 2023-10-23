"""
    Unqork Security - Threat Detection and Response - PySigma DictQuery Backend
"""
from .dictquery import DictQueryBackend

backends = {  # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "dictquery": DictQueryBackend,
}
