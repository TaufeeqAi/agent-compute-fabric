"""acf-api: the interface plane of Agent Compute Fabric.

Two roles in one deployable. An *edge* process parses what callers send and holds nothing. The *core*
process verifies who is asking, decides what they may ask for, and is the platform's only voice to the
execution plane. The two meet at the command interface (:mod:`acf_api.command`) and nowhere else.
"""

__version__ = "0.3.0"
