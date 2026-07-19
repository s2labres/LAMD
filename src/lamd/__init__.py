"""LAMD: context-driven Android malware analysis with language models."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lamd")
except PackageNotFoundError:  # Running from an unpacked source tree.
    __version__ = "0.1.0"

__all__ = ["__version__"]
