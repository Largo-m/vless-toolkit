"""Exceptions raised by :mod:`vless_toolkit`."""


class LinkError(ValueError):
    """Base class for errors caused by an invalid proxy share link."""


class LinkParseError(LinkError):
    """Raised when a share link cannot be parsed or uses an unsupported scheme."""


class LinkValidationError(LinkError):
    """Raised when parsed or hand-built link data is not valid."""
