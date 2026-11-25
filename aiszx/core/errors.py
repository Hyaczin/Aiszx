"""Expected, user-facing error types.

Anything derived from :class:`AiszxError` is reported to the user as a clean
message with a specific exit code. Any other exception is a bug and is shown
with a traceback.
"""


class AiszxError(Exception):
    """Base class for expected errors."""

    exit_code = 1


class ConfigError(AiszxError):
    """Invalid or unreadable configuration."""

    exit_code = 2


class ValidationError(AiszxError):
    """Invalid user input (target, scope value, option)."""

    exit_code = 2


class ScopeError(AiszxError):
    """An operation was refused because it falls outside authorised scope."""

    exit_code = 3


class NotFoundError(AiszxError):
    """A referenced engagement, target or rule does not exist."""

    exit_code = 4


class DatabaseError(AiszxError):
    """Database missing, outdated, newer than the code, or a migration failed."""

    exit_code = 5


class WorkspaceError(AiszxError):
    """Filesystem workspace problem."""

    exit_code = 6
