class Pylera1nException(Exception):
    pass


class MissingProductVersionError(Pylera1nException):
    pass


class SshError(Pylera1nException):
    pass


class ProcessExecutionFailedError(SshError):
    pass


class MissingActivePrebootError(SshError):
    pass


class MountError(SshError):
    pass


class DirectoryNotEmptyError(SshError):
    pass
