"""
Custom exception classes

Unless something needs to be overwritten, these just inherit the BaseException class
"""


class BaseException(Exception):
    def __init__(self, thing=""):
        self._thing = thing

    def __str__(self):
        return "({}){}".format(
            self.__class__.__name__,
            (self._thing and (" %s" % str(self._thing)) or "",)[0],
        )

    def __repr__(self):
        return str(self)


class NotUser(BaseException):
    """Raised when a user is not recognized by an auth source"""

    pass


class NotFound(BaseException):
    """Raised for things that are not found"""

    pass


class RequiredArgument(BaseException):
    """Raised when a needed argument hasn't been passed"""

    pass


class InvalidArgument(BaseException):
    """Raised when a needed argument is invalid"""

    pass


class NotImplemented(BaseException):
    """Raised when needed for things that haven't been implemented"""

    pass


class FatalException(BaseException):
    """Raised in places that should never be reached"""

    pass


class NoFreeAddresses(BaseException):
    """Raised when no addresses are available to hand out from a network"""

    pass


class InsufficientPermissions(BaseException):
    """Raised when a user has insufficient permissions to do what they were asking"""

    pass


class NotUnique(BaseException):
    """Raised where only one thing should have been returned"""

    pass


class InsertFailed(BaseException):
    """Raised when an INSERT fails"""

    pass


class UpdateFailed(BaseException):
    """Raised when an UPDATE fails"""

    pass


class DeleteFailed(BaseException):
    """Raised when a DELETE fails"""

    pass


class AlreadyExists(BaseException):
    """Raised when we're adding something that already exists"""

    def __init__(self, *args, **kw):
        if "mac" in kw:
            self.mac = kw["mac"]
            del kw["mac"]
        if "hostname" in kw:
            self.host = kw["hostname"]
            del kw["hostname"]
        BaseException.__init__(self, *args, **kw)


class InvalidMACAddress(BaseException):
    """Raised for an invalid MAC addresses"""

    pass


class InvalidIPAddress(BaseException):
    """Raised for an invalid MAC addresses"""

    pass


class InvalidCIDRNetwork(BaseException):
    """Raised for an invalid CIDR network description"""

    pass
