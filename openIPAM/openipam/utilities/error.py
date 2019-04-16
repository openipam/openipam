"""
Custom exception classes

Unless something needs to be overwritten, these just inherit the BaseException class
"""

import types
import cgi


def parse_webservice_fault(fault):
    """
	Take a fault object and return the string within brackets, like:
	given  <Fault 1: "[InvalidCredentials]">
	returns "InvalidCredentials"
	
	@return: the string within brackets of a fault object
	"""

    if not hasattr(fault, "faultString"):
        return ""

    string = fault.faultString

    if string.find("(") == -1:
        # fault.faultString = "Error from backend was raised, but could not be parsed. Error: %s" % fault.faultString
        raise fault

    return string[string.find("(") + 1 : string.find(")")]


def get_nice_error(e):
    """
	Takes an error exception and returns a message ul of the errors listed.
	Used mostly for post-form submission errors.
	"""

    text = []

    if type(e.message) is list:
        text.append(
            "<strong>The following error%s occurred:</strong><ul>"
            % ((len(e.message) > 1) and "s" or "",)[0]
        )
        for msg in e.message:
            text.append("<li>%s</li>" % msg)
        text.append("</ul>")
    else:
        raise e
        # TODO: make this put a generic error not a fault trace thing
        text.append(cgi.escape(str(e)))

    return "".join(text)


class BaseException(Exception):
    def __init__(self, thing=""):
        self._thing = thing

    def __str__(self):
        return "(%s)%s" % (
            self.__class__.__name__,
            (self._thing and (" %s" % str(self._thing)) or "",)[0],
        )

    def __repr__(self):
        return str(self)


class ListXMLRPCFault(BaseException):
    """An error type that makes a semi-colon delimited string from a list ... because
	CherryPy stupidly stringifys it anyway so we might as well have a good separator
	on which to split"""

    def __str__(self):
        if type(self._thing) is bytes:
            return BaseException.__str__(self)

        self._thing = ";".join(self._thing)
        return BaseException.__str__(self)


class LibraryError(BaseException):
    """Raised for bad package versions or other library errors"""

    pass


class NotUser(BaseException):
    """Raised when a user is not recognized by an auth source"""

    pass


class InvalidCredentials(BaseException):
    """Raised for bad usernames and/or passwords"""

    pass


class NoEmail(BaseException):
    """Raised for LDAP users who don't return an email address after binding"""

    pass


class NotFound(BaseException):
    """Raised for things that are not found"""

    pass


class SessionExpired(BaseException):
    """Raised when the users session has expired or been expired"""

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


class InvalidTicket(BaseException):
    """Raised when a user tries to use an invalid ticket"""

    pass


class AlreadyExists(BaseException):
    """Raised when we're adding something that already exists (logically, not SQLAlchemy)"""

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
