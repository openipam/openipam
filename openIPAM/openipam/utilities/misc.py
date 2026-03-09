import re
import datetime


def fix_timedelta(datum):
    if isinstance(datum, datetime.timedelta):
        datum = str(datum)

    return datum


def fix_checkbox(form, key):
    if key not in form:
        return False
    else:
        return True


def fix_mac(mac):
    return mac.replace(":", "").replace("-", "")


def fix_cidr_network(network):
    return network.replace("/", "--").replace(".", "-")


def unfix_cidr_network(network):
    return network.replace("--", "/").replace("-", ".")


def make_time_delta(s):
    """Create timedelta object representing time delta
       expressed in a string

    Takes a string in the format produced by calling str() on
    a python timedelta object and returns a timedelta instance
    that would produce that string.

    Acceptable formats are: "X days, HH:MM:SS" or "HH:MM:SS".

    @author: Kelly Yancey http://kbyanc.blogspot.com
    """
    if s is None:
        return None
    d = re.match(
        r"((?P<days>\d+) days?, )?(?P<hours>\d+):" r"(?P<minutes>\d+):(?P<seconds>\d+)",
        str(s),
    ).groupdict(0)
    return datetime.timedelta(
        **{key: int(value) for key, value in list(d.items())}
    )
