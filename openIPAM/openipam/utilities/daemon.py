import os
import sys
import atexit
import errno


# FIXME: this should go somewhere else!
def sighand_hup(signum, frame):
    print("Received SIGHUP.")
    print("(This is where we should reload.)")


def findpid(pidfile):
    f = open(pidfile)
    p = f.read()
    f.close()
    return int(p)


def update_pidfile(pidfile):

    if pidfile:
        print('Using pidfile "%s"' % pidfile)
        if os.path.exists(pidfile):
            p = findpid(pidfile)
            print("Found pidfile with PID %s" % p)
            try:
                os.kill(p, 0)
            except OSError as detail:
                if detail.errno == errno.ESRCH:
                    print("stale pidfile exists.  removing it.")
                    os.unlink(pidfile)
            else:
                print("valid PID file exists, exiting")
                exit(2)
        atexit.register(os.unlink, pidfile)
        f = open(pidfile, "w")
        f.write("%d" % os.getpid())
        f.close()


def daemonize(fcn, pidfile=None):
    UMASK = 0o7137
    WORKDIR = "/"
    MAXFD = 1024

    if hasattr(os, "devnull"):
        # OS concept of null device
        REDIRECT = os.devnull
    else:
        # if the OS won't tell anything, assume unix-like
        REDIRECT = "/dev/null"

    try:
        # first fork
        pid = os.fork()
    except OSError as e:
        raise Exception("%s [%d]" % (e.strerror, e.errno))

    if pid == 0:

        # I am the child process
        os.chdir(WORKDIR)
        os.umask(UMASK)
        os.setsid()

        try:
            # second fork...welcome to daemon space
            pid = os.fork()
        except OSError as e:
            raise Exception("%s [%d]" % (e.strerror, e.errno))

        if pid == 0:
            # Redirect standard file descriptors.
            si = open("/dev/null")
            so = open("/dev/null", "a+b")
            se = open("/dev/null", "a+b", 0)
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())

            # Become the group leader
            os.setpgrp()

            update_pidfile(pidfile)
            # Call the passed in function (ie. start the daemon)
            fcn()
        else:
            os._exit(0)
    else:
        # I am the parent process

        os._exit(0)

        # FIXME: why do we do this?
        # close all open file descriptors
    import resource

    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if maxfd == resource.RLIM_INFINITY:
        maxfd = MAXFD
    for fd in range(0, maxfd):
        try:
            os.close(fd)
        except OSError:
            # fd wasn't actually open
            pass

            # attach file descriptors 1 and 2 to something useful
    os.open(REDIRECT, os.O_RDWR)
    os.dup(0, 1)
    os.dup(0, 2)

    return 0
