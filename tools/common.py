from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import subprocess

VERBOSE = False
SUCCESS = "Success"
FAILURE = "FAIL --"


# Fail Func
def ff(reasons):
    if type(reasons) not in (list, tuple):
        return " ".join((FAILURE, reasons))
    return " ".join((FAILURE, " ".join(reasons)))


def vprint(*args, **kwargs):
    global VERBOSE
    if VERBOSE:
        print(*args, **kwargs)


def exe(cmd):
    vprint("Running cmd:", cmd)
    return subprocess.check_output(cmd, shell=True)


def exe_check(cmd, err=False):
    try:
        exe(cmd)
        if err:
            return False
        return True
    except subprocess.CalledProcessError:
        if not err:
            return False
        return True
