#!/usr/bin/env python

from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import argparse
import os
import shutil
import subprocess
import sys

REQUIREMENTS = ('git', 'curl')
GITHUB = "http://github.com/Datera/cinder-driver"
HOME = os.path.expanduser("~")
REPO = "{}/cinder-driver".format(HOME)
LOC = "/usr/lib/python2.7/dist-packages/cinder/volume/drivers/"
LOCD = "/opt/stack/cinder/cinder/volume/drivers/"
ETC = "/etc/cinder/cinder.conf"

ETC_TEMPLATE = """
[datera]
volume_driver = cinder.volume.drivers.datera.datera_iscsi.DateraDriver
san_is_local = True
san_ip = {ip}
san_login = {login}
san_password = {password}
volume_backend_name = datera
datera_debug = True
"""

verbose = False


def vprint(*args, **kwargs):
    global verbose
    if verbose:
        print(*args, **kwargs)


def check_requirements():
    vprint("Checking Requirements")
    for binary in REQUIREMENTS:
        try:
            subprocess.check_call(['which', binary])
        except subprocess.CalledProcessError:
            print("Missing requirement:", binary)
            print("Please install and retry script")


def exe(cmd):
    vprint("Running cmd:", cmd)
    return subprocess.check_output(cmd, shell=True)


def main(args):
    check_requirements()

    # Get repository and checkout version
    if not args.cinder_driver:
        repo = REPO
        exe("cd {} && git clone {}".format(HOME, GITHUB))
    else:
        repo = args.cinder_driver
    version = args.d_version
    exe("cd {} && git checkout {}".format(repo, version))

    # Copy files to install location
    loc = LOC
    if args.devstack:
        loc = LOCD
    exe("cp -r {}/src/datera/ {}".format(repo, loc))

    # Modify etc file
    data = None
    with open(ETC, 'r') as f:
        data = f.readlines()
    insert = 0
    for index, line in enumerate(data):
        if any((elem in line for elem in
                ("enabled_backends", "verbose", "debug"))):
            del data[index]
        elif "DEFAULT" in line:
            insert = index
    data.insert(insert + 1, "enabled_backends = datera")
    data.insert(insert + 1, "verbose = True")
    data.insert(insert + 1, "debug = True")
    tdata = ETC_TEMPLATE.format(
        ip=args.ip,
        login=args.username,
        password=args.password)
    data.extend(tdata.splitlines())

    shutil.copyfile(ETC, ETC + ".bak")
    with open(ETC, 'w') as f:
        for line in data:
            line = line.strip()
            f.write(line)
            f.write("\n")

    # Restart cinder-volume service
    if args.devstack:
        print("Restart the cinder-volume service to complete installation")
    else:
        vprint("Restarting the cinder-volume service")
        exe("service cinder-volume restart")
        print("Ready to go")
    sys.exit(0)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('ip', help="Datera Mgmt IP")
    parser.add_argument('username', help="Datera account username")
    parser.add_argument('password', help="Datera account password")
    parser.add_argument('d_version', default="master",
                        help="Driver Version. Eg: 'newton-v2.3.2'")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Print verbose output")
    parser.add_argument('-d', '--devstack', action='store_true',
                        help="Use devstack install locations")
    parser.add_argument('-c', '--cinder-driver',
                        help="Cinder driver folder location (for custom "
                             "install)")

    args = parser.parse_args()
    verbose = args.verbose
    sys.exit(main(args))
