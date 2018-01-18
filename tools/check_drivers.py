#!/usr/bin/env python

from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import argparse
import io
import os
import shutil
import subprocess
import sys
import uuid

import common
from common import vprint, exe, exe_check

REQUIREMENTS = ('git', 'curl')
GITHUB = "http://github.com/Datera/cinder-driver"
HOME = os.path.expanduser("~")
REPO = "{}/cinder-driver".format(HOME)
ETC = "/etc/cinder/cinder.conf"
PACKAGE_INSTALL = "/usr/lib/python2.7/dist-packages/cinder"
SITE_PACKAGE_INSTALL = "/usr/lib/python2.7/site-packages/cinder"
DEVSTACK_INSTALL = "/opt/stack/cinder/cinder"

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

SUCCESS = 0
FAILURE = 1


def check_requirements():
    vprint("Checking Requirements")
    for binary in REQUIREMENTS:
        if not exe_check("which {}".format(binary), err=False):
            print("Missing requirement:", binary)
            print("Please install and retry script")


def detect_cinder_install():
    if os.path.isdir(PACKAGE_INSTALL):
        return PACKAGE_INSTALL
    elif os.path.isdir(DEVSTACK_INSTALL):
        return DEVSTACK_INSTALL
    elif os.path.isdir(SITE_PACKAGE_INSTALL):
        return SITE_PACKAGE_INSTALL
    else:
        result = None
        try:
            vprint("Normal cinder install not found, searching for driver")
            result = exe("sudo find / -name datera_iscsi.py")
            if not result or result.isspace():
                raise ValueError()
            return result.strip().replace(
                "/volume/drivers/datera/datera_iscsi.py", "")
        except (subprocess.CalledProcessError, ValueError):
            raise EnvironmentError(
                "Cinder installation not found. Usual locations: [{}, {}]"
                "".format(PACKAGE_INSTALL, DEVSTACK_INSTALL))


def detect_service_restart_cmd(service, display=False):

    def is_journalctl():
        try:
            exe("journalctl --unit {} | grep 'No entries'")
            return False
        except subprocess.CalledProcessError:
            return True

    def screen_name(service):
        first = service[0]
        pos = service.find("-")
        return "-".join((first, service[pos+1:pos+4]))

    result = exe(
        "sudo service --status-all 2>&1 | awk '{{print $4}}' | grep {} || true"
        "".format(service))
    if service in result:
        return "sudo service {} restart".format(result.strip())
    result = exe("sudo systemctl --all 2>&1 | awk '{{print $1}}' | grep {} || "
                 "true".format(service))
    if service in result:
        return "sudo service {} restart".format(
            result.replace(".service", "").strip())
    sn = screen_name(service)
    result = exe(
        "screen -Q windows | grep {}".format(sn))
    if sn in result:
        if display:
            return "screen -S stack -p {} -X stuff $'\\003 !!\\n'".format(sn)
        else:
            return "screen -S stack -p {} -X stuff $'\003 !!\\n'".format(sn)
    raise EnvironmentError("Service: {} not detected".format(service))


def clone_driver(cinder_driver, d_version):
    check_requirements()
    # Get repository and checkout version
    if not cinder_driver:
        repo = REPO
        if not os.path.isdir("{}/cinder-driver".format(HOME)):
            exe("cd {} && git clone {}".format(HOME, GITHUB))
    else:
        repo = cinder_driver
    version = d_version
    exe("cd {} && git fetch --all".format(HOME))
    exe("cd {} && git checkout {}".format(repo, version))
    loc = detect_cinder_install()
    return repo, loc


def install_volume_driver(cinder_driver, ip, username, password, d_version):
    # Copy files to install location
    repo, loc = clone_driver(cinder_driver, d_version)
    dloc = os.path.join(loc, "volume/drivers")
    exe("cp -r {}/src/datera/ {}".format(repo, dloc))

    # Modify etc file
    data = None
    with io.open(ETC, 'r') as f:
        data = f.readlines()
    # Place lines under [DEFAULT]
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

    # Write [datera] section
    tdata = ETC_TEMPLATE.format(
        ip=ip,
        login=username,
        password=password)
    data.extend(tdata.splitlines())

    shutil.copyfile(ETC, ETC + ".bak.{}".format(str(uuid.uuid4())[:4]))
    with io.open(ETC, 'w') as f:
        for line in data:
            line = line.strip()
            f.write(line)
            f.write("\n")

    # Restart cinder-volume service
    restart = detect_service_restart_cmd("cinder-volume")
    vprint("Restarting the cinder-volume service")
    if loc == DEVSTACK_INSTALL:
        vprint("Detected devstack")
    else:
        vprint("Detected non-devstack")
    exe(restart)


def check_volume_driver():
    pass

# def install_backup_driver(
#         cinder_driver, ip, username, password, devstack, d_version):
#     vprint("Checking/Installing Datera Cinder Backup Driver")
#     # Copy files to install location
#     repo, loc = clone_driver(cinder_driver, d_version)
#     dloc = os.path.join(loc, "backup/drivers")
#     exe("cp {}/src/datera/backup/datera.py {}".format(repo, dloc))

#     # Modify etc file

#     # Restart cinder-backup service

# def check_backup_driver():
#    pass


def main(args):
    if args.detect_install:
        print("Location:", detect_cinder_install())
        print("Service Restart:", detect_service_restart_cmd("cinder-volume",
                                                             display=True))
        return SUCCESS
    check_volume_driver(args.cinder_driver,
                        args.ip,
                        args.username,
                        args.password,
                        args.d_version)

    # if args.backup_driver:
    #     check_backup_driver(args.cinder_driver,
    #                         args.ip,
    #                         args.username,
    #                         args.password,
    #                         args.d_version)

    print("Ready to go")
    return SUCCESS

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('ip', nargs='?', help="Datera Mgmt IP")
    parser.add_argument('username', nargs='?', help="Datera account username")
    parser.add_argument('password', nargs='?', help="Datera account password")
    parser.add_argument('d_version', nargs='?', default="master",
                        help="Driver Version. Eg: 'newton-v2.3.2'")
    parser.add_argument('-d', '--detect-install', action='store_true',
                        help='Detect cinder installation and print location')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Print verbose output")
    # parser.add_argument('-b', '--backup-driver', action='store_true',
    #                     help="Install backup driver")
    parser.add_argument('-c', '--cinder-driver',
                        help="Cinder driver folder location (for custom "
                             "install)")

    args = parser.parse_args()
    common.verbose = args.verbose
    sys.exit(main(args))
