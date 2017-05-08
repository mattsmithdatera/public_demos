#!/usr/bin/env python
from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import argparse
import re
import sys

from dfs_sdk import DateraApi21

IPRE_STR = r'(\d{1,3}\.){3}\d{1,3}'
IPRE = re.compile(IPRE_STR)

SIP = re.compile(r'san_ip\s+?=\s+?(?P<san_ip>%s)' % IPRE_STR)
SLG = re.compile(r'san_login\s+?=\s+?(?P<san_login>.*)')
SPW = re.compile(r'san_password\s+?=\s+?(?P<san_password>.*)')


def readCinderConf():
    data = None
    with open('/etc/cinder/cinder.conf') as f:
        data = f.read()
    san_ip = SIP.search(data).group('san_ip')
    san_login = SLG.search(data).group('san_login')
    san_password = SPW.search(data).group('san_password')
    return san_ip, san_login, san_password


def getAPI(tenant=None):
    san_ip, san_login, san_password = readCinderConf()
    if tenant and "root" not in tenant:
        tenant = "/root/{}".format(tenant)
    return DateraApi21(san_ip,
                       username=san_login,
                       password=san_password,
                       tenant=tenant,
                       secure=True,
                       immediate_login=True)


def main(args):
    api = getAPI()
    to_delete = []
    for tenant in api.tenants.list():
        tname = "/root/{}".format(tenant['name'])
        if "root" in tenant['name']:
            tname = "/{}".format(tenant['name'])
        if not api.app_instances.list(tenant=tname) and args.clean:
            if args.openstack_only:
                if tenant['name'].startswith("OS-"):
                    print("Openstack Tenant: ", tname)
                    to_delete.append(tenant)
            else:
                print("Tenant", tname)
                to_delete.append(tenant)
    resp = raw_input("Are you sure you want to delete these? [Y/N]\n")
    if resp.lower().strip() in ("y", "yes"):
        print("Deleting")
        for t in to_delete:
            t.delete()
        sys.exit(0)
    else:
        print("Cancelling")
        sys.exit(1)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--clean", action='store_true',
                        help="Clean empty tenants")
    parser.add_argument("-o", "--openstack-only", action='store_true',
                        help="Clean only openstack tenants")
    args = parser.parse_args()
    main(args)
    sys.exit(0)
