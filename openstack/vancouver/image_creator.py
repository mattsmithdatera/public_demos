#!/usr/bin/env python

from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import argparse
import sys
import threading
import time

import openstack
# from dfs_sdk import get_api

IMG_INTERVAL = 20
WAIT_INTERVAL = 600


def gen_name():
    pass


def create_image(conn):
    name = gen_name()
    return conn.images.create(name=name)


def delete_image(conn, name):
    return conn.images.delete(name=name)


def cd_image(conn):
    img = create_image(conn)
    time.sleep(WAIT_INTERVAL)
    delete_image(conn, img.name)


def main(args):
    conn = openstack.connect()
    # api = get_api()
    threads = []
    while True:
        thread = threading.Thread(target=cd_image, args=conn)
        threads.append(thread)
        thread.daemon = True
        thread.start()
        time.sleep(IMG_INTERVAL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    sys.exit(main(args))
