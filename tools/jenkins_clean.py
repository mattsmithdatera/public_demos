#!/usr/bin/env python

import argparse

try:
    from io import StringIO
except ImportError:
    from StringIO import StringIO

import requests
from lxml import etree
import arrow


def main(args):

    parser = etree.HTMLParser()
    html = requests.get("http://jenkins.daterainc.com/jenkins/").text
    root = etree.parse(StringIO(html), parser)

    table = root.xpath("//table[@id='projectstatus']")[0]

    found = []
    for row in table.getchildren():
        td = row.xpath('td[4]')
        if td:
            utime = td[0].attrib['data']
            time = arrow.get(utime) if utime != "-" else arrow.get(0)
            found.append((row.attrib['id'].replace("job_", "", 1), time))

    old = arrow.utcnow().replace(months=-args.months)
    found = filter(lambda x: x[1] <= old, found)
    found = sorted(found, key=lambda x: x[1])

    for name, time in found:
        print("{:<40} {}".format(name, str(time)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--months", default=6, type=int,
                        help="Limit displayed results to jobs that haven't "
                             "run since this many months ago")
    args = parser.parse_args()
    main(args)
