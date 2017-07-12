#!/usr/bin/env python

from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

"""
Openstack cinder controller level:

Driver check:

Is the latest running?

Auto update?

Is cinder backup setup, if not suggest they get the driver :)


OpenStack Datera types created?

Given the backend name, are types created?


Host level stuff:

Is ARP setup correctly?

#sysctl

#check /etc/sysctl.conf

Settings:

net.ipv4.conf.all.arp_announce = 2

net.ipv4.conf.all.arp_ignore = 1



Is irqbalance running?

#Stop irqbalanace if running

#service irqbalance stop
#Recommend rebalancing IRQ for Network interface based on NIC vendor tools.


Is cpufreq set to performance?

NOTE: this is OS dependent:
https://www.google.com/search?q=linux+cpufreq+howto&oq=linux+cpufreq&aqs=chrome.4.69i57j0l5.6655j0j7&sourceid=chrome&ie=UTF-8,
need Debian / Ubuntu and RedHat / Centos.


Block devices set to NOOP?

Check /sys/block/*/device/scheduler

NOTE:
http://www.techrepublic.com/article/how-to-change-the-linux-io-scheduler-to-fit-your-needs/



Multipath.conf setting and nova.conf check:

#If They want to use Multipath.conf this is needed.

https://drive.google.com/drive/u/1/folders/0B7eQy3YWSJolYnFQYVJnYzc2cWs

Check Page 11 here.  Ideally we could have a reference multipath.conf file
that checks the local multipath.conf file


If this tool can be used out side of OpenStack environments to validate
best practices that would be even better!!
"""
import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import uuid

try:
    from install_cinder_driver import check_volume_driver as check_vdriver
    from install_cinder_driver import check_backup_driver as check_bdriver
except ImportError:
    print("No module install_cinder_driver found")
    check_vdriver = None
    check_bdriver = None

SUCCESS = 0
FAILURE = 1

verbose = False

# Using string REPLACEME instead of normal string formatting because it's
# easier than escaping everything
MULTIPATH_CONF = """
defaults {
    checker_REPLACEME 5

}

devices {

    device {

    vendor "DATERA"

    product "IBLOCK"

    getuid_callout "/lib/udev/scsi_id --whitelisted --replace-
    whitespace --page=0x80 --device=/dev/%n"

    path_grouping_policy group_by_prio

    path_checker tur

    prio alua

    path_selector "queue-length 0"

    hardware_handler "1 alua"

    failback 5

    }

}

blacklist {

    device {

    vendor ".*"

    product ".*"

    }

}

blacklist_exceptions {

    device {

    vendor "DATERA.*"

    product "IBLOCK.*"

    }

}
"""

CONFIG = {"ip": "1.1.1.1",
          "username": "admin",
          "password": "password",
          "cinder-backup": {
              "version": "master",
              "location": None},
          "cinder-volume": {
              "version": "master",
              "location": None}}

GEN_CONFIG_FILE = "datera-validation-config.json"
DEFAULT_CONFIG_FILE = ".datera-validation-config.json"


def vprint(*args, **kwargs):
    global verbose
    if verbose:
        print(*args, **kwargs)


def exe(cmd):
    vprint("Running cmd:", cmd)
    return subprocess.check_output(cmd, shell=True)


def get_os():
    try:
        exe("which apt-get")
        return "ubuntu"
    except subprocess.CalledProcessError:
        try:
            exe("which yum")
            return "centos"
        except subprocess.CalledProcessError:
            return


# Check Exit
def ce(func, **kwargs):
    if func(**kwargs):
        sys.exit(FAILURE)
    return SUCCESS


def check_arp(*args, **kwargs):
    vprint("Checking ARP settings")
    exe("sudo sysctl -w net.ipv4.conf.all.arp_announce=2")
    exe("sudo sysctl -w net.ipv4.conf.all.arp_ignore=1")
    return SUCCESS


def check_irq(*args, **kwargs):
    vprint("Checking irqbalance settings")
    exe("sudo service irqbalance stop")
    return SUCCESS


def check_cpufreq(*args, **kwargs):
    vprint("Checking cpufreq settings")
    if kwargs["os_version"] == "ubuntu":
        # Install necessary headers and utils
        exe("sudo apt-get install linux-tools-$(uname -r) "
            "linux-cloud-tools-$(uname -r) linux-tools-common -y")
        # Install cpufrequtils package
        exe("sudo apt-get install cpufrequtils -y")
    elif kwargs["os_version"] == "centos":
        # Install packages
        exe("sudo yum install kernel-tools -y")
    try:
        exe("sudo cpupower frequency-info --governors | grep performance")
    except subprocess.CalledProcessError:
        raise EnvironmentError(
            "No 'performance' governor found for system.  If this is a VM,"
            " governors might not be available and this check should be"
            " disabled")
    # Update governor
    exe("sudo cpupower frequency-set --governor performance")
    # Restart service
    if kwargs["os_version"] == "ubuntu":
        exe("sudo service cpufrequtils restart")
    else:
        exe("sudo service cpupower restart")
        exe("sudo systemctl daemon-reload")
    # Remove ondemand rc.d files
    exe("sudo rm -f /etc/rc?.d/*ondemand")
    return SUCCESS


def check_block_devices(*args, **kwargs):
    vprint("Checking block device settings")
    grub = "/etc/default/grub"
    bgrub = "/etc/default/grub.bak.{}".format(str(uuid.uuid4())[:4])
    vprint("Backing up grub default file to {}".format(bgrub))
    shutil.copyfile(grub, bgrub)
    vprint("Writing new grub default file")
    data = []
    with io.open(grub, "r+") as f:
        for line in f.readlines():
            if "GRUB_CMDLINE_LINUX=" in line and "elevator=noop" not in line:
                line = "=".join(("GRUB_CMDLINE_LINUX", "\"" + " ".join((
                    line.split("=")[-1].strip("\""), "elevator=noop"))))
            data.append(line)
    with io.open(grub, "w+") as f:
        f.writelines(data)
    if kwargs["os_version"] == "ubuntu":
        exe("sudo update-grub2")
    elif kwargs["os_version"] == "centos":
        exe("grub2-mkconfig -o /boot/grub2/grub.cfg")
    return SUCCESS


def check_multipath(*args, **kwargs):
    vprint("Checking multipath settings")
    if kwargs["os_version"] == "ubuntu":
        exe("sudo apt-get install multipath-tools -y")
    elif kwargs["os_version"] == "centos":
        exe("sudo yum install device-mapper-multipath -y")

    mfile = "/etc/multipath.conf"
    bfile = "/etc/multipath.conf.bak.{}".format(str(uuid.uuid4())[:4])
    if os.path.exists("/etc/multipath.conf"):
        vprint("Found existing multipath.conf, moving to {}".format(bfile))
        shutil.copyfile(mfile, bfile)
    with io.open("/etc/multipath.conf", "w+") as f:
        if kwargs["os_version"] == "ubuntu":
            f.write(MULTIPATH_CONF.replace("REPLACEME", "timer"))
        elif kwargs["os_version"] == "centos":
            mconf = MULTIPATH_CONF.replace("REPLACEME", "timeout")
            # filter out getuid line which is deprecated in RHEL
            mconf = "\n".join((line for line in mconf.split("\n")
                               if "getuid" not in line))
            f.write(mconf)
    if kwargs["os_version"] == "ubuntu":
        exe("sudo systemctl start multipath-tools")
        exe("sudo systemctl enable multipath-tools")
    elif kwargs["os_version"] == "centos":
        exe("sudo systemctl start multipathd")
        exe("sudo systemctl enable multipathd")
    return SUCCESS


def check_cinder_volume(*args, **kwargs):
    config = kwargs["config"]
    ip = config["ip"]
    username = config["username"]
    password = config["password"]
    version = config["cinder-volume"]["version"]
    location = config["cinder-volume"]["location"]

    check_vdriver(location, ip, username, password, version)


def check_cinder_backup(*args, **kwargs):
    config = kwargs["config"]
    ip = config["ip"]
    username = config["username"]
    password = config["password"]
    version = config["cinder-backup"]["version"]
    location = config["cinder-backup"]["location"]

    check_bdriver(location, ip, username, password, version)


def generate_config_file():
    print("Generating example config file: {}".format(GEN_CONFIG_FILE))
    with io.open(GEN_CONFIG_FILE, "w+") as f:
        try:
            json.dump(CONFIG, f, indent=4, sort_keys=True)
        except TypeError:
            # Python 2 compatibility
            f.write(json.dumps(CONFIG, indent=4, sort_keys=True).decode(
                'utf-8'))
        sys.exit(0)


def main(args):

    # Generate or load config file
    if args.generate_config_file:
        generate_config_file()
        return SUCCESS
    elif args.config_file:
        if not os.path.exists(args.config_file):
            raise EnvironmentError(
                "Config file {} not found".format(args.config_file))
        with io.open(args.config_file, "r") as f:
            config = json.load(f)
    elif os.path.exists(DEFAULT_CONFIG_FILE):
        with io.open(DEFAULT_CONFIG_FILE, "r") as f:
            config = json.load(f)
    else:
        print("No config file found.\nMust either have a {} file in current "
              "directory or manually specify config file via '-c' flag. "
              "\nA sample config file can be generated with the '-g' flag."
              "".format(
                  DEFAULT_CONFIG_FILE))
        return FAILURE

    os_version = get_os()
    if not os_version:
        raise EnvironmentError("Unsupported Operating System")

    if not args.disable_arp_check:
        ce(check_arp, os_version=os_version)
    if not args.disable_irq_check:
        ce(check_irq, os_version=os_version)
    if not args.disable_cpufreq_check:
        ce(check_cpufreq, os_version=os_version)
    if not args.disable_block_device_check:
        ce(check_block_devices, os_version=os_version)
    if not args.disable_multipath_check:
        ce(check_multipath, os_version=os_version)
    if not args.disable_cinder_volume_check:
        ce(check_cinder_volume, os_version=os_version, config=config)

    return SUCCESS

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--generate-config-file", action="store_true",
                        help="Generate config file example")
    parser.add_argument("-c", "--config-file",
                        help="Config file location")
    parser.add_argument("--disable-cinder-volume-check", action="store_true")
    parser.add_argument("--disable-arp-check", action="store_true")
    parser.add_argument("--disable-irq-check", action="store_true")
    parser.add_argument("--disable-cpufreq-check", action="store_true")
    parser.add_argument("--disable-block-device-check", action="store_true")
    parser.add_argument("--disable-multipath-check", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print verbose output")
    args = parser.parse_args()

    verbose = args.verbose
    sys.exit(main(args))
