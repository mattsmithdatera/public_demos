#!/usr/bin/env python

from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import io
import os
import shutil
import uuid

from common import vprint, exe, exe_check, SUCCESS, ff

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


def get_os():
    if exe_check("which apt-get", err=False):
        return "ubuntu"
    if exe_check("which yum", err=False):
        return "centos"


def check_os():
    if not get_os():
        return ff("Unsupported Operating System")
    return SUCCESS


def check_arp():
    vprint("Checking ARP settings")
    results = []
    first = exe_check("sysctl --all 2>/dev/null | "
                      "grep 'net.ipv4.conf.all.arp_announce = 2'",
                      err=False)
    second = exe_check("sysctl --all 2>/dev/null | "
                       "grep 'net.ipv4.conf.all.arp_ignore = 1'",
                       err=False)
    if not first:
        results.append("net.ipv4.conf.all.arp_announce != 2")
    if not second:
        results.append("net.ipv4.conf.all.arp_ignore != 1")
    if results:
        return ff(results)
    return SUCCESS


def fix_arp(*args, **kwargs):
    vprint("Fixing ARP settings")
    exe("sysctl -w net.ipv4.conf.all.arp_announce=2")
    exe("sysctl -w net.ipv4.conf.all.arp_ignore=1")
    return SUCCESS


def check_irq():
    vprint("Checking irqbalance settings, (should be turned off)")
    if not exe_check("systemctl status irqbalance | "
                     "grep 'Active: active'",
                     err=True):
        return ff("irqbalance is active")
    return SUCCESS


def fix_irq(*args, **kwargs):
    vprint("Stopping irqbalance service")
    exe("service irqbalance stop")
    return SUCCESS


def check_cpufreq():
    vprint("Checking cpufreq settings")
    if not exe_check("which cpupower"):
        return ff("cpupower is not installed")
    if not exe_check("cpupower frequency-info --governors | "
                     "grep performance",
                     err=False):
        return ff(
            "No 'performance' governor found for system.  If this is a VM,"
            " governors might not be available and this check should be"
            " disabled")
    return SUCCESS


def fix_cpufreq(*args, **kwargs):
    if kwargs["os_version"] == "ubuntu":
        # Install necessary headers and utils
        exe("apt-get install linux-tools-$(uname -r) "
            "linux-cloud-tools-$(uname -r) linux-tools-common -y")
        # Install cpufrequtils package
        exe("apt-get install cpufrequtils -y")
    elif kwargs["os_version"] == "centos":
        # Install packages
        exe("yum install kernel-tools -y")
    # Update governor
    exe("cpupower frequency-set --governor performance")
    # Restart service
    if kwargs["os_version"] == "ubuntu":
        exe("service cpufrequtils restart")
    else:
        exe("service cpupower restart")
        exe("systemctl daemon-reload")
    # Remove ondemand rc.d files
    exe("rm -f /etc/rc?.d/*ondemand")
    return SUCCESS


def check_block_devices():
    vprint("Checking block device settings")
    grub = "/etc/default/grub"
    with io.open(grub, "r") as f:
        line = filter(lambda x: x.startswith("GRUB_CMDLINE_LINUX="),
                      f.readlines())
        if len(line != 1):
            return ff("Grub file appears non-standard")
        if "elevator=noop" not in line:
            return ff("Scheduler is not set to noop")
    return SUCCESS


def fix_block_devices(*args, **kwargs):
    vprint("Fixing block device settings")
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
        exe("update-grub2")
    elif kwargs["os_version"] == "centos":
        exe("grub2-mkconfig -o /boot/grub2/grub.cfg")
    return SUCCESS


def check_multipath():
    vprint("Checking multipath settings")
    if not exe_check("which multipath", err=False):
        return ff("Multipath binary could not be found, is it installed?")
    mfile = "/etc/multipath.conf"
    if not os.path.exists(mfile):
        return ff("multipath.conf file not found")
    if not exe_check("systemctl status multipathd | grep Active: active",
                     err=False):
        return ff("multipathd not enabled")
    return SUCCESS


def fix_multipath(*args, **kwargs):
    vprint("Fixing multipath settings")
    if kwargs["os_version"] == "ubuntu":
        exe("apt-get install multipath-tools -y")
    elif kwargs["os_version"] == "centos":
        exe("yum install device-mapper-multipath -y")
    mfile = "/etc/multipath.conf"
    bfile = "/etc/multipath.conf.bak.{}".format(str(uuid.uuid4())[:4])
    if os.path.exists(mfile):
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
        exe("systemctl start multipath-tools")
        exe("systemctl enable multipath-tools")
    elif kwargs["os_version"] == "centos":
        exe("systemctl start multipathd")
        exe("systemctl enable multipathd")
    return SUCCESS


def client_check(config):

    checks = [check_os,
              check_arp,
              check_irq,
              check_cpufreq,
              check_block_devices,
              check_multipath]

    print("\n".join(map(lambda x: x(), checks)))


def connection_check(config):
    checks = []
    mgmt = config["mgmt_ip"]
    vip1 = config["vip1_ip"]
    vip2 = config.get("vip2_ip")
    if not exe_check("ping -c 2 {}".format(mgmt), err=False):
        checks.append(ff("Could not ping management ip {}".format(mgmt)))
    if not exe_check("ping -c 2 {}".format(vip1), err=False):
        checks.append(ff("Could not ping vip1 ip {}".format(vip1)))
    if vip2 and not exe_check("ping -c 2 {}".format(vip2), err=False):
        checks.append(ff("Could not ping vip2 ip {}".format(vip2)))

    if checks:
        print("\n".join(checks))
        return ff("Connection errors")

    return SUCCESS


def client_fix(args):
    pass
