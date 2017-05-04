#!/usr/bin/env python

from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import argparse
import contextlib
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import uuid

from openstack import connection

from dfs_sdk import DateraApi21

import six.moves.queue as queue
from six.moves import input

IPRE_STR = r'(\d{1,3}\.){3}\d{1,3}'
IPRE = re.compile(IPRE_STR)

SIP = re.compile(r'san_ip\s+?=\s+?(?P<san_ip>%s)' % IPRE_STR)
SLG = re.compile(r'san_login\s+?=\s+?(?P<san_login>.*)')
SPW = re.compile(r'san_password\s+?=\s+?(?P<san_password>.*)')

stop = False
verbose = False
net_name = None
image_id = None


class QuitError(Exception):
    pass


def usage():
    print("OS_USERNAME, OS_PASSWORD, OS_AUTH_URL and "
          "OS_PROJECT_NAME must be set")


def vprint(*args, **kwargs):
    global verbose
    if verbose:
        print(*args, **kwargs)


@contextlib.contextmanager
def setup(args):
    admin_conn, conns = None, []
    project_names = [elem for elem in args.projects.split(",") if elem]
    base_bandwidth = 500
    index = 1
    sec_group = "open"
    try:
        admin_conn = get_conn()
        global image_id
        image_id = admin_conn.image.find_image(args.image_name).id
        if args.clean:
            for conn, pname in zip(conns, project_names):
                delete_project(admin_conn, pname)
                delete_project(admin_conn, pname)

        for pname in project_names:
            create_project(admin_conn, pname)
            conn = get_conn(project_name=pname)
            dprint("Creating Security Group", c="*")
            create_security_group(conn, sec_group)
            create_volume_type(admin_conn,
                               pname,
                               volume_backend_name="datera",
                               total_bandwidth_max=str(base_bandwidth * index))
            index += 1
            conns.append(conn)

        yield zip(conns, project_names)

    finally:
        dprint("Cleaning Up")
        for conn in conns:
            clean_servers(conn)
            clean_volumes(conn)
        time.sleep(5)

        for pname in project_names:
            delete_volume_type(admin_conn, pname)
            delete_project(admin_conn, pname)
            delete_security_group(admin_conn, sec_group)
        dprint("Done!")


def clean_volumes(conn):
    print("Cleaning volumes")
    for volume in conn.block_store.volumes():
        conn.block_store.delete_volume(volume.id)


def clean_servers(conn):
    print("Cleaning servers")
    for server in conn.compute.servers():
        conn.compute.delete_server(server.id)

    while len(list(conn.compute.servers())) > 0:
        time.sleep(2)


def get_conn(project_name=None, username=None, password=None, udomain=None,
             pdomain=None):
    auth_dict = {'auth_url': os.getenv("OS_AUTH_URL"),
                 'project_name': project_name if project_name else os.getenv(
                     "OS_PROJECT_NAME"),
                 'username': username if username else os.getenv(
                     "OS_USERNAME"),
                 'password': password if password else os.getenv(
                     "OS_PASSWORD"),
                 'user_domain_name': udomain if udomain else os.getenv(
                     "OS_USER_DOMAIN_NAME"),
                 'project_domain_name': pdomain if pdomain else os.getenv(
                     "OS_PROJECT_DOMAIN_NAME")}

    if not all(auth_dict.keys()):
        usage()
        sys.exit(1)
    return connection.Connection(**auth_dict)


def create_project(conn, name):
    vprint("Creating project: {}".format(name))
    conn.identity.create_project(name=name)
    role = conn.identity.create_role(name=name)
    conn.identity.update_role(role)
    # Add conn role
    subprocess.check_call(shlex.split(
        "openstack role add --user admin --project {} {}".format(name, name)))
    # Add admin role
    subprocess.check_call(shlex.split(
        "openstack role add --user admin --project {} admin".format(
            name)))


def delete_project(conn, name):
    vprint("Deleting project: {}".format(name))
    pid = conn.identity.find_project(name)
    if pid:
        conn.identity.delete_project(pid, ignore_missing=False)
    try:
        subprocess.check_call(shlex.split(
            "openstack role remove --user admin --project {} {}".format(
                name, name)))
    except subprocess.CalledProcessError as e:
        print(e)
    try:
        subprocess.check_call(shlex.split(
            "openstack role remove --user admin --project {} admin".format(
                name)))
    except subprocess.CalledProcessError as e:
        print(e)
    role = conn.identity.find_role(name)
    if role:
        conn.identity.delete_role(role, ignore_missing=False)


def create_volume(conn, size, vol_ref=None, vols=None, image_name=None,
                  volume_type=None):
    global image_id
    imid = None
    if not vol_ref:
        imid = image_id
    vprint("Creating Volume: size={}, vol_ref={}, image_name={}, "
           "volume_type={}".format(size, vol_ref, image_name, volume_type))
    vol_id = conn.block_store.create_volume(size=size,
                                            imageRef=imid,
                                            source_volid=vol_ref,
                                            volume_type=None).id
    vprint("Created Volume: {}".format(vol_id))
    while True:
        vol = conn.block_store.get_volume(vol_id)
        if vol.status == 'available':
            if vols:
                vols.put(vol)
            vprint("Volume: {} now available".format(vol_id))
            return vol


def create_volume_type(conn, name, **attrs):
    vprint("Creating volume type: {}, extra_specs: {}".format(name, attrs))
    conn.block_store.create_type(name=name, extra_specs=attrs)


def delete_volume_type(conn, name):
    vprint("Deleting volume type: {}".format(name))
    fil = [t for t in conn.block_store.types() if t.name == name]
    tp = None
    if len(fil) > 0:
        tp = fil[0]
    if tp:
        conn.block_store.delete_type(tp, ignore_missing=False)


def create_server(conn, root_vol, data_vol, flavor, net_name, security_group):
    vprint("Creating Server: root_vol={}, data_vol={}, net={}".format(
        root_vol.id, data_vol.id, net_name))
    name = "myvm-{}".format(str(uuid.uuid4()))
    net = conn.network.find_network(net_name)
    server_id = conn.compute.create_server(
            name=name, flavorRef=flavor, networks=[{'uuid': net.id}],
            block_device_mapping_v2=[{
                "device_name": "vda",
                "source_type": "volume",
                "destination_type": "volume",
                "uuid": root_vol.id,
                "boot_index": 0}]).id
    vprint("Created Server: {}".format(server_id))
    server = None
    while True:
        try:
            server = conn.compute.find_server(server_id)
            if server.status == 'ACTIVE':
                vprint("Server: {} now active".format(server_id))
                break
        except AttributeError as e:
            print(e)
    # Add security group
    server.add_security_group(conn.session, security_group)
    conn.compute.create_volume_attachment(server.id, volumeId=data_vol.id)
    vprint("Attaching Volume: {} to Server: {}".format(data_vol.id, server.id))
    return server


def create_security_group(conn, name):
    vprint("Creating security_group {}".format(name))
    sec_group = conn.network.create_security_group(name=name)
    for direction in ['ingress', 'egress']:
        # ICMP
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction=direction,
            remote_ip_prefix='0.0.0.0/0',
            protocol='icmp',
            port_range_max=None,
            port_range_min=None,
            ethertype='IPv4')
        # SSH
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction=direction,
            remote_ip_prefix='0.0.0.0/0',
            protocol='tcp',
            port_range_max=22,
            port_range_min=22,
            ethertype='IPv4')


def delete_security_group(conn, name):
    for sec_group in conn.network.security_groups():
        if sec_group.name == name:
            conn.network.delete_security_group(sec_group.id,
                                               ignore_missing=False)


def exec_cmd(server, cmd, quiet=False, reraise=False):
    vprint("Server: {}, cmd: {}".format(server.name, cmd))
    global net_name
    try:
        ip = server.addresses[net_name][0]['addr']
        m = IPRE.match(ip)
        if not m:
            ip = server.addresses[net_name][1]['addr']
    except KeyError:
        ip = server.addresses[net_name][1]['addr']
    try:
        ncmd = (
            "sshpass -p 'cubswin:)' "
            "ssh "
            "{} "
            "-o UserKnownHostsFile=/dev/null "
            "-o StrictHostKeyChecking=no "
            "-o CheckHostIP=no "
            "cirros@{} \"{}\"".format("-q" if quiet else "", ip, cmd))
        vprint(ncmd)
        result = subprocess.check_output(shlex.split(ncmd))
    except subprocess.CalledProcessError as e:
        vprint(e)
        result = e.output
        if reraise:
            raise

    return result


def dprint(s, c="="):
    l = len(s)
    bfl = l + 4
    print()
    print(c * bfl)
    print("{c} {s} {c}".format(c=c, s=s))
    print(c * bfl)
    print()


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

    global verbose, net_name
    if args.verbose:
        verbose = True
    net_name = args.net_name

    dprint("Starting OpenStack Boston Summit Tenancy Demo")
    with setup(args) as conns:
        for conn, pname in conns:
            dprint("Setting Up Project")

            dprint("Creating Root Image", c="*")
            # Create initial volume:
            vol = create_volume(conn, args.root_size,
                                image_name=args.image_name)

            root_vols = queue.Queue()
            data_vols = queue.Queue()
            dprint("Creating Data and Root Volumes", c="*")
            for vm in range(args.num_vms):
                thread = threading.Thread(target=create_volume,
                                          args=(conn, args.root_size),
                                          kwargs={'vols': root_vols,
                                                  'vol_ref': vol.id,
                                                  'volume_type': "datera"})
                thread.daemon = True
                thread.start()
                thread = threading.Thread(target=create_volume,
                                          args=(conn, args.data_size),
                                          kwargs={'vols': data_vols,
                                                  'volume_type': pname})
                thread.daemon = True
                thread.start()

            dprint("Creating Servers", c="*")
            for vm in range(args.num_vms):
                root_vol = root_vols.get()
                data_vol = data_vols.get()
                thread = threading.Thread(target=create_server,
                                          args=(conn, root_vol, data_vol,
                                                args.flavor_id, args.net_name,
                                                'open'))

                thread.daemon = True
                thread.start()

        time.sleep(10)
        dprint("Testing Connection To Servers")
        for conn, name in conns:
            servers = conn.compute.servers()
            if not servers:
                raise EnvironmentError(
                    "No servers available in {} project. Problem in "
                    "setup".format(name))
            for server in conn.compute.servers():
                timeout = 30
                while timeout:
                    try:
                        result = exec_cmd(server, "uname -a && ip a",
                                          quiet=verbose)
                        break
                    except subprocess.CalledProcessError:
                        timeout -= 1
                        time.sleep(1)

        def quit(arg_str):
            print("Recieved Quit Request")
            raise QuitError

        def print_projects(arg_str):
            projects = []
            for project in conns[0][0].identity.projects():
                projects.append((project.name, str(uuid.UUID(project.id))))
            api = getAPI(None)
            dprint("Project Name --> Datera Tenant")
            for tenant in api.tenants.list():
                for pname, pid in projects:
                    if pid in tenant.get("name"):
                        print(pname, "-->", tenant)

        def print_volumes(arg_str):
            dprint("Project : Volume", c="-")
            for conn, _ in conns:
                for volumed in conn.block_store.volumes():
                    pid = volumed.project_id
                    project = conn.identity.find_project(pid)
                    print(project.name, ":", volumed.id)

        def print_servers(arg_str):
            dprint("Project : Server", c="-")
            for conn, _ in conns:
                for serverd in conn.compute.servers():
                    pid = serverd.project_id
                    project = conn.identity.find_project(pid)
                    print(project.name, ":", serverd.id)

        def run_traffic(arg_str):
            serverd = next(conns[0][0].compute.servers())
            pid = serverd.project_id
            volume = serverd.attached_volumes[0]
            dprint("Running Traffic", c="-")
            print("Project :", pid)
            print("Server :", serverd.id)
            print("Volume :", volume['id'])
            print("-----------------------")
            exec_cmd(serverd, "sudo /usr/sbin/mkfs.ext4 /dev/vdb")
            exec_cmd(serverd, "sudo mkdir /mnt/mydrive")
            exec_cmd(serverd, "sudo mount /dev/vdb /mnt/mydrive")

            def _traffic_helper():
                global stop
                stop = False
                while not stop:
                    exec_cmd(serverd,
                             "sudo dd if=/dev/urandom of=/mnt/mydrive/test.img"
                             " bs=1M count=1000 >/dev/null 2>&1 && sudo sync"
                             "", quiet=verbose)
                dprint("Traffic thread stopped", c="-")

            thread = threading.Thread(target=_traffic_helper)
            thread.daemon = True
            thread.start()
            dprint("Traffic is running", c="-")

        def stop_traffic(arg_str):
            dprint("Stopping Traffic", c="-")
            global stop
            stop = True

        def show_ai(arg_str):
            tenant = arg_str.strip()
            if not tenant:
                tenant = "/root"
            dprint("AppInstances under Tenant: {}".format(tenant), c="-")
            api = getAPI(tenant)
            for ai in api.app_instances.list():
                print(ai.get('name'))

        def get_traffic_stats(arg_str):
            dprint("Getting Traffic Stats", c="-")
            tenant = arg_str.strip()
            if not tenant:
                tenant = "/root"
            api = getAPI(tenant)
            try:
                while True:
                    print("Metrics!")
                    try:
                        metric = api.metrics.io.thpt_write.latest.get(
                            )[0]['point']
                        print("IOPS: ", metric['value'])
                    except IndexError:
                        print("No traffic object available")
                        break
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        # Finished with setup
        run = {'q': quit,
               'pp': print_projects,
               'pv': print_volumes,
               'ps': print_servers,
               'rt': run_traffic,
               'st': stop_traffic,
               'sai': show_ai,
               'gts': get_traffic_stats}
        help = """
--------------------------------------------
q --> Quit
pp --> Print Projects
pv --> Print Volumes
ps --> Print Servers
rt --> Run Traffic
st --> Stop Traffic
sai tenant --> Show App Instances for Tenant
gts tenant --> Show traffic stats for Tenant
--------------------------------------------
"""
        dprint("Ready To Go!")
        while True:
            result = input(help)

            try:
                cmd, arg_str = None, None
                try:
                    cmd, arg_str = result.split(" ", 1)
                except ValueError:
                    cmd, arg_str = result, ""
                print()
                run[cmd.lower()](arg_str)
                print()
            except KeyError:
                print("Unknown input: {}".format(result))
            except QuitError:
                break


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('num_vms', type=int)
    parser.add_argument('root_size', type=int)
    parser.add_argument('data_size', type=int)
    parser.add_argument('image_name')
    parser.add_argument('net_name')
    parser.add_argument('flavor_id')
    parser.add_argument('-c', '--clean', action='store_true',
                        help='Clean volumes and servers before running')
    parser.add_argument('-p', '--projects', default="silver,gold",
                        help="Comma delimited list of project names to use")
    parser.add_argument('-v', '--verbose', default=False, action='store_true',
                        help="Enable verbose output")

    args = parser.parse_args()

    requirements = ["sshpass"]

    for requirement in requirements:
        dprint("Checking requirements")
        try:
            subprocess.check_call(shlex.split("which {}".format(requirement)))
        except subprocess.CalledProcessError:
            print("Missing {} requirement".format(requirement))

    sys.exit(main(args))
