#!/usr/bin/env python

from __future__ import (print_function, unicode_literals, division,
                        absolute_import)

import argparse
import contextlib
import os
import random
import shlex
import subprocess
import sys
import threading
import time
import uuid

from openstack import connection

import six.moves.queue as queue
from six.moves import input

stop = False
verbose = False


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
    try:
        admin_conn = get_conn()
        if args.clean:
            for conn, pname in zip(conns, project_names):
                delete_project(admin_conn, pname)
                delete_project(admin_conn, pname)

        for pname in project_names:
            create_project(admin_conn, pname)
            conns.append(get_conn(project_name=pname))

        yield conns

    finally:
        dprint("Cleaning Up")
        for conn in conns:
            clean_servers(conn)
            clean_volumes(conn)
        time.sleep(5)

        for pname in project_names:
            delete_project(admin_conn, pname)
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


def get_conn(project_name=None, username=None, password=None):
    auth_dict = {'auth_url': os.getenv("OS_AUTH_URL"),
                 'project_name': project_name if project_name else os.getenv(
                     "OS_PROJECT_NAME"),
                 'username': username if username else os.getenv(
                     "OS_USERNAME"),
                 'password': password if password else os.getenv(
                     "OS_PASSWORD")}
    return connection.Connection(**auth_dict)


def create_project(conn, name):
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


def create_volume(conn, size, vol_ref=None, vols=None, image_ref=None):
    vprint("Creating Volume: size={}, vol_ref={}, image_ref={}".format(
        size, vol_ref, image_ref))
    vol_id = conn.block_store.create_volume(size=size,
                                            imageRef=image_ref,
                                            source_volid=vol_ref).id
    vprint("Created Volume: {}".format(vol_id))
    while True:
        vol = conn.block_store.get_volume(vol_id)
        if vol.status == 'available':
            if vols:
                vols.put(vol)
            vprint("Volume: {} now available".format(vol_id))
            return vol


def create_server(conn, root_vol, data_vol, flavor, net_id, security_group):
    vprint("Creating Server: root_vol={}, data_vol={}, net_id={}".format(
        root_vol.id, data_vol.id, net_id))
    name = "myvm-{}".format(str(uuid.uuid4()))
    server_id = conn.compute.create_server(
            name=name, flavorRef=flavor, networks=[{'uuid': net_id}],
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
    conn.network.remove_security_group(name, ignore_missing=False)


def exec_cmd(server, cmd, quiet=False):
    if not quiet:
        print("Server: {}, cmd: {}".format(server.name, cmd))
    ip = server.addresses['public'][1]['addr']
    try:
        ncmd = (
            "sshpass -p 'cubswin:)' "
            "ssh "
            "{} "
            "-o UserKnownHostsFile=/dev/null "
            "-o StrictHostKeyChecking=no "
            "-o CheckHostIP=no "
            "cirros@{} \"{}\"".format("-q" if quiet else "", ip, cmd))
        if not quiet:
            print(ncmd)
        result = subprocess.check_output(shlex.split(ncmd))
    except subprocess.CalledProcessError as e:
        if not quiet:
            print(e)
        result = e.output

    return result


def dprint(s, c="="):
    l = len(s)
    bfl = l + 4
    print()
    print(c * bfl)
    print("{c} {s} {c}".format(c=c, s=s))
    print(c * bfl)
    print()


def main(args):
    global verbose
    if args.verbose:
        verbose = True

    dprint("Starting OpenStack Boston Summit Tenancy Demo")
    with setup(args) as conns:
        for conn in conns:
            dprint("Setting Up Project")

            dprint("Creating Root Image", c="*")
            # Create initial volume:
            vol = create_volume(conn, args.root_size, image_ref=args.image_id)

            root_vols = queue.Queue()
            data_vols = queue.Queue()
            dprint("Creating Security Group", c="*")
            sec_group = "open"
            create_security_group(conn, sec_group)
            dprint("Creating Data and Root Volumes", c="*")
            for vm in range(args.num_vms):
                threading.Thread(target=create_volume,
                                 args=(conn, args.root_size),
                                 kwargs={'vols': root_vols,
                                         'vol_ref': vol.id}).start()
                threading.Thread(target=create_volume,
                                 args=(conn, args.data_size),
                                 kwargs={'vols': data_vols}).start()

            dprint("Creating Servers", c="*")
            for vm in range(args.num_vms):
                root_vol = root_vols.get()
                data_vol = data_vols.get()
                threading.Thread(target=create_server,
                                 args=(conn, root_vol, data_vol,
                                       args.flavor_id, args.net_id,
                                       sec_group)).start()

        time.sleep(10)
        dprint("Testing Connection To Servers")
        for conn in conns:
            for server in conn.compute.servers():
                while True:
                    result = exec_cmd(server, "uname -a && ip a")
                    if "returned non-zero exit status" not in result:
                        break

        def quit():
            print("Recieved Quit Request")
            raise QuitError

        def print_projects():
            print("Projects")
            print("========")
            for project in conns[0].identity.projects():
                print(project.name, ":", project.id)

        def print_volumes():
            print("Project : Volume")
            print("================")
            for conn in conns:
                for volumed in conn.block_store.volumes():
                    pid = volumed.project_id
                    project = conn.identity.find_project(pid)
                    print(project.name, ":", volumed.id)

        def print_servers():
            print("Project : Server")
            print("================")
            for conn in conns:
                for serverd in conn.compute.servers():
                    pid = serverd.project_id
                    project = conn.identity.find_project(pid)
                    print(project.name, ":", serverd.id)

        def run_traffic():
            serverd = next(random.choice(conns).compute.servers())
            pid = serverd.project_id
            volume = serverd.attached_volumes[0]
            print("Running Traffic")
            print("===============")
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
                             "sudo dd if=/dev/zero of=/mnt/mydrive/test.img "
                             "bs=1M count=500", quiet=True)
                print("Traffic thread stopped")

            threading.Thread(target=_traffic_helper).start()
            print("Traffic is running")

        def stop_traffic():
            print("Stopping Traffic")
            global stop
            stop = True

        # Finished with setup
        run = {'q': quit,
               'pp': print_projects,
               'pv': print_volumes,
               'ps': print_servers,
               'rt': run_traffic,
               'st': stop_traffic}
        help = """
q --> Quit
pp --> Print Projects
pv --> Print Volumes
ps --> Print Servers
rt --> Run Traffic
st --> Stop Traffic
-----------
"""
        dprint("Ready To Go!")
        while True:
            result = input(help)

            try:
                print()
                run[result.lower()]()
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
    parser.add_argument('image_id',
                        help="ID for image to use in root volume")
    parser.add_argument('net_id')
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
        print("Checking requirements")
        try:
            subprocess.check_call(shlex.split("which {}".format(requirement)))
        except subprocess.CalledProcessError:
            print("Missing {} requirement".format(requirement))

    sys.exit(main(args))
