#!/bin/bash

# Requires Node with the following attributes:
# 2 GB RAM
# 2 VCPUs
# 2 interfaces (ens3 MGMT and ens4 ANYTHING)
# Hostame == ceph-single-node
# vdb >= 1 TB
# vdc >= 1 TB
# vdd >= 1 TB

if [[ $(hostname) != ceph-single-node ]]; then
    echo "Hostname must be 'ceph-single-node', (because I'm lazy)"
    exit 1
fi

DEVS=(/dev/vdb /dev/vdc /dev/vdd)
for bd in ${DEVS[@]}; do
    if ! [ -b /dev/vdb ]; then
        echo "Need block device ${bd}"
        exit 1
    fi
done

# Configure interfaces and hosts file
sudo ifconfig ens4 up
sudo dhclient ens4
export IP="$(sudo ifconfig ens3 | grep "inet addr" | cut -d ':' -f 2 | cut -d ' ' -f 1)"
sudo -E sh -c 'echo "${IP} ceph-single-node\n$(cat /etc/hosts)" > /etc/hosts'

# Install Ceph prereqs
wget -q -O- 'https://download.ceph.com/keys/release.asc' | sudo apt-key add -
echo deb http://download.ceph.com/debian-jewel/ trusty main | sudo tee /etc/apt/sources.list.d/ceph.list
sudo apt-get update && sudo apt-get install ceph-deploy -y

# Setup ceph-deploy user
sudo useradd -m -s /bin/bash ceph-deploy
sudo passwd ceph-deploy
echo "ceph-deploy ALL = (root) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/ceph-deploy
sudo chmod 0440 /etc/sudoers.d/ceph-deploy

# Generate ssh keyfiles and register on same node
sudo su ceph-deploy -c 'ssh-keygen'
sudo su ceph-deploy -c 'cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys'
sudo su ceph-deploy -c 'ssh-copy-id ceph-deploy@ceph-single-node'

# Make directory for cluster configs
sudo su ceph-deploy -c 'cd ~ && mkdir ~/my-cluster'

# Create the new config
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy new ceph-single-node'

# Set single-node params
sudo sh -c 'echo "osd_pool_default_size = 2" >> /home/ceph-deploy/my-cluster/ceph.conf'
sudo sh -c 'echo "osd_crush_chooseleaf_type = 0" >> /home/ceph-deploy/my-cluster/ceph.conf'

# Install Ceph
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy install ceph-single-node'

# Create monitor service
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy mon create-initial'

# Configure block device daemons
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy osd prepare ceph-single-node:vdb'
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy osd prepare ceph-single-node:vdc'
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy osd prepare ceph-single-node:vdd'

# Activate block device daemons
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy osd activate ceph-single-node:/dev/vdb1'
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy osd activate ceph-single-node:/dev/vdc1'
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy osd activate ceph-single-node:/dev/vdd1'

# Create admin user
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy admin ceph-single-node'
sudo su ceph-deploy -c 'cd ~/my-cluster && sudo chmod +r /etc/ceph/ceph.client.admin.keyring'

# Print status
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph -s'

echo "Waiting for Ceph cluster to form"
sleep 10

# Create storage gateway and cephfs
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy rgw create ceph-single-node'
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph-deploy mds create ceph-single-node'

# Setup cephfs volumes
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph osd pool create cephfs_data 128'
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph osd pool create cephfs_metadata 128'

# Create filesystem
sudo su ceph-deploy -c 'cd ~/my-cluster && ceph fs new cephfs cephfs_metadata cephfs_data'

# Ceph client libraries
sudo apt-get install ceph-fs-common

# Mount cephfs filesystem
sudo mkdir /mnt/mycephfs
SKEY=sudo su ceph-deploy -c 'cat ~/my-cluster/ceph.client.admin.keyring' | grep key | awk '{print $3}'
sudo mount -t ceph ceph-single-node:6789:/ /mnt/mycephfs -o name=admin,secret=${SKEY}

# Show mount
df -h /mnt/mycephfs
