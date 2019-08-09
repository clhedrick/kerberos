#!/usr/bin/python3

# this program kills unused network name spaces
# it also cleans up the associated veth link and iptables rules
# all the magic is done by executing system commands, so this
# could have been done in bash, but I prefer the data
# structures in Python
#   This is way too complicated. But the reason is that
# the system commands don't give the information you need
# in any easy way. So we need to build up various maps,
# and combine the information in them.
#   Like any script of this kind, changes in format of output
# could break it, so beware of version changes. 

import subprocess
import json
import shlex
import re

# first list all name spaces
# output looks like
# 4026532472 ns1
# first field is inode number
# allnsinodes maps inode -> name
inodes = subprocess.check_output(['ls', '-i', '/run/netns']).decode('utf-8').split('\n')
nsinodes = {}
for inodeline in inodes:
  fields = inodeline.split(' ')
  if len(fields) != 2:
    continue
  inode = fields[0]
  name = fields[1]
  nsinodes[inode] = name

# now list the ones in use
# output looks like
# 4026532627 net
inodes = subprocess.check_output(['lsns', '-n', '--output', 'ns,type']).decode('utf-8').split('\n')
for inodeline in inodes:
  fields = inodeline.split(' ')
  if len(fields) != 2:
    continue
  inode = fields[0]
  itype = fields[1]
  if itype == 'net':
    if inode in nsinodes:
      del nsinodes[inode]

# nsinodes now has just the ones to delete

# need to know link associated with this namespace
# "ip netns" returns things like "ns2 (id: 1)"
# we can then use "ip link" to find the link by its id

# build map of ns name to id

ns2id = {}
nslist = subprocess.check_output(["ip", "netns"]).decode('utf-8').split('\n')
for nsmap in nslist:
    # looks like "ns2 (id: 1)"
    m = re.search('^(\S+) \(id: ([0-9])+\)', nsmap)
    if not m:
        continue
    name = m.group(1)
    nsid = m.group(2)
    ns2id[name] = nsid

links = {}
linklist = subprocess.check_output(["ip", "link", "show", "type", "veth"]).decode('utf-8').split('\n')
name = None
for linkline in linklist:
#5: v-eth1@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
#    link/ether d2:79:bc:a5:b1:6a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    if name is None:
        m = re.search('^[0-9]+: (\S+)@', linkline)
        if m:
            name = m.group(1)
    else:
        m = re.search('link-netnsid ([0-9]+)', linkline)
        if m:
            nsid = m.group(1)
            links[nsid] = name
            name = None
rules = subprocess.check_output(["iptables-save", "-t", "filter"]).decode('utf-8').split('\n')
#-A FORWARD -i enp0s25 -o v-eth2 -j ACCEPT
#-A FORWARD -o enp0s25 -i v-eth2 -j ACCEPT

# the namespaces left in the nsinodes map are those that need to be killed
# we now have enough informaton to do it
for ns in nsinodes:
    nsname = nsinodes[ns]
    if not nsname in ns2id:
        # apparently no links
        subprocess.run(['ip', 'netns', 'del', nsname])
        continue
    nsid = ns2id[nsname]
    if not nsid in links:
        subprocess.run(['ip', 'netns', 'del', nsname])
        continue
    linkname = links[nsid]
    for rule in rules:
        #-A FORWARD -i v-eth1 -o enp0s25 -j ACCEPT
        if rule.find(linkname) > 0:
            command = ['iptables', '-D']
            command.extend(shlex.split(rule[2:]))
            subprocess.run(command)
    subprocess.run(['ip', 'link', 'del', linkname])
    subprocess.run(['ip', 'netns', 'del', nsname])
    





  
  





