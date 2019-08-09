#!/usr/bin/python3

import re
import subprocess
import os
import sys

if len(sys.argv) < 2:
  print('usage: create.py UID')
  exit(1)

uid = sys.argv[1]

# create net name space and set it up for loopback and NAT to the Internet
# arg1: user

# see what is in use
nslist = subprocess.check_output(["ip", "netns"]).decode('utf-8').split('\n')
nsmax = 0
for nsline in nslist:
  m = re.search('^ns([0-9]+)', nsline)
  if m:
     nsnumber = int(m.group(1))
     if nsnumber > nsmax:
       nsmax = nsnumber

nsnum = nsmax + 1

# in case of race condition, next ns could already exist
# try up to 20 times
nslimit = nsnum + 20
while nsnum < nslimit:
  try:
     subprocess.check_output(['ip', 'netns', 'add', f'ns{nsnum}'],stderr=subprocess.DEVNULL)
     # worked, we're done
     break
  except subprocess.CalledProcessError:
     print(f"failed {nsnum}, retrying")
     nsnum = nsnum + 1

if nsnum == nslimit:
  print('unable to create network namespace')
  exit(1)

# claim the namespace for this user

if not os.path.exists(f'/var/run/user/{uid}'):
    os.makedirs(f'/var/run/user/{uid}')
    os.chown(f'/var/run/user/{uid}', int(uid), -1)
    os.chmod(f'/var/run/user/{uid}', 0o700)
os.symlink(f'/run/netns/ns{nsnum}', f'/var/run/user/{uid}/netnamespace')

# now see highest ip in use
iplist = subprocess.check_output(['ip', 'addr', 'show', 'type', 'veth']).decode('utf-8').split('\n')
# first address is 10.200.1.2
addrmax = 258
for ipline in iplist:
  m = re.search('inet 10.200.([0-9]+)\\.([0-9]+)/', ipline)
  if m:
     high = int(m.group(1))
     low = int(m.group(2))
     addr = high * 256 + low
     if addr > addrmax:
       addrmax = addr

# must be even or routing fails
if addrmax % 2 == 1:
  addrmax = addrmax +1
address = addrmax + 2
first_high = address // 256
first_low = address % 256
second_high = (address+1) // 256
second_low = (address+1) % 256
first = f'10.200.{first_high}.{first_low}'
second = f'10.200.{second_high}.{second_low}'

# need a network device for nat
# use the one associated with default route
# default via 128.6.157.129 dev ens32
routes = subprocess.check_output(['ip', 'route']).decode('utf-8').split('\n')
for route in routes:
  if route.startswith('default '):
    m = re.search(' dev (\S+)', route)
    if m:
      dev = m.group(1)

filters = subprocess.check_output(['iptables-save']).decode('utf-8').split('\n')
nats = subprocess.check_output(['iptables-save','-t','nat']).decode('utf-8').split('\n')

subprocess.check_output(['ip','netns','exec',f'ns{nsnum}','ip','link','set','dev','lo','up'])
subprocess.check_output(['ip','link','add',f'v-eth{nsnum}','type','veth','peer','name',f'v-peer{nsnum}'])
subprocess.check_output(['ip','link','set',f'v-peer{nsnum}','netns',f'ns{nsnum}'])
subprocess.check_output(['ip','addr','add',f'{first}/31','dev',f'v-eth{nsnum}'])
subprocess.check_output(['ip','link','set',f'v-eth{nsnum}','up'])
subprocess.check_output(['ip','netns','exec',f'ns{nsnum}','ip','addr','add',f'{second}/31','dev',f'v-peer{nsnum}'])
subprocess.check_output(['ip','netns','exec',f'ns{nsnum}','ip','link','set',f'v-peer{nsnum}','up'])
subprocess.check_output(['ip','netns','exec',f'ns{nsnum}','ip','route','add','default','via',f'{first}'])
subprocess.check_output(['bash','-c','echo 1 >/proc/sys/net/ipv4/ip_forward'])
subprocess.check_output(['iptables','-I','FORWARD','-i',dev,'-o',f'v-eth{nsnum}','-j','ACCEPT'])
subprocess.check_output(['iptables','-I','FORWARD','-o',dev,'-i',f'v-eth{nsnum}','-j','ACCEPT'])
# we need to work with both ubuntu and centos. Centos ends with drop-all, so it makes sense
# to insert at the beginning. However centos also has
# -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# we want to go after that if it's there
# so if we have -A INPUT ... ESTABLISHED, use the next index, else 1
newindex = 1
i = 1
for f in filters:
  if f.startswith('-A INPUT'):
      i = i + 1
      if 'ESTABLISHED' in f:
          newindex = i
          break
if '-A INPUT -s 10.200.0.0/16 -j ACCEPT' not in filters:
  subprocess.check_output(['iptables','-I','INPUT',str(newindex),'-s','10.200.0.0/16','-j','ACCEPT'])
if '-A INPUT -d 10.200.0.0/16 -j ACCEPT' not in filters:
  subprocess.check_output(['iptables','-I','INPUT',str(newindex),'-d','10.200.0.0/16','-j','ACCEPT'])
if f'-A POSTROUTING -s 10.200.0.0/16 -o {dev} -j MASQUERADE' not in nats:
  subprocess.check_output(['iptables','-t','nat','-I','POSTROUTING','-s','10.200.0.0/16','-o',dev,'-j','MASQUERADE'])

exit(0)




