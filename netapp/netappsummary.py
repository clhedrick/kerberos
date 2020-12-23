#!/koko/system/anaconda/envs/python38/bin/python

import json
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

userpass=''
descriptions={}

# file starts with user:pass pairs, appropriate for http auth
# then sections. currently the only one is [qtrees]
# firtsection means we're still in the beginning. It ends
#   at the first section break
# insection means we're in [qtree]. It ends at the next
#   section break, and at that point no more parsing is needed

with open ("/etc/netapp.conf", "r") as myfile:
   insection = False
   firstsection = True

   for line in myfile:
      line = line.strip()
      if line == '[qtrees]':
         firstsection = False
         insection = True
         continue

      # at section marker, terminate current section
      if line.startswith('['):
         if insection:
            break
         else:
            firstsection = False

      if firstsection:
         if line.startswith('getstats:'):
            userpass = line

      if insection:
         items = line.split('=', 1)
         if len(items) == 2:
            descriptions[items[0]] = items[1]

if userpass != '':
   up = userpass.split(':', 1)
   userpass = (up[0], up[1])

print ("""
<!doctype html>
<html lang="en">
<head><link href="usertool.css" rel="stylesheet" type="text/css">
<title> Netapp Usage</title>
<style type="text/css">
tr:nth-child(odd) {background-color: #eee;}
td,th {padding: 2px 5px}
#main {max-width:45em}
</style>

</head>
<div id="masthead"></div>
<div id="main">
<h1>Netapp Usage</h1>
<h2>Aggregates</h2>

<p> The following table reflects the physical disks used as well as the user and snapshot space usage on each aggregate defined. System aggregates are not included. Sizes are in GB.

<table>
<tr>
<th>Name
<th>Size
<th>Used
<th>Avail
<th>Disks
<th>Raid
<th>Disk type
""")

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

gb = 1024 * 1024 * 1024

r = requests.get('https://cluster.lcsr.rutgers.edu/api/storage/aggregates?fields=space,block_storage', auth=userpass, verify=False)
if r.status_code != 200:
   print (f'get failed status {r.status_code}')
   sys.exit(1)

root = r.json()

def sortName(val): 
    return val["name"]

records = root['records']
records.sort(key = sortName)
for ag in records:
   agname = ag['name']
   size = int(ag['space']['block_storage']['size'] / gb)
   avail = int(ag['space']['block_storage']['available'] /gb)
   used = int(ag['space']['block_storage']['used'] / gb)
   disks = ag['block_storage']['primary']['disk_count']
   raid = ag['block_storage']['primary']['raid_type']
   disktype = ag['block_storage']['primary']['disk_type']
   cachecount = ag['block_storage']['hybrid_cache']['disk_count']
   cacheraid = ag['block_storage']['hybrid_cache']['raid_type']
   cachesize = int(ag['block_storage']['hybrid_cache']['size'] / gb)
   cacheused = int(ag['block_storage']['hybrid_cache']['used'] / gb)

   print(f'<tr>'
         f'<td>{agname}'
         f'<td>{size}'
         f'<td>{used}'
         f'<td>{avail}'
         f'<td>{disks}'
         f'<td>{raid}'
         f'<td>{disktype}'
         f'\n<tr>'
         f'<td>cache'
         f'<td>{cachesize}'
         f'<td>{cacheused}'
         f'<td>{cachesize - cacheused}'
         f'<td>{cachecount}'
         f'<td>SSD'
         f'<td>{cacheraid}'
         )

print("""</table>

<h2>Volumes</h2>

<p>The following table reflects the user and snapshot space usage on each volume defined.

<table>
<tr>
<th rowspan=2>Volume
<th colspan=4>Usage (GB)
<th colspan=4>Snapshots(GB)
<tr>
<th>Total
<th>Used
<th>Avail
<th>Pct(%)
<th>Total
<th>Used
<th>Avail
<th>Pct(%)
""")

r = requests.get('https://cluster.lcsr.rutgers.edu/api/storage/volumes?fields=space', auth=userpass, verify=False)
if r.status_code != 200:
   print (f'get failed status {r.status_code}')
   sys.exit(1)
root = r.json()

records = root['records']
records.sort(key = sortName)
for vol in records:
   volname = vol["name"]

   snaprsvd = vol["space"]["snapshot"]["reserve_percent"]
   volspace = vol["space"]["size"] * ( 1 - (snaprsvd/100.0) )
   volused = vol["space"]["used"]
   volavail = vol["space"]["available"]
   volpct = (volused * 100.0) / volspace
   snapspace = vol["space"]["size"] * (snaprsvd/100.0)
   snapused = vol["space"]["snapshot"]["used"]
   snapavail = snapspace - snapused
   if snapavail < 0:
      snapavail = 0;
   snappct = (snapused * 100.0) / snapspace

   print(f'<tr>'
         f'<td>{vol["name"]}'
         f'<td>{int(volspace / gb)}'
         f'<td>{int(volused / gb)}'
         f'<td>{int(volavail / gb)}'
         f'<td>{int(volpct)}'
         f'<td>{int(snapspace / gb)}'
         f'<td>{int(snapused / gb)}'
         f'<td>{int(snapavail / gb)}'
         f'<td>{int(snappct)}'
         )

print("""</table>

<h2> Qtrees</h2>

<p>The following table reflects what qtrees reside on which volumes, any quotas in effect for those qtrees, and a brief description of the usage of each qtree.

<table>
<tr>
<th colspan=7>Qtrees by volume
<tr>
<th>Volume
<th>Qtree
<th>Quota
<th>Used
<th>Avail
<th>Pct
<th>Description
""")

r = requests.get('https://cluster.lcsr.rutgers.edu/api/storage/quota/reports?type=tree&fields=space,qtree&return_timeout=120', auth=userpass, verify=False)
if r.status_code != 200:
   print (f'get failed status {r.status_code}')
   sys.exit(1)
root = r.json()

def sortQName(val): 
    return f'{val["volume"]["name"]} {val["qtree"]["name"]}'

records = root['records']
records.sort(key = sortQName)
lastvol = ''
for q in records:
   vol = q["volume"]["name"]
   qtree = q["qtree"]["name"]
   quota = int(q["space"]["hard_limit"] / gb) if 'hard_limit' in q['space'] else '-'
   used = int(q["space"]["used"]["total"] / gb)
   avail = int((q["space"]["hard_limit"] - q["space"]["used"]["total"]) / gb) if 'hard_limit' in q['space'] else '-'
   percent = int(q["space"]["used"]["total"] * 100.0 / q["space"]["hard_limit"]) if 'hard_limit' in q['space'] else '-'
   if qtree in descriptions:
      desc = descriptions[qtree]
   else:
      desc = ''
   if qtree != "":
      if vol != lastvol:
         volout = vol
         lastvol = vol
      else:
         volout = ''
      print(f'<tr>'
            f'<td>{volout}'
            f'<td>{qtree}'
            f'<td>{quota}'
            f'<td>{used}'
            f'<td>{avail}'
            f'<td>{percent}'
            f'<td>{desc}'
            )

print(f'</table>'
      f''
      f'<p>This page last updated {datetime.now()}'
      f'</body>'
      f'</html>'
      )
