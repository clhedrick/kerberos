#!/bin/bash

# Kill kerberos credential caches that are no longer active.
# Renew the ones that need renewing.

# Have to process KEYRING:persistent and files in /tmp differently

#### functions common to all credential cache types

# checkrenew - see if a ccache needs renewing
#   it does if it's reached half its life
# argument is cc name
# returns 1 or 0 in renew
function checkrenew() {
   local date ccstart ccend lifetime renewtime now

   date=`klist -c "$1"|grep "krbtgt/CS.RUTGERS.EDU@CS.RUTGERS.EDU"`
   # get first two items from 
   # 01/26/2022 15:03:37  01/26/2022 22:52:16  krbtgt/CS.RUTGERS.EDU@CS.RUTGERS.EDU
   ccstart=`echo "$date" | awk '{print $1 " " $2}' `
   # convert to Unix date, seconds fron epoch
   ccstart=`date +'%s' -d "$ccstart"`
   # same for end
   ccend=`echo $date | awk '{print $3 " " $4}'`
   ccend=`date +'%s' -d "$ccend"`

   # ccstart and end are now start and end of ticket in Unix times
   lifetime=$(($ccend - $ccstart))
   # we start renewing at half its lifetime from the start
   renewtime=$(($ccstart + ($lifetime/2) ))
   # now in same units
   now=`date +%s`

   if test "$now" -ge "$renewtime"; then
      renew=1
   else
      renew=0
   fi
}

#checkrenew "KEYRING:persistent:1003"
#echo $ccstart $ccend $lifetime $renewtime $now $renew

# see if a credential cache has expired 
# this can only happen for ccaches in /tmp
# the keyring automatically kills expired ccaches

function checkexpired() {
   local date ccstart ccend lifetime renewtime now

   date=`klist -c "$1"|grep "krbtgt/CS.RUTGERS.EDU@CS.RUTGERS.EDU"`
   # expiration time as 01/26/2022 22:52:16
   ccend=`echo $date | awk '{print $3 " " $4}'`
   # expiration time in unix seconds since epoch
   ccend=`date +'%s' -d "$ccend"`

   now=`date +%s`

   # if ticket end is in the past, it's expired
   if test "$now" -ge "$ccend"; then
      expired=1
   else
      expired=0
   fi
}

# loggedin is array loggedin[uid] is 1 if user is logged in
declare -a loggedin

# get all users with processes
function getloggedin() {
   while read uid; do
     loggedin[$uid]=1
   done < <(grep Uid: /proc/[0-9]*/status | awk '{print $2}' )
}

getloggedin
#echo ${!loggedin[@]}

#### handle KEYRING caches

# has an entry for all uids with keyrings
declare -a keyusers

# This is all the users using kernel keyrings.
# They are not necessarily krb5 credentials,
# but this is all users who might have krb5 keyrings
function getkeyusers() {
   while read uid; do
      keyusers[$uid]=1
   done < <(cat /proc/key-users | cut -d: -f1)
}

getkeyusers
# echo ${!keyusers[@]}


### main processing loop

# look at all users who might have keyrings
# and process their ccaches appropriately

for uid in "${!keyusers[@]}"
do
   # don't do anything to root
   if test "$uid" -eq 0; then
     continue
   fi

   # use klist -l to list all ccaches for uid
   # klist -l needs KRB5CCNAME set. -c doesn't work in a few cases
   export KRB5CCNAME=KEYRING:persistent:"${uid}"

   # get username for this uid
   uname=`getent passwd "$uid" | cut -d: -f1`

   if test -n "${loggedin[$uid]}"; then
      # user has active processes. renew any ccaches that need it

      # use klist -l to list their actual credentials
      while read ccname; do
	 # if time to renew, do so
         checkrenew "$ccname"  
         if test "$renew" -eq 1; then
            logger -p user.debug -t renew sudo -n -u "$uname" kinit -R -c "$ccname"  
            logger -p user.info -r renewd renewing cache "$ccname"  
	    # kinit -R will renew a cache
	    sudo -n -u "$uname" kinit -R -c "$ccname"  
	 else
            logger -p user.debug -t renewd "not time to renew yet $ccname"
         fi
      done < <( sudo -n -u "$uname" klist -l | tail -n +3 | awk '{print $2}' )
   else
      # not logged in, so kill all their keys

      # do they actually have any keys?
      # this is worth doing because sudo takes .1 sec.
      # on the big systems there can be 1000 key tables, mostly empty
      # so checking this first speeds things up

      # tail gets rid of the header
      # list all ccaches for this user. KRB5CCNAME was set above to the uid
      creds=`klist -l | tail -n +3`
      if test -z "$creds"; then
#         echo no creds for "$uid"
         continue
      fi

      logger -p user.info -t renewd Deleted old cache "$uname"
      # kdestroy -A kills all caches for collection in KRB5CCNAME
      # | true suppresses messages about seg faults
      sudo -n -u "$uname" kdestroy -A | true
   fi
done



#### handle caches in /tmp

# all temp file actually in use 
# tempccs is indexed by file name
# look for all files listed as KRB5CCNAME for some process
declare -A tempccs
function gettempinuse() {
   while read file; do

       # by doing egrep -i /tmp/krb5cc.*, we ignore any FILE: prefix
       # so we always have a file name

       tempccs["$file"]=1
   done < <(egrep -sohz 'KRB5CCNAME=.*' /proc/*/environ | egrep -o '/tmp/krb5cc.*')
}

gettempinuse

# see if this temp file is in use

function checktempused() {
   local file

   file="$1"

   if test -n "${tempccs[$file]}"; then
       inuse=1
   else
       inuse=0
   fi
}


### main processing loop

# process all ccaches in temp
# just look at files we might produce
# if a user does their own kinit they're on their own
for ccname in /tmp/krb5cc*
do
   # see who owns the file
   uid=`stat -c '%u' "$ccname"`

   # leave root alone
   if test "$uid" -eq 0; then
     continue
   fi

   # get username for this uid
   uname=`getent passwd "$uid" | cut -d: -f1`

   # if ccache isn't in use, kill it
   checktempused "$ccname"
   if test "$inuse" -eq 0; then
      # not in use by any process. kill it
      logger -p user.info -t renewd Deleted old cache "$ccname"
      rm "$ccname"
      continue
   fi

   # if we get here, the ccache is in use. But might
   # still be expired
   # if ccache is expired we can't do anything, so kill it
   # (not needed for keyring, as it removes expired cc's)
   checkexpired "$ccname"
   if test "$expired" -eq 1; then
      logger -p user.info -t renewd Deleted old cache "$ccname"
      rm "$ccname"
      continue
   fi

   # no need to see if user is logged in, since
   # only ccaches in use by someone get to here
   checkrenew "$ccname"  
   if test "$renew" -eq 1; then
      logger -p user.info -t renewd renewing cache "$ccname"  
      sudo -n -u "$uname" kinit -R -c "$ccname"  
   else
      logger -p user.debug -t renewd "not time to renew yet $ccname"
   fi

done






