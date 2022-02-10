#!/bin/bash

# Kill kerberos credential caches that are no longer active.
# Renew the ones that need renewing.

# Have to process KEYRING:persistent and files in /tmp differently

if test "$1" = "-d"; then
    DEBUG="echo"
else
    DEBUG=""
fi

#### functions common to all credential cache types

# checkrenew - see if a ccache needs renewing
#   it does if it's reached half its life
# argument is cc name
# returns 1 or 0 in renew
function checkrenew() {
   local date ccstart ccend lifetime renewtime now

   date=`sudo -n -u "$2" klist -c "$1"|grep "krbtgt/CS.RUTGERS.EDU@CS.RUTGERS.EDU"`
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

   date=`sudo -n -u "$2" klist -c "$1"|grep "krbtgt/CS.RUTGERS.EDU@CS.RUTGERS.EDU"`
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

function checkprincipal() {
   local date ccstart ccend lifetime renewtime now

   ccprin=`sudo -n -u "$2" klist -c "$1" | grep "Default principal" | egrep -o '[^ ]+@CS.RUTGERS.EDU'`

   if test "$ccprin" = "$2@CS.RUTGERS.EDU"; then
      ok=1
   else
      ok=0
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
if test -n "$DEBUG"; then
    echo ${!loggedin[@]}
fi

#### handle KEYRING caches

CACHETYPE=`grep '^ *default_ccache_name' /etc/krb5.conf | egrep -o '=.*$' | egrep -o '[^= ]+'`

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

# echo ${!keyusers[@]}

function getkcmusers() {
   while read uid; do
      keyusers[$uid]=1
   done < <(strings /var/lib/sss/secrets/secrets.ldb | awk '/cn=ccache,cn=[0-9]+,.*,cn=kcm$/{print gensub("^.*cn=ccache,cn=([0-9]*).*$","\\1",1)}')
}

if test "$CACHETYPE" = "KCM:"; then
    getkcmusers
else
    getkeyusers
fi
    
if test -n "$DEBUG"; then
    echo ${!keyusers[@]}
fi

### main processing loop

# look at all users who might have keyrings
# and process their ccaches appropriately

for uid in "${!keyusers[@]}"
do
echo checking uid $uid
   # don't do anything to root
   if test "$uid" -eq 0; then
     continue
   fi

   # use klist -l to list all ccaches for uid
   # klist -l needs KRB5CCNAME set. -c doesn't work in a few cases
   if test "$CACHETYPE" = "KCM:"; then
       export KRB5CCNAME="KCM:"
   else
       export KRB5CCNAME=KEYRING:persistent:"${uid}"
   fi

   if test -n "$DEBUG"; then
       echo $KRB5CCNAME
   fi

   # get username for this uid
   uname=`getent passwd "$uid" | cut -d: -f1`

   if test -n "${loggedin[$uid]}"; then
      # user has active processes. renew any ccaches that need it

      # use klist -l to list their actual credentials
      while read ccname; do
         echo check logged in $ccname
	  # check if expired
         checkexpired "$ccname" "$uname"
	 if test "$expired" -eq 1; then
	     $DEBUG logger -p user.debug -t renewd "destroy sudo -n -u $uname kdestroy -R -c $ccname"  
	     $DEBUG logger -p user.info -t renewd "destroy expired cache $ccname"  
	    # kinit -R will renew a cache
	     echo sudo -n -u "$uname" kdestroy -c "$ccname"  
	     $DEBUG sudo -n -u "$uname" kdestroy -c "$ccname"  
            continue
         fi

	 # if the pricipal isn't user@CS.RUTGERS.EDU, dont consider renewing
	 checkprincipal "$ccname" "$uname"
	 if test "$ok" -eq 0; then
	     echo cache has wrong principal, ignoring
	     continue
	 fi

	 # if time to renew, do so
         checkrenew "$ccname" "$uname"
         if test "$renew" -eq 1; then
	     $DEBUG logger -p user.debug -t renewd "sudo -n -u $uname kinit -R -c $ccname"  
	     $DEBUG logger -p user.info -t renewd "renewing cache $ccname"  
	    # kinit -R will renew a cache
	     echo sudo -n -u "$uname" kinit -R -c "$ccname"  
	     $DEBUG sudo -n -u "$uname" kinit -R -c "$ccname"  
	 else
	     $DEBUG logger -p user.debug -t renewd "not time to renew yet $ccname"
         fi
      done < <( sudo -n -u "$uname" klist -l | tail -n +3 | awk '{print $2}' )
   else
      if test -n "$DEBUG"; then
          echo not logged in $uid
      fi
      # not logged in, so kill all their keys

      # do they actually have any keys?
      # this is worth doing because sudo takes .1 sec.
      # on the big systems there can be 1000 key tables, mostly empty
      # so checking this first speeds things up

      # tail gets rid of the header
      # list all ccaches for this user. KRB5CCNAME was set above to the uid
      creds=`sudo -n -u "$uname" klist -l | tail -n +3`
      if test -z "$creds"; then
         echo no creds for "$uid"
         continue
      fi

      $DEBUG logger -p user.info -t renewd "Deleted old cache $uname"
      # kdestroy -A kills all caches for collection in KRB5CCNAME
      # | true suppresses messages about seg faults
      $DEBUG sudo -n -u "$uname" kdestroy -A | true
   fi
done



#### handle caches in /tmp

# all temp file actually in use 
# tempccs is indexed by file name
# look for all files listed as KRB5CCNAME for some process
declare -A tempccs
/proc/*/environ | tr '\000' '\n'| egrep -soh 'KRB5CCNAME=.*' | egrep -o '/tmp/krb5cc.*'
function gettempinuse() {
   while read file; do
       # by doing egrep -i /tmp/krb5cc.*, we ignore any FILE: prefix
       # so we always have a file name
       tempccs["$file"]=1
   done < <(cat /proc/*/environ | tr '\000' '\n'| egrep -soh 'KRB5CCNAME=.*' | egrep -o '/tmp/krb5cc.*')
}

gettempinuse
if test -n "$DEBUG"; then
    echo tempccs ${!tempccs[@]}
fi

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
   echo checking $ccname
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
      echo "Deleted cache not in use  $ccname"
      logger -p user.info -t renewd "Deleted cache not in use $ccname"
      rm "$ccname"
      continue
   fi
   echo inuse

   # if we get here, the ccache is in use. But might
   # still be expired
   # if ccache is expired we can't do anything, so kill it
   # (not needed for keyring, as it removes expired cc's)
   checkexpired "$ccname" "$uname"
   if test "$expired" -eq 1; then
      echo "Deleted old cache $ccname"
      logger -p user.info -t renewd "Deleted old cache $ccname"
      rm "$ccname"
      continue
   fi

   # if the pricipal isn't user@CS.RUTGERS.EDU, dont consider renewing
   checkprincipal "$ccname" "$uname"
   if test "$ok" -eq 0; then
       echo cache has wrong principal, ignoring
       continue
   fi

   # no need to see if user is logged in, since
   # only ccaches in use by someone get to here
   checkrenew "$ccname" "$uname"
   if test "$renew" -eq 1; then
      logger -p user.info -t renewd "renewing cache $ccname"  
      echo sudo -n -u "$uname" kinit -R -c "$ccname"  
      sudo -n -u "$uname" kinit -R -c "$ccname"  
   else
      logger -p user.debug -t renewd "not time to renew yet $ccname"
   fi

done






