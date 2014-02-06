#!/bin/bash

if [ "x$HAVE_IPSET" == "x1" ]; then
  if [ -d $CONFIGDIR/groups/ipset ]; then
    find $CONFIGDIR/groups/ipset -maxdepth 1 -type d -name 'ipset*' | 
    while read ipsetdir; do
      ipsetname=${ipsetdir##$CONFIGDIR/groups/ipset-}
      if [ -e $ipsetdir/setup ]; then
        ipset create -exist $ipsetname $(cat $ipsetdir/setup)
        dummy=$(ipset -L $ipsetname | 
          while read a b; do
            if [ x$a == "xType:" ]; then
              echo ${b#*:}
            fi
          done
        )
      else
        echo "Please add '$ipsetdir/setup'" | tee -a $LOGSTARTUP
      fi
    done
  fi
fi
