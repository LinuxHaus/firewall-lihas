#!/bin/bash

lihas_ipt_rejectclients () {
  outfile=$1
  snet=$2
  dnet=$3
  proto=$4
  dport=$5
  oiface=$6
  if [ "$snet" == "include" ]; then
    if [ -e "$dnet" ]; then
      cat $dnet | helper_hostgroup | helper_portgroup | helper_dns | sed '/^[ \t]*$/d; /^#/d' |
      while read snet dnet proto dport oiface; do
        lihas_ipt_rejectclients "$outfile" "$snet" "$dnet" "$proto" "$dport" "$oiface"
      done
    else
      echo "$snet doesn't exist"
    fi
  else
    if [ $dport == "0" ]; then
      if [ "ga$oiface" == "ga" ]; then
        echo "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto -j ACCEPT" >> $outfile
        echo "-A in-$iface -m state --state new -s $snet -d $dnet -p $proto -j ACCEPT" >> $outfile
      else
        echo "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto -o $oiface -j ACCEPT" >> $outfile
      fi
    else
      if [ "ga$oiface" == "ga" ]; then
        if [ $proto == "icmp" ]; then
          echo "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --icmp-type $dport -j ACCEPT" >> $outfile
          echo "-A in-$iface -m state --state new -s $snet -d $dnet -p $proto --icmp-type $dport -j ACCEPT" >> $outfile
        else 
          echo "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --dport $dport -j ACCEPT" >> $outfile
          echo "-A in-$iface -m state --state new -s $snet -d $dnet -p $proto --dport $dport -j ACCEPT" >> $outfile
        fi
      else
        if [ $proto == "icmp" ]; then
          echo "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --icmp-type $dport -o $oiface -j ACCEPT" >> $outfile
        else 
          echo "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --dport $dport -o $oiface -j ACCEPT" >> $outfile
        fi
      fi
    fi
  fi
}

