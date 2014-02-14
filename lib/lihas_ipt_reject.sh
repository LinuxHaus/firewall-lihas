#!/bin/bash

lihas_ipt_rejectclients () {
  snet=$1
  dnet=$2
  proto=$3
  dport=$4
  oiface=$5
  if [ "$snet" == "include" ]; then
    if [ -e "$dnet" ]; then
      cat $dnet | helper_hostgroup | helper_portgroup | helper_dns | sed '/^[ \t]*$/d; /^#/d' |
      while read snet dnet proto dport oiface; do
        lihas_ipt_rejectclients "$snet" "$dnet" "$proto" "$dport" "$oiface"
      done
    else
      echo "$snet doesn't exist"
    fi
  else
    if [ $dport == "0" ]; then
      if [ "ga$oiface" == "ga" ]; then
        IPT_FILTER "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto -j REJECT"
        IPT_FILTER "-A in-$iface -m state --state new -s $snet -d $dnet -p $proto -j REJECT"
      else
        IPT_FILTER "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto -o $oiface -j REJECT"
      fi
    else
      if [ "ga$oiface" == "ga" ]; then
        if [ $proto == "icmp" ]; then
          IPT_FILTER "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --icmp-type $dport -j REJECT"
          IPT_FILTER "-A in-$iface -m state --state new -s $snet -d $dnet -p $proto --icmp-type $dport -j REJECT"
        else 
          IPT_FILTER "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --dport $dport -j REJECT"
          IPT_FILTER "-A in-$iface -m state --state new -s $snet -d $dnet -p $proto --dport $dport -j REJECT"
        fi
      else
        if [ $proto == "icmp" ]; then
          IPT_FILTER "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --icmp-type $dport -o $oiface -j REJECT"
        else 
          IPT_FILTER "-A fwd-$iface -m state --state new -s $snet -d $dnet -p $proto --dport $dport -o $oiface -j REJECT"
        fi
      fi
    fi
  fi
}

