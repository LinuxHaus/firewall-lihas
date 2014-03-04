lihas_ipt_dnat () {
  chain=$1
  dnet=$2
  mnet=$3
  proto=$4
  dport=$5
  ndport=$6
  if [ $dnet == "include" ]; then
    if [ -e $mnet ]; then
      cat $mnet | helper_hostgroup | helper_portgroup | helper_dns | sed '/^[ \t]*$/d; /^#/d' |
      while read dnet mnet proto dport ndport; do
        lihas_ipt_dnat "$chain" "$dnet" "$mnet" "$proto" "$dport" "$ndport"
      done
    else
      echo "$mnet doesn't exist"
    fi
  else
    if [ $dnet == ACCEPT ]; then
      if [ $dport == "0" ]; then
        IPT_NAT "-A $chain -s $mnet -p $proto -j ACCEPT"
      else
        if [ $proto == "icmp" ]; then
          IPT_NAT "-A $chain -s $mnet -p $proto --icmp-type $dport -j ACCEPT"
        else
          IPT_NAT "-A $chain -s $mnet -p $proto --dport $dport -j ACCEPT"
        fi
      fi
    else
      if [ $dport == "0" ]; then
        IPT_NAT "-A $chain -d $dnet -p $proto -j DNAT --to-destination $mnet"
      else
        ndport=${ndport//:/-}
        if [ $proto == "icmp" ]; then
          IPT_NAT "-A $chain -d $dnet -p $proto --icmp-type $dport -j DNAT --to-destination $mnet:$ndport"
        else
          IPT_NAT "-A $chain -d $dnet -p $proto --dport $dport -j DNAT --to-destination $mnet:$ndport"
        fi
      fi
    fi
  fi
}
