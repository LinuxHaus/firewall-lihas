portal_ipt_privclients () {
  # TODO: join with lihas_ipt_privclients 
  chain=$1
  snet=$2
  dnet=$3
  proto=$4
  dport=$5
  oiface=$6
  if [ "$snet" == "include" ]; then
    if [ -e "$dnet" ]; then
      cat $dnet | helper_hostgroup | helper_portgroup | helper_dns | sed '/^[ \t]*$/d; /^#/d' |
      while read snet dnet proto dport oiface; do
        portal_ipt_privclients "$chain" "$snet" "$dnet" "$proto" "$dport" "$oiface"
      done
    else
      echo "$snet doesn't exist"
    fi
  else
    if [ $dport == "0" ]; then
      if [ "ga$oiface" == "ga" ]; then
        IPT_FILTER "-A $chain $CONNSTATE NEW -s $snet -d $dnet -p $proto -j ACCEPT"
      else
        IPT_FILTER "-A $chain $CONNSTATE NEW -s $snet -d $dnet -p $proto -o $oiface -j ACCEPT"
      fi
    else
      if [ "ga$oiface" == "ga" ]; then
        if [ $proto == "icmp" ]; then
          IPT_FILTER "-A $chain $CONNSTATE NEW -s $snet -d $dnet -p $proto --icmp-type $dport -j ACCEPT"
        else
          IPT_FILTER "-A $chain $CONNSTATE NEW -s $snet -d $dnet -p $proto --dport $dport -j ACCEPT"
        fi
      else
        if [ $proto == "icmp" ]; then
          IPT_FILTER "-A $chain $CONNSTATE NEW -s $snet -d $dnet -p $proto --icmp-type $dport -o $oiface -j ACCEPT"
        else
          IPT_FILTER "-A $chain $CONNSTATE NEW -s $snet -d $dnet -p $proto --dport $dport -o $oiface -j ACCEPT"
        fi
      fi
    fi
  fi
}

portal_setup () {
  if [ -d $CONFIGDIR/feature/portal ]; then
    if [ "x$HAVE_IPSET" != "x1" ]; then
      echo "WARNING: Captive Portals need ipset Support. Remove $CONFIGDIR/feature/portal to disable this message" | tee -a $LOGSTARTUP
    else
      find $CONFIGDIR/feature/portal -mindepth 1 -maxdepth 1 -type d |
      while read portalname; do
        portalname=${portalname##$CONFIGDIR/feature/portal/}
        if [ ! -e $CONFIGDIR/feature/portal/$portalname/ipset-name ]; then
          echo "Captive Portal $portalname needs $CONFIGDIR/feature/portal/$portalname/ipset-name" | tee -a $LOGSTARTUP
        elif ! ipset list $(sed '/^[ \t]*$/d; /^#/d' < $CONFIGDIR/feature/portal/$portalname/ipset-name); then
          # name of used ipset
          echo "Captive Portal $portalname needs $CONFIGDIR/groups/ipset/ipset-$(sed '/^[ \t]*$/d; /^#/d' < $CONFIGDIR/feature/portal/$portalname/ipset-name)" | tee -a $LOGSTARTUP
        elif [ ! -e $CONFIGDIR/feature/portal/$portalname/interfaces ]; then
          # 1 line per interface
          echo "Captive Portal $portalname needs $CONFIGDIR/feature/portal/$portalname/interfaces to know what interface to watch" | tee -a $LOGSTARTUP
        else
          IPT_FILTER ":portal-$portalname -"
          IPT_FILTER "-A portal-$portalname -m set --match-set $(sed '/^[ \t]*$/d; /^#/d' < $CONFIGDIR/feature/portal/$portalname/ipset-name) src,src -j RETURN"
  	  # privclients from portal configuration
          if [ ! -e $CONFIGDIR/feature/portal/$portalname/privclients ]; then
            echo "WARNING: Captive Portals unknown clients won't have access anywhere. Use $CONFIGDIR/feature/portal/$portalname/privclients to disable this message" | tee -a $LOGSTARTUP
          else
  	    cat $CONFIGDIR/feature/portal/$portalname/privclients | helper_hostgroup | helper_portgroup | helper_dns | sed '/^[ \t]*$/d; /^#/d' |
  	    while read snet dnet proto dport oiface; do
                portal_ipt_privclients "portal-$portalname" "$snet" "$dnet" "$proto" "$dport" "$oiface"
  	    done
          fi
          IPT_FILTER "-A portal-$portalname -j REJECT"
          cat $CONFIGDIR/feature/portal/$portalname/interfaces | sed '/^[ \t]*$/d; /^#/d' |
          while read iface; do
            IPT_FILTER "-A FORWARD -i $iface -j portal-$portalname"
            IPT_FILTER "-A INPUT -i $iface -j portal-$portalname"
          done
          if [ ! -e $CONFIGDIR/feature/portal/$portalname/dnat ]; then
            # new target for unknown clients, works like dnat
            echo "WARNING: Captive Portals unknown clients won't be redirected anywhere. Use $CONFIGDIR/feature/portal/$portalname/dnat to disable this message" | tee -a $LOGSTARTUP
          else
            IPT_NAT    ":portal-$portalname -"
            IPT_NAT    "-A portal-$portalname -m set --match-set $(sed '/^[ \t]*$/d; /^#/d' < $CONFIGDIR/feature/portal/$portalname/ipset-name) src,src -j RETURN"
  	    cat $CONFIGDIR/feature/portal/$portalname/dnat | helper_hostgroup | helper_portgroup | helper_dns | sed '/^[ \t]*$/d; /^#/d' |
            while read dnet mnet proto dport ndport; do
              lihas_ipt_dnat "portal-$portalname" "$dnet" "$mnet" "$proto" "$dport" "$ndport"
            done
            IPT_NAT    "-A portal-$portalname -j RETURN"
            cat $CONFIGDIR/feature/portal/$portalname/interfaces | sed '/^[ \t]*$/d; /^#/d' |
            while read iface; do
              IPT_NAT    "-A PREROUTING -i $iface -j portal-$portalname"
            done
          fi
        fi
      done
    fi
  fi
}
