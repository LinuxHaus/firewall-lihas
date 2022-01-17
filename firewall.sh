#!/bin/bash
### BEGIN INIT INFO
# Provides:          firewall
# Required-Start:    $local_fs
# Required-Stop:     $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: LiHAS Firewall
# Description:       Firewall
### END INIT INFO
# Author: Adrian Reyer <are@lihas.de>

# Do NOT "set -e"

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="LiHAS Firewall"
NAME=firewall
DAEMON=/bin/true
SCRIPTNAME=/etc/init.d/$NAME
CONFIGDIR=/etc/firewall.lihas.d
LIBDIR=/usr/lib/firewall-lihas
TMPDIR=${TMPDIR:-/tmp}
FEATURE_COUNTER=0

DATAPATH=/var/lib/firewall-lihas
DATABASE=$DATAPATH/db.sqlite
LOGSTARTUP=$TMPDIR/firewall-lihas-startup.log

# Default values
# TARGETLOG: LOG-Chain, mostly useful: LOG ULOG
TARGETLOG=LOG
# POLICYMETHOD: static bird
POLICYMETHOD=static

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Reset startup logfile
echo -n > $LOGSTARTUP

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

FILE=$TMPDIR/iptables
FILEraw=$TMPDIR/iptables-raw
FILEfilter=$TMPDIR/iptables-filter
FILEnat=$TMPDIR/iptables-nat
FILEmangle=$TMPDIR/iptables-mangle


if [ -e $CONFIGDIR/config.xml ]; then
  DATAPATH=$(xmlstarlet sel -t -v /applicationconfig/application/config/@db_dbd $CONFIGDIR/config.xml)
  DATABASE=$DATAPATH/db.sqlite
  FEATURE_COUNTER=$(xmlstarlet sel -t -v /applicationconfig/application/feature/counter/@enabled $CONFIGDIR/config.xml || echo -n ${FEATURE_COUNTER:-0})
fi

export CONFIGDIR LIBDIR TMPDIR FILE FILEraw FILEfilter FILEnat FILEmangle TARGETLOG DATABASE DATAPATH
if getent group www-data >/dev/null 2>&1; then
  mkdir -p "$DATAPATH"
  chgrp www-data $DATAPATH
  chmod g+w $DATAPATH
  touch $DATABASE
  chgrp www-data $DATABASE
  chmod g+w $DATABASE
fi

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

do_reload() {
        do_start
        return 0
}

do_start() {

ipt_cmd=0
ipt_err=0

set -a

[ -d "$CONFIGDIR" ] && cd "$CONFIGDIR"

rm $FILE $FILEfilter $FILEnat $FILEmangle $FILEraw
exec 4>$FILE 5>$FILEfilter 6>$FILEnat 7>$FILEmangle 8>$FILEraw

HAVE_COMMENT=0
HAVE_LOG=0
HAVE_ULOG=0
HAVE_IPSET=0
# check availability of modules:
iptables -N lihas-moduletest
iptables -A lihas-moduletest $CONNSTATE >/dev/null 2>&1
if iptables-save | egrep -q 'lihas-moduletest.*-m state'; then
  CONNSTATE="-m state --state"
else
  CONNSTATE="-m conntrack --ctstate"
fi
export CONNSTATE
iptables -A lihas-moduletest -m comment --comment "test" >/dev/null 2>&1
if [ $? -eq 0 ]; then
  HAVE_COMMENT=1
fi
iptables -A lihas-moduletest -j LOG --log-prefix 'test' >/dev/null 2>&1
if [ $? -eq 0 ]; then
  HAVE_LOG=1
fi
iptables -A lihas-moduletest -j ULOG --ulog-prefix 'test' >/dev/null 2>&1
if [ $? -eq 0 ]; then
  HAVE_ULOG=1
fi
iptables -A lihas-moduletest -j NFLOG --nflog-prefix 'test' >/dev/null 2>&1
if [ $? -eq 0 ]; then
  HAVE_NFLOG=1
fi
# check if ipset is available
if [ type -a ipset > /dev/null ]; then
  ipset create -exist lihas-moduletest bitmap:ip,mac range 127.0.0.0/24 >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    iptables -A lihas-moduletest -m set --match-set lihas-moduletest src,src >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      HAVE_IPSET=1
    fi
    iptables -F lihas-moduletest >/dev/null 2>&1
    ipset destroy lihas-moduletest
  fi
fi
iptables -F lihas-moduletest
iptables -X lihas-moduletest

# determine LOG target
if [ $TARGETLOG == "LOG" ] && [ $HAVE_LOG -eq 1 ]; then
  TARGETLOG=LOG
elif [ $TARGETLOG == "ULOG" ] && [ $HAVE_ULOG -eq 1 ]; then
  TARGETLOG=ULOG
elif [ $TARGETLOG == "NFLOG" ] && [ $HAVE_NFLOG -eq 1 ]; then
  TARGETLOG=NFLOG
elif [ $HAVE_LOG -eq 1 ]; then
  TARGETLOG=LOG
elif [ $HAVE_ULOG -eq 1 ]; then
  TARGETLOG=ULOG
elif [ $HAVE_NFLOG -eq 1 ]; then
  TARGETLOG=NFLOG
fi

export TARGETLOG HAVE_COMMENT HAVE_LOG HAVE_ULOG HAVE_IPSET
  
. $LIBDIR/helper-dns.sh
. $LIBDIR/helper-group.sh
. $LIBDIR/ipset-setup.sh
. $LIBDIR/iptables-wrapper.sh
. $LIBDIR/feature-portal.sh

for chain in INPUT OUTPUT FORWARD; do
  IPT_FILTER ":$chain DROP"
done
for chain in PREROUTING POSTROUTING OUTPUT; do
  IPT_NAT ":$chain ACCEPT"
done
for chain in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do
  IPT_MANGLE ":$chain ACCEPT"
done

for iface in interface-*; do
  iface=${iface#interface-}
  IPT_FILTER ":in-$iface -"
  IPT_FILTER ":out-$iface -"
  IPT_FILTER ":fwd-$iface -"
  IPT_FILTER ":dns-in-$iface -"
  IPT_FILTER ":dns-out-$iface -"
  IPT_FILTER ":dns-fwd-$iface -"

  IPT_NAT ":pre-$iface -"
  IPT_NAT ":post-$iface -"
  IPT_NAT ":dns-pre-$iface -"
  IPT_NAT ":dns-post-$iface -"
done
if [ $FEATURE_COUNTER == "1" ]; then
  echo "Setting up counter infrastructure"
  IPT_FILTER ":counter -"
  for chain in INPUT OUTPUT FORWARD; do
    IPT_FILTER "-A $chain -j counter"
  done
fi
echo "Allowing all established Connections"
for chain in INPUT OUTPUT FORWARD; do
  IPT_FILTER "-A $chain $CONNSTATE ESTABLISHED,RELATED -j ACCEPT"
done

echo "Policy Routing"
portal_setup

firewall-lihas -f --log=$TARGETLOG

echo Policy Routing
for policy in policy-routing-*; do
  policy=${policy#policy-routing-}
  if [ -e policy-routing-$policy/key ]; then
    if ! ip route ls table $policy >/dev/null 2>&1; then
      echo "Please add '$policy' to /etc/iproute2/rt_tables or policy routing won't work. If you don't want policy routing, feel free to delete $CONFIGDIR/policy-routing-$policy" | tee -a $LOGSTARTUP
    fi
    [ -e policy-routing-$policy/comment ] && cat policy-routing-$policy/comment | sed 's/^/ /'
    key=$(cat policy-routing-$policy/key)
    if [ -e policy-routing-$policy/gateway ]; then
      cat policy-routing-$policy/gateway | sed '/^[ \t]*$/d; /^#/d' |
      while read type interface gateway; do
        ip route flush table $policy
        if [ $type == "PPP" ]; then
          ip route ls |
          sed 's/^default.*/default dev '$interface'/' |
          while read a; do
            ip route add $a table $policy
          done
        elif [ $type == "NET" ]; then
          ip route ls |
          sed 's/^default.*/default dev '$interface' via '$gateway'/' |
          while read a; do
            ip route add $a table $policy
          done
        else
          echo Non PPP/NET-Policy-Routing is not implemented
        fi
        while ip rule | egrep -qw "fwmark $key lookup $policy"; do
          ip rule del fwmark $key table $policy
        done
        ip rule add fwmark $key pref 9000 table $policy
        ip route flush cache
      done
    fi
  fi
done
IPT_MANGLE "-I PREROUTING -j MARK --set-mark 0"
IPT_MANGLE "-I OUTPUT -j MARK --set-mark 0"
for iface in interface-*; do
  iface=${iface#interface-}
  if [ -e interface-$iface/policy-routing ]; then
    [ -e interface-$iface/comment ] && cat interface-$iface/comment | sed 's/^/ /'
    cat interface-$iface/policy-routing | firewall-lihas -H -P | helper_dns | sed '/^[ \t]*$/d; /^#/d' |
    while read snet dnet proto dport policy; do
      mark=$(cat policy-routing-$policy/key)
      if [ $dport == "0" ]; then
          IPT_MANGLE "-A OUTPUT -s $snet -d $dnet -p $proto -j MARK --set-mark $mark" 
          IPT_MANGLE "-A PREROUTING -s $snet -d $dnet -p $proto -j MARK --set-mark $mark"
      else
          IPT_MANGLE "-A OUTPUT -s $snet -d $dnet -p $proto --dport $dport -j MARK --set-mark $mark"
          IPT_MANGLE "-A PREROUTING -s $snet -d $dnet -p $proto --dport $dport -j MARK --set-mark $mark"
      fi
    done
  fi
done

echo LOCALHOST
# There might be legacy FILE* in there, sync
sync
. ./localhost
sync

for chain in INPUT OUTPUT FORWARD; do
  IPT_FILTER "-A $chain -j $TARGETLOG"
done

if [ -e ./script-post ]; then
  echo "Hook: script-post"
  . ./script-post
fi

cat >$FILE <<'EOF'
*raw
:PREROUTING ACCEPT
:OUTPUT ACCEPT
EOF
cat $FILEraw | sed '/-[sd] dns-/d' >> $FILE
cat $FILEraw | sed -n '/-[sd] dns-/p' > $DATAPATH/dns-raw
echo COMMIT >> $FILE
echo *filter >> $FILE
cat $FILEfilter | sed '/-[sd] dns-/d' >> $FILE
cat $FILEfilter | sed -n '/-[sd] dns-/p' > $DATAPATH/dns-filter
echo COMMIT >> $FILE
echo *mangle >> $FILE
cat $FILEmangle | sed '/-[sd] dns-/d' >> $FILE
cat $FILEmangle | sed -n '/-[sd] dns-/p' > $DATAPATH/dns-mangle
echo COMMIT >> $FILE
echo *nat >> $FILE
cat $FILEnat | sed '/-[sd] dns-/d; /--to-destination dns/d' >> $FILE
cat $FILEnat | sed -n '/-[sd] dns-/p; /--to-destination dns/p' > $DATAPATH/dns-nat
echo COMMIT >> $FILE

}

do_stop () {
  iptables-restore < /etc/firewall.lihas.d/iptables-accept
}

FILE=$TMPDIR/iptables

case "$1" in
  test)
        do_start
	echo "Check $FILE to see what it would look like"
	if [ -s "$LOGSTARTUP" ]; then
	  echo
	  echo "********************************************************************************"
	  echo "Potential showstoppers:"
	  cat $LOGSTARTUP
        fi
	;;
  start)
        [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
        do_start
	if [ "x$HAVE_IPSET" == "x1" ]; then
	    ipset_exit
	    ipset_init
	fi
        iptables-restore < $FILE
	[ -x /etc/firewall.lihas.d/fw_post_rules ] && /etc/firewall.lihas.d/fw_post_rules
	firewall-lihasd.pl
	if [ -s "$LOGSTARTUP" ]; then
	  echo
	  echo "********************************************************************************"
	  echo "Potential showstoppers:"
	  cat $LOGSTARTUP
        fi
        ;;
  stop)
        [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop
	if [ "x$HAVE_IPSET" == "x1" ]; then
	    ipset_exit
	fi
	kill -INT $(cat /var/run/firewall-lihasd.pid )
	ps ax | awk '$5 ~ /^\/usr\/bin\/perl$/ && $6 ~ /firewall-lihasd.pl/ {print $1}' | xargs --no-run-if-empty kill
        ;;
  reload|force-reload)
        #
        # If do_reload() is not implemented then leave this commented out
        # and leave 'force-reload' as an alias for 'restart'.
        #
        log_daemon_msg "Reloading $DESC" "$NAME"
        do_start
	if [ "x$HAVE_IPSET" == "x1" ]; then
	    ipset_exit
	    ipset_init
	fi
        iptables-restore < $FILE
	[ -x /etc/firewall.lihas.d/fw_post_rules ] && /etc/firewall.lihas.d/fw_post_rules
	kill -INT $(cat /var/run/firewall-lihasd.pid )
	sleep 1
	firewall-lihasd.pl
        ;;
  restart|force-reload)
        #
        # If the "reload" option is implemented then remove the
        # 'force-reload' alias
        #
        log_daemon_msg "Restarting $DESC" "$NAME"
        do_start
	if [ "x$HAVE_IPSET" == "x1" ]; then
	    ipset_exit
	    ipset_init
	fi
        iptables-restore < $FILE
	[ -x /etc/firewall.lihas.d/fw_post_rules ] && /etc/firewall.lihas.d/fw_post_rules
	kill -INT $(cat /var/run/firewall-lihasd.pid )
	sleep 1
	firewall-lihasd.pl
        ;;
  *)
        #echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
        echo "Usage: $SCRIPTNAME {start|stop|restart|force-reload|test}" >&2
        exit 3
        ;;
esac

exit 0
