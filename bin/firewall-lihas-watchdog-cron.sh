#!/bin/bash
# Copyright (C) 2014 Adrian Reyer support@lihas.de
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Check if policy-routing routing tables have the correct content.
# Use this as a cron job.
# e.g. echo "*/5 * * * * root /usr/bin/firewall-lihas-watchdog-cron.sh" >> /etc/cron.d/firewall-lihas

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
NAME=firewall
CONFIGDIR=/etc/firewall.lihas.d
LIBDIR=/usr/lib/firewall-lihas
TMPDIR=${TMPDIR:-/tmp}

DATAPATH=/var/lib/firewall-lihas
DATABASE=$DATAPATH/db.sqlite
LOGSTARTUP=$TMPDIR/firewall-lihas-startup.log

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

export CONFIGDIR LIBDIR TMPDIR DATABASE DATAPATH


check_routing_tables() {
  cd "${CONFIGDIR}"
  for policy in policy-routing-*; do
    policy=${policy#policy-routing-}
    if ! ip route ls table $policy >/dev/null 2>&1; then
      echo "Please add '$policy' to /etc/iproute2/rt_tables or policy routing won't work. If you don't want policy routing, feel free to delete $CONFIGDIR/policy-routing-$policy" | tee -a $LOGSTARTUP
    fi
    if [ -e policy-routing-$policy/key ]; then
      key=$(cat policy-routing-$policy/key)
      if [ -e policy-routing-$policy/gateway ]; then
        cat policy-routing-$policy/gateway | sed '/^[ \t]*$/d; /^#/d' |
        while read type interface gateway; do
          echo -n > $TMPDIR/firewall-lihas-watchdog-cron-"$policy"
          if [ $type == "PPP" ]; then
            ip route ls |
            sed 's/^default.*/default dev '$interface'/' |
            while read a; do
              echo ip route add $a table $policy >> $TMPDIR/firewall-lihas-watchdog-cron-"$policy"
            done
          elif [ $type == "NET" ]; then
            ip route ls |
            sed 's/^default.*/default via '$gateway' dev '$interface'/' |
            while read a; do
              echo ip route add $a table $policy >> $TMPDIR/firewall-lihas-watchdog-cron-"$policy"
            done
          else
            echo Non PPP/NET-Policy-Routing is not implemented
          fi
        done
      fi
    fi
    cmp -s <(ip route ls table "$policy" | sed 's/ \+/ /g; s/ *$//' | sort -u) <(cat $TMPDIR/firewall-lihas-watchdog-cron-"$policy" | sed 's/ip route add //; s/ table '$policy'//; s/ \+/ /g' | sort -u)
    res=$?
    case $res in
      0)
        # alles ok
        ;;
      1)
        ./firewall.sh start
        ;;
      2)
        if [ $(iptables-save -t mangle | wc -l) -lt 10 ]; then
          echo "Firewall down" | tee -a $LOGSTARTUP
        else
          ./firewall.sh start
        fi
        ;;
    esac
  done
}

check_routing_tables
