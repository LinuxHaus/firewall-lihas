#!/bin/bash

helper_dns () {
  dns_replace=$1
  hostname=${$dns_replace#dns-}
  host -t a $hostname | while read name dummy ip; do
    replacement=$( | sed 's/'$dns_replace'/'$ip'/')
    if echo $replacement | grep '\b'$dns_replace > /dev/null; then
      echo replacement | helper_dns $dns_replace
    fi
  done
}

echo "0.0.0.0/0       dns-irc.netgamers.org       tcp     80" | helper_dns dns-irc.netgamers.org
