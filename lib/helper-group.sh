#!/bin/bash

helper_dns () {

  TMPFILE=$(mktemp -p /dev/shm firewall-helper-dns-$(date -I).XXXXXXXXXX)
  cat > $TMPFILE
  replacement=$(cat $TMPFILE)

  if echo $replacement | grep '\b'dns- > /dev/null; then
    dns_replace=$(echo $replacement | sed 's/.*dns-/dns-/; s/dns-\([^ \t]*\)[ \t].*/dns-\1/')
    hostname=${dns_replace#dns-}
    host -t a $hostname | while read name dummy ip; do
      replacement=$( sed s/$dns_replace/$ip/ < $TMPFILE )
      if echo $replacement | grep '\b'dns- > /dev/null; then
        echo $replacement | helper_dns
      else
        echo $replacement
      fi
    done
  else
    echo $replacement
  fi
  rm $TMPFILE
}
