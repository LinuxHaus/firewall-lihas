#!/bin/bash

helper_dns () {

  cat | while read replacement; do
    if echo $replacement | grep '\b'dns- > /dev/null; then
      dns_replace=$(echo $replacement | sed 's/.*dns-/dns-/; s/dns-\([^ \t]*\)[ \t].*/dns-\1/')
      hostname=${dns_replace#dns-}
      host -t a $hostname | sed 's/^.*[ \t]\+//' | while read ip; do
        if echo $ip | egrep -q '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
          repl=$( echo $replacement | sed s/$dns_replace/$ip/ )
          if echo $repl | grep '\b'dns- > /dev/null; then
            echo $repl | helper_dns
          else
            echo $repl
          fi
        else
          echo >&2 "$hostname DNS lookup timed out"
        fi
      done
    else
      echo $replacement
    fi
  done
}
