#!/bin/bash

helper_hostgroup () {

  TMPFILE=$(mktemp -p /dev/shm firewall-helper-hostgroup-$(date -I).XXXXXXXXXX)
  cat > $TMPFILE
  replacement=$(cat $TMPFILE)

  if echo $replacement | grep '\b'hostgroup- > /dev/null; then
    hostgroup_replace=$(echo $replacement | sed 's/.*hostgroup-/hostgroup-/; s/hostgroup-\([^ \t]*\)[ \t].*/hostgroup-\1/')
    cat groups/$hostgroup_replace | sed '/^[ \t]*$/d; /^#/d' |
    while read name; do
      replacement=$( sed s/$hostgroup_replace/$name/ < $TMPFILE )
      if echo $replacement | grep '\b'hostgroup- > /dev/null; then
        echo $replacement | helper_hostgroup
      else
        echo $replacement
      fi
    done
  else
    echo $replacement
  fi
  rm $TMPFILE
}


helper_portgroup () {

  TMPFILE=$(mktemp -p /dev/shm firewall-helper-portgroup-$(date -I).XXXXXXXXXX)
  cat > $TMPFILE
  replacement=$(cat $TMPFILE)

  if echo $replacement | grep '\b'portgroup- > /dev/null; then
    repproto=$(echo $replacement | awk '{print $3}')
    portgroup_replace=$(echo $replacement | sed 's/.*portgroup-/portgroup-/; s/portgroup-\([^ \t]*\)[ \t].*/portgroup-\1/')
    if [ "$repproto" == "any" ]; then
      cat groups/$portgroup_replace | sed '/^[ \t]*$/d; /^#/d' |
      while read proto port; do
        replacement=$( sed "s/$portgroup_replace/$port/g; s/any/$proto/" < $TMPFILE )
        if echo $replacement | grep '\b'portgroup- > /dev/null; then
          echo $replacement | helper_portgroup
        else
          echo $replacement
        fi
      done
    else
      cat groups/$portgroup_replace | sed '/^[ \t]*$/d; /^#/d' | awk '$1 ~ /^'$repproto'/' |
      while read proto port; do
        replacement=$( sed "s/$portgroup_replace/$port/g;" < $TMPFILE )
        if echo $replacement | grep '\b'portgroup- > /dev/null; then
          echo $replacement | helper_portgroup
        else
          echo $replacement
        fi
      done
    fi
  else
    echo $replacement
  fi
  rm $TMPFILE
}
