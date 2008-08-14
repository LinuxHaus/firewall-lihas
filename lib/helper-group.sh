#!/bin/bash

helper_hostgroup () {
  cat | while read replacement; do
    if echo $replacement | grep '\b'hostgroup- > /dev/null; then
      hostgroup_replace=$(echo $replacement | sed 's/.*hostgroup-/hostgroup-/; s/hostgroup-\([^ \t]*\)[ \t].*/hostgroup-\1/')
      cat groups/$hostgroup_replace | sed '/^[ \t]*$/d; /^#/d' |
      while read name; do
        repl=$( echo $replacement | sed s/$hostgroup_replace/$name/ )
        if echo $repl | grep '\b'hostgroup- > /dev/null; then
          echo $repl | helper_hostgroup
        else
          echo $repl
        fi
      done
    else
      echo $replacement
    fi
  done
}

helper_portgroup () {
  cat | while read replacement; do
    if echo $replacement | grep '\b'portgroup- > /dev/null; then
      repproto=$(echo $replacement | awk '{print $3}')
      portgroup_replace=$(echo $replacement | sed 's/.*portgroup-/portgroup-/; s/portgroup-\([^ \t]*\)[ \t].*/portgroup-\1/')
      if [ "$repproto" == "any" ]; then
        cat groups/$portgroup_replace | sed '/^[ \t]*$/d; /^#/d' |
        while read proto port; do
          repl=$( echo $replacement | sed "s/$portgroup_replace/$port/g; s/any/$proto/" )
          if echo $repl | grep '\b'portgroup- > /dev/null; then
            echo $repl | helper_portgroup
          else
            echo $repl
          fi
        done
      else
        cat groups/$portgroup_replace | sed '/^[ \t]*$/d; /^#/d' | awk '$1 ~ /^'$repproto'/' |
        while read proto port; do
          repl=$( echo $replacement | sed "s/$portgroup_replace/$port/g;" )
          if echo $repl | grep '\b'portgroup- > /dev/null; then
            echo $repl | helper_portgroup
          else
            echo $repl
          fi
        done
      fi
    else
      echo $replacement
    fi
  done
}
