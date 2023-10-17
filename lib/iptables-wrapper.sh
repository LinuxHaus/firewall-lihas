#!/bin/bash
# exec 4>$FILE 5>$FILEfilter 6>$FILEnat 7>$FILEmangle 8>$FILEraw 9>$FILE6 10>$FILE6filter 11>$FILE6nat 12>$FILE6mangle 13>$FILE6raw

IPT_MANGLE () {
  echo $* >&7
}
IPT_NAT () {
  echo $* >&6
}
IPT_FILTER () {
  echo $* >&5
}
IPT_RAW () {
  echo $* >&8
}

IPT6_MANGLE () {
  echo $* >&12
}
IPT6_NAT () {
  echo $* >&11
}
IPT6_FILTER () {
  echo $* >&10
}
IPT6_RAW () {
  echo $* >&13
}
