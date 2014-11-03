#!/bin/bash
IPT_MANGLE () {
  echo $* >&7
}

IPT_NAT () {
  echo $* >&6
}

IPT_FILTER () {
  echo $* >&5
}
