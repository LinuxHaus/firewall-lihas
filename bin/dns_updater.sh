#!/bin/bash

LANG=C
LC_ALL=C
export LANG LC_ALL

DATABASE=/tmp/db
RELOADFW=0;
UNIXTIME=$(date +%s)

function check_reload {
  echo "SELECT value FROM vars_num WHERE name='reload';" | sqlite3 ${DATABASE}
}

echo "DELETE FROM vars_num WHERE name='reload';
      INSERT INTO vars_num (name, value) VALUES ('reload', 0);" | sqlite3 ${DATABASE}

(
  echo "DELETE FROM hostnames;"
  echo "DELETE FROM hostnames_current;"

  # All names present in config:
  find include interface-* groups -maxdepth 1 -mindepth 1 -type f |
  xargs sed '/^#/d; /^$/d' |
  xargs -n1 echo |
  sort -u |
  egrep '^dns-' |
  sed 's/^dns-/INSERT INTO hostnames (hostname) VALUES ('"'"'/;
       s/$/.'"'"')\;/;'
) |
sqlite3 ${DATABASE}

check_reload

# Disable old names:
ACTIVEHOSTS1=$( echo "SELECT count(*) FROM dnshistory WHERE active=1;" | sqlite3 ${DATABASE} )
echo "UPDATE dnshistory SET active=0 WHERE active=1 AND hostname NOT IN (SELECT hostname FROM hostnames);" | sqlite3 ${DATABASE}
ACTIVEHOSTS2=$( echo "SELECT count(*) FROM dnshistory WHERE active=1;" | sqlite3 ${DATABASE} )
if [ $ACTIVEHOSTS1 -ne $ACTIVEHOSTS2 ]; then
  echo "UPDATE vars_num SET value=value+1 WHERE name='reload';" | sqlite3 ${DATABASE}
fi

echo "SELECT hostname FROM hostnames;" |
sqlite3 ${DATABASE} |
while read host; do
  dig -t a $host |
  sed '/^$/d; /^\;/d' |
  while read host ttl dummy dummy ip; do
    echo "SELECT count(*), '$host', '$ip', '$ttl' FROM dnshistory WHERE active=1 AND hostname='$host' AND ip='$ip';"
    echo "INSERT INTO hostnames_current (hostname, time_first, time_valid_till, ip) VALUES ('$host', $UNIXTIME, $UNIXTIME+$ttl, '$ip');"
  done
done |
sqlite3 ${DATABASE} | sed 's/|/ /g' |
while read count host ip ttl; do
  if [ $count -eq 0 ]; then
    echo "INSERT INTO dnshistory (hostname, time_first, time_valid_till, ip, active) VALUES ('$host', $UNIXTIME, $UNIXTIME+$ttl, '$ip', 1);"
    echo "UPDATE vars_num SET value=value+1 WHERE name='reload';"
  else
    echo "UPDATE dnshistory SET time_valid_till=$UNIXTIME+$ttl WHERE active=1 AND hostname='$host' AND ip='$ip';"
  fi
done |
sqlite3 ${DATABASE}

check_reload

ACTIVEHOSTS1=$( echo "SELECT count(*) FROM dnshistory WHERE active=1;" | sqlite3 ${DATABASE} )
echo "UPDATE dnshistory SET active=0 WHERE active=1 AND ip NOT IN (SELECT ip FROM hostnames_current);" | sqlite3 ${DATABASE}
ACTIVEHOSTS2=$( echo "SELECT count(*) FROM dnshistory WHERE active=1;" | sqlite3 ${DATABASE} )
if [ $ACTIVEHOSTS1 -ne $ACTIVEHOSTS2 ]; then
  echo "UPDATE vars_num SET value=value+1 WHERE name='reload';" | sqlite3 ${DATABASE}
fi

check_reload

#if [ $RELOADFW -gt 0 ]; then
#  ./firewall.sh restart
#fi
