echo "
  SELECT * FROM hostnames;
  SELECT hostname, ip, datetime(time_first, 'unixepoch') , datetime(time_valid_till, 'unixepoch') FROM hostnames_current;
  SELECT name,value FROM vars_num;
  SELECT hostname, ip, datetime(time_first, 'unixepoch') , datetime(time_valid_till, 'unixepoch') FROM dnshistory ORDER BY time_valid_till DESC;" |
sqlite3 /var/lib/firewall-lihas/db.sqlite |
sed 's/ /_/g; s/|/ /g' |
while read a b c d; do
  printf '%-30s\t% 16s\t%s\t%s\n' $a $b $c $d
done
ls -l /var/lib/firewall-lihas/db.sqlite

