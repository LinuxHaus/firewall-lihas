#!/bin/bash
if [ "x$HAVE_IPSET" == "x1" ]; then
	if [ -d $CONFIGDIR/groups/ipset ]; then
		find $CONFIGDIR/groups/ipset -maxdepth 1 -type d -name 'ipset-*' | 
		while read ipsetdir; do
			ipsetname=${ipsetdir##$CONFIGDIR/groups/ipset/ipset-}
			if [ -e $ipsetdir/setup ]; then
				ipset create -exist $ipsetname $(cat $ipsetdir/setup)
				ipset create -exist pswap$ipsetname $(cat $ipsetdir/setup)
				dummy=$(ipset -L $ipsetname | 
					while read a b; do
						if [ x$a == "xType:" ]; then
							echo ${b#*:}
						fi
					done
				)
				echo $dummy
			else
				echo "Please add '$ipsetdir/setup'" | tee -a $LOGSTARTUP
			fi
		done
	fi
fi

# config.xml-based
ipset_init() {
ipsetcount=$(xmlstarlet sel -t -v 'count(applicationconfig/application/ipsets/*)' $CONFIGDIR/config.xml)
for i in $(seq 1 $ipsetcount); do
	eval $(xmlstarlet sel -t -v "concat('ipsetname=',applicationconfig/application/ipsets/*[$i]/@name,' ipsetpersist=',applicationconfig/application/ipsets/*[$i]/@persistent,' ipsetbackup=',applicationconfig/application/ipsets/*[$i]/@backupfile)" $CONFIGDIR/config.xml)
	if [ x != "x$ipsetname" ]; then
		if [ xyes != "x$ipsetpersist" ]; then
			ipset destroy "$ipsetname" >/dev/null 2>&1
		fi
		if ! ipset list $ipsetname >/dev/null 2>&1; then
			if [ $? -eq 0 ]; then
				if [ xyes == "x$ipsetpersist" ]; then
					if [ x != "x$ipsetbackup" ]; then
						if [ -e "$ipsetbackup" ]; then
							ipset -file $ipsetbackup restore
						fi
					else
						echo "Please add attribute 'backupfile' to $CONFIGDIR/config.xml applicationconfig/application/ipsets/ipset[name=$ipsetname] to use persistent ipset" | tee -a $LOGSTARTUP
					fi
				fi
				ipset_create="$(xmlstarlet sel -t -v applicationconfig/application/ipsets/ipset\[@name=\'$ipsetname\'\]/create $CONFIGDIR/config.xml)"
				ipset -exist create "$ipsetname" $ipset_create
				if [ $? -ne 0 ]; then
					echo "ipset $ipsetname creation failed, ipset will not be available" | tee -a $LOGSTARTUP
				fi
			fi
		fi
	else
		echo "ipset $i has no name attribute, ipset will not be available" | tee -a $LOGSTARTUP
	fi
done
}
ipset_exit() {
ipsetcount=$(xmlstarlet sel -t -v 'count(applicationconfig/application/ipsets/*)' $CONFIGDIR/config.xml)
for i in $(seq 1 $ipsetcount); do
	eval $(xmlstarlet sel -t -v "concat('ipsetname=',applicationconfig/application/ipsets/*[$i]/@name,' ipsetpersist=',applicationconfig/application/ipsets/*[$i]/@persistent,' ipsetbackup=',applicationconfig/application/ipsets/*[$i]/@backupfile)" $CONFIGDIR/config.xml)
	if [ x != "x$ipsetname" ]; then
		if [ xyes == "x$ipsetpersist" ]; then
			if [ x != "x$ipsetbackup" ]; then
				ipset -file $ipsetbackup save "$ipsetname"
			else
				echo "Please add attribute 'backupfile' to $CONFIGDIR/config.xml applicationconfig/application/ipsets/ipset[name=$ipsetname] to use persistent ipset" | tee -a $LOGSTARTUP
			fi
		else
			ipset destroy "$ipsetname"
		fi
	fi
done
}
# vim: ts=2 sw=2 sts=2 sr noet
