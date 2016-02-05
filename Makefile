APPNAME=$(shell basename `pwd`)
VERSION=$(shell git describe | sed 's/-/./g')

UPLOADURL=http://ftp.lihas.de/cgi-bin/newpackage
DEBIAN_FULL_NAME=Adrian Reyer
DEBIAN_EMAIL=are@lihas.de
DEBIAN_HOMEPAGE=https://github.com/LinuxHaus/firewall-lihas/
DESC_SHORT=LiHAS firewall with additional features: dns-support, portal-support
DESC_LONG=LiHAS firewall with additional features:\n policy-routing\n dns-support\n captive portal with sms service integration\n traffic shaping
DEBIAN_DEPENDS=iptables,perl (>= 5.12),liblog-log4perl-perl,libgetopt-mixed-perl,libxml-application-config-perl,libxml-xpath-perl,liblog-dispatch-perl
DEBIAN_RECOMMENDS=liblog-dispatch-perl,libpoe-component-client-dns-perl,libpoe-component-client-ping-perl,libpoe-perl,libdbi-perl,libdbd-sqlite3-perl,libnet-server-perl,xmlstarlet,ipset,net-tools,libpoe-component-server-http-perl,libhttp-message-perl
ARCH=all

CFGDIR=$(DESTDIR)/etc/$(APPNAME)
CFGDDIR=$(DESTDIR)/etc/firewall.lihas.d
CRONDFILES=$( etc/cron.d/* )
CRONHOURLYFILES=$( etc/cron.hourly/* )
CRONDAILYFILES=$( etc/cron.daily/* )
CRONWEEKLYFILES=$( etc/cron.weekly/* )
CRONMONTHLYFILES=$( etc/cron.monthly/* )
BINDIR=$(DESTDIR)/bin
SBINDIR=$(DESTDIR)/sbin
UBINDIR=$(DESTDIR)/usr/bin
USBINDIR=$(DESTDIR)/usr/sbin
ULBINDIR=$(DESTDIR)/usr/local/bin
ULSBINDIR=$(DESTDIR)/usr/local/sbin
ULIBDIR=$(DESTDIR)/usr/lib/$(APPNAME)
USHAREDIR=$(DESTDIR)/usr/share/$(APPNAME)
USDOCDIR=$(DESTDIR)/usr/share/doc/$(APPNAME)
MAN1DIR=$(DESTDIR)/usr/share/man/man1
MAN2DIR=$(DESTDIR)/usr/share/man/man2
MAN3DIR=$(DESTDIR)/usr/share/man/man3
MAN4DIR=$(DESTDIR)/usr/share/man/man4
MAN5DIR=$(DESTDIR)/usr/share/man/man5
MAN6DIR=$(DESTDIR)/usr/share/man/man6
MAN7DIR=$(DESTDIR)/usr/share/man/man7
MAN8DIR=$(DESTDIR)/usr/share/man/man8
RUNDIR=$(DESTDIR)/var/lib/$(APPNAME)

all:
	

install:
	install -m 0755 -d $(CFGDDIR)
	install -m 0755 -d $(ULIBDIR) $(ULIBDIR)/templates $(UBINDIR) $(USBINDIR) $(DESTDIR)/etc/init.d
	install -m 0755 -d $(RUNDIR)
	install -m 0755 -d $(DESTDIR)/usr/share/perl5
	install -m 0755 -d $(USDOCDIR)/examples
	install -m 0755 -d $(CFGDDIR)/groups $(CFGDDIR)/include $(CFGDDIR)/feature/portal
	install -m 0600 config.xml $(CFGDDIR)
	install -m 0600 log4perl.conf $(CFGDDIR)
	install -m 0755 bin/firewall-lihas.pl $(USBINDIR)/firewall-lihas
	install -m 0755 bin/firewall-lihasd.pl $(USBINDIR)/
	chmod 0755 $(USBINDIR)/firewall-lihasd.pl
	install -m 0755 bin/firewall-lihas-watchdog-cron.sh $(UBINDIR)/
	chmod 0755 $(UBINDIR)/firewall-lihas-watchdog-cron.sh
	install -m 0644 lib/*.sh $(ULIBDIR)/
	install -m 0644 lib/templates/* $(ULIBDIR)/templates/
	cp -a lib/LiHAS $(DESTDIR)/usr/share/perl5/LiHAS
	chmod 0755 $(ULIBDIR)/*.sh
	install -m 0644 README $(USDOCDIR)
	install -m 0644 doc/* $(USDOCDIR)
	install -m 0755 localhost $(CFGDDIR)/
	install -m 0755 firewall.sh $(UBINDIR)/; cd $(CFGDDIR) && ln -s /usr/bin/firewall.sh firewall.sh
	install -m 0644 iptables-accept $(CFGDDIR)
	cp -a policy-routing-dsl $(USDOCDIR)/examples/
	cp -a interface-eth0 $(USDOCDIR)/examples/interface-eth99
	cp -a include $(USDOCDIR)/examples/
	cp -a groups $(USDOCDIR)/examples/
	install -D -m 755 lib/portal-cgi.pl $(DESTDIR)/usr/lib/cgi-bin/portal-cgi.pl
	
	chown -R root:root  $(DESTDIR)
	cd $(DESTDIR)/etc/init.d/ && ln -sf /etc/firewall.lihas.d/firewall.sh firewall-lihas
	git log --decorate=short > $(USDOCDIR)/CHANGELOG

package:
	jonixbuild build

debian-clean:
	rm -rf debian
debian-preprepkg:
	if test -d debian ; then echo "ERROR: debian directory already exists"; exit 1; fi
debian-prepkg: debian-preprepkg
	echo | DEBFULLNAME="$(DEBIAN_FULL_NAME)" dh_make -sy --native -e "$(DEBIAN_EMAIL)" -p $(APPNAME)_$(VERSION)
	sed -i 's#^Homepage:.*#Homepage: $(DEBIAN_HOMEPAGE)#; s#^Architecture:.*#Architecture: $(ARCH)#; /^#/d; s#^Description:.*#Description: $(DESC_SHORT)#; s#^ <insert long description, indented with spaces># $(DESC_LONG)#; s#^Depends: .*#Depends: $${misc:Depends}$(DEBIAN_DEPENDS)#; s#^Section: .*#Section: admin#; s#^Standards-Version: .*#Standards-Version: 3.9.6#; /^Depends:/aRecommends: $(DEBIAN_RECOMMENDS)' debian/control
	sed -i 's/^Copyright:.*/Copyright: 2006-2014 Adrian Reyer <are@lihas.de>/; /likewise for another author/d; s#^Source:.*#Source: https://github.com/LinuxHaus/firewall-lihas#; /^#/d' debian/copyright
	rm debian/*.ex debian/README.Debian debian/README.source debian/firewall-lihas.doc-base.EX
	for file in /etc/firewall.lihas.d/config.xml /etc/firewall.lihas.d/iptables-accept /etc/firewall.lihas.d/log4perl.conf /etc/firewall.lihas.d/localhost; do echo $i >> debian/conffiles; done
debian-dpkg:
	dpkg-buildpackage -sa -rfakeroot -tc

debian-upload:
	curl -u `cat $(HOME)/.debianrepositoryauth` -v $(UPLOADURL) -F B1="Datei hochladen" -F uploaded_file=@../$(APPNAME)_$(VERSION)_$(ARCH).deb
