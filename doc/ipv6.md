# IPv6 Support
By default IPv6 support is disabled and IPv4 support is enabled. Both can be enabled at the same time.
## Activation:
Add to `/etc/default/firewall`:
```
DOIPV6=true
```
This is actually the program `true` and called from within firewall-lihas
## Deactivation
Add to `/etc/default/firewall`:
```
DOIPV6=false
```
This is actually the program `false`.

## Differences to IPv4 support
* ipv6-icmp doesn't use conntrack enhancement, request and replies have to be allowed separately
* Configuration is done in separate files where neccesary
    * `interface-*`:
        * `network` -> `network6`
        * `privclients` -> `privclients6`
        * `dnat` -> `dnat6`
        * `snat` -> `snat6`
        * `masquerade` -> `masquerade6`
        * `reject` -> `reject6`
        * `nolog` -> `nolog6`
    * `groups`
        * `hostgroup6-*`
        * `portgroup-*`: ipv4 and ipv6 combined
        * `ifacegroup-*`: ipv4 and ipv6 combined
* Be aware IPv6 depends on certain `ipv6-icmp` types to be allowed
