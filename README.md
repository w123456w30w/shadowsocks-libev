sudo apt-get install --no-install-recommends gettext build-essential autoconf libtool libpcre3-dev m4 pkg-config libev-dev libc-ares-dev automake libmbedtls-dev libsodium-dev


./autogen.sh


./configure --disable-documentation
## Usage

For a detailed and complete list of all supported arguments,
you may refer to the man pages of the applications, respectively.

    ss-[local|redir|server|tunnel|manager]

       -s <server_host>           Host name or IP address of your remote server.

       -p <server_port>           Port number of your remote server.

       -l <local_port>            Port number of your local server.

       -k <password>              Password of your remote server.

       -m <encrypt_method>        Encrypt method: rc4-md5,
                                  aes-128-gcm, aes-192-gcm, aes-256-gcm,
                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,
                                  aes-128-ctr, aes-192-ctr, aes-256-ctr,
                                  camellia-128-cfb, camellia-192-cfb,
                                  camellia-256-cfb, bf-cfb,
                                  chacha20-ietf-poly1305,
                                  xchacha20-ietf-poly1305,
                                  salsa20, chacha20 and chacha20-ietf.
                                  The default cipher is chacha20-ietf-poly1305.

       [-a <user>]                Run as another user.

       [-f <pid_file>]            The file path to store pid.

       [-t <timeout>]             Socket timeout in seconds.

       [-c <config_file>]         The path to config file.

       [-n <number>]              Max number of open files.

       [-i <interface>]           Network interface to bind.
                                  (not available in redir mode)

       [-b <local_address>]       Local address to bind.
                                  For servers: Specify the local address to use 
                                  while this server is making outbound 
                                  connections to remote servers on behalf of the
                                  clients.
                                  For clients: Specify the local address to use 
                                  while this client is making outbound 
                                  connections to the server.

       [-u]                       Enable UDP relay.
                                  (TPROXY is required in redir mode)

       [-U]                       Enable UDP relay and disable TCP relay.
                                  (not available in local mode)

       [-T]                       Use tproxy instead of redirect. (for tcp)
                                  (only available in redir mode)

       [-L <addr>:<port>]         Destination server address and port
                                  for local port forwarding.
                                  (only available in tunnel mode)

       [-6]                       Resolve hostname to IPv6 address first.

       [-d <addr>]                Name servers for internal DNS resolver.
                                  (only available in server mode)

       [--reuse-port]             Enable port reuse.

       [--fast-open]              Enable TCP fast open.
                                  with Linux kernel > 3.7.0.
                                  (only available in local and server mode)

       [--acl <acl_file>]         Path to ACL (Access Control List).
                                  (only available in local and server mode)

       [--manager-address <addr>] UNIX domain socket address.
                                  (only available in server and manager mode)

       [--mtu <MTU>]              MTU of your network interface.

       [--mptcp]                  Enable Multipath TCP on MPTCP Kernel.

       [--no-delay]               Enable TCP_NODELAY.

       [--executable <path>]      Path to the executable of ss-server.
                                  (only available in manager mode)

       [-D <path>]                Path to the working directory of ss-manager.
                                  (only available in manager mode)

       [--key <key_in_base64>]    Key of your remote server.

       [--plugin <name>]          Enable SIP003 plugin. (Experimental)

       [--plugin-opts <options>]  Set SIP003 plugin options. (Experimental)

       [-v]                       Verbose mode.

## Transparent proxy

The latest shadowsocks-libev has provided a *redir* mode. You can configure your Linux-based box or router to proxy all TCP traffic transparently, which is handy if you use an OpenWRT-powered router.

    # Create new chain
    iptables -t nat -N SHADOWSOCKS
    iptables -t mangle -N SHADOWSOCKS

    # Ignore your shadowsocks server's addresses
    # It's very IMPORTANT, just be careful.
    iptables -t nat -A SHADOWSOCKS -d 123.123.123.123 -j RETURN

    # Ignore LANs and any other addresses you'd like to bypass the proxy
    # See Wikipedia and RFC5735 for full list of reserved networks.
    # See ashi009/bestroutetb for a highly optimized CHN route list.
    iptables -t nat -A SHADOWSOCKS -d 0.0.0.0/8 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 10.0.0.0/8 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 127.0.0.0/8 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 169.254.0.0/16 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 172.16.0.0/12 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 192.168.0.0/16 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 224.0.0.0/4 -j RETURN
    iptables -t nat -A SHADOWSOCKS -d 240.0.0.0/4 -j RETURN

    # Anything else should be redirected to shadowsocks's local port
    iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports 12345

    # Add any UDP rules
    ip route add local default dev lo table 100
    ip rule add fwmark 1 lookup 100
    iptables -t mangle -A SHADOWSOCKS -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01

    # Apply the rules
    iptables -t nat -A PREROUTING -p tcp -j SHADOWSOCKS
    iptables -t mangle -A PREROUTING -j SHADOWSOCKS

    # Start the shadowsocks-redir
    ss-redir -u -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid

## Transparent proxy (pure tproxy)

Executing this script on the linux host can proxy all outgoing traffic of this machine (except the traffic sent to the reserved address). Other hosts under the same LAN can also change their default gateway to the ip of this linux host (at the same time change the dns server to 1.1.1.1 or 8.8.8.8, etc.) to proxy their outgoing traffic.

> Of course, the ipv6 proxy is similar, just change `iptables` to `ip6tables`, `ip` to `ip -6`, `127.0.0.1` to `::1`, and other details.

```shell
#!/bin/bash

start_ssredir() {
    # please modify MyIP, MyPort, etc.
    (ss-redir -s MyIP -p MyPort -m MyMethod -k MyPasswd -b 127.0.0.1 -l 60080 --no-delay -u -T -v </dev/null &>>/var/log/ss-redir.log &)
}

stop_ssredir() {
    kill -9 $(pidof ss-redir) &>/dev/null
}

start_iptables() {
    ##################### SSREDIR #####################
    iptables -t mangle -N SSREDIR

    # connection-mark -> packet-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --restore-mark
    iptables -t mangle -A SSREDIR -m mark --mark 0x2333 -j RETURN

    # please modify MyIP, MyPort, etc.
    # ignore traffic sent to ss-server
    iptables -t mangle -A SSREDIR -p tcp -d MyIP --dport MyPort -j RETURN
    iptables -t mangle -A SSREDIR -p udp -d MyIP --dport MyPort -j RETURN

    # ignore traffic sent to reserved addresses
    iptables -t mangle -A SSREDIR -d 0.0.0.0/8          -j RETURN
    iptables -t mangle -A SSREDIR -d 10.0.0.0/8         -j RETURN
    iptables -t mangle -A SSREDIR -d 100.64.0.0/10      -j RETURN
    iptables -t mangle -A SSREDIR -d 127.0.0.0/8        -j RETURN
    iptables -t mangle -A SSREDIR -d 169.254.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 172.16.0.0/12      -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.0.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.2.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.88.99.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 192.168.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 198.18.0.0/15      -j RETURN
    iptables -t mangle -A SSREDIR -d 198.51.100.0/24    -j RETURN
    iptables -t mangle -A SSREDIR -d 203.0.113.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 224.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 240.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 255.255.255.255/32 -j RETURN

    # mark the first packet of the connection
    iptables -t mangle -A SSREDIR -p tcp --syn                      -j MARK --set-mark 0x2333
    iptables -t mangle -A SSREDIR -p udp -m conntrack --ctstate NEW -j MARK --set-mark 0x2333

    # packet-mark -> connection-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --save-mark

    ##################### OUTPUT #####################
    # proxy the outgoing traffic from this machine
    iptables -t mangle -A OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR

    ##################### PREROUTING #####################
    # proxy traffic passing through this machine (other->other)
    iptables -t mangle -A PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR

    # hand over the marked package to TPROXY for processing
    iptables -t mangle -A PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080
    iptables -t mangle -A PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080
}

stop_iptables() {
    ##################### PREROUTING #####################
    iptables -t mangle -D PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080 &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080 &>/dev/null

    iptables -t mangle -D PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null

    ##################### OUTPUT #####################
    iptables -t mangle -D OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null

    ##################### SSREDIR #####################
    iptables -t mangle -F SSREDIR &>/dev/null
    iptables -t mangle -X SSREDIR &>/dev/null
}

start_iproute2() {
    ip route add local default dev lo table 100
    ip rule  add fwmark 0x2333        table 100
}

stop_iproute2() {
    ip rule  del   table 100 &>/dev/null
    ip route flush table 100 &>/dev/null
}

start_resolvconf() {
    # or nameserver 8.8.8.8, etc.
    echo "nameserver 1.1.1.1" >/etc/resolv.conf
}

stop_resolvconf() {
    echo "nameserver 114.114.114.114" >/etc/resolv.conf
}

start() {
    echo "start ..."
    start_ssredir
    start_iptables
    start_iproute2
    start_resolvconf
    echo "start end"
}

stop() {
    echo "stop ..."
    stop_resolvconf
    stop_iproute2
    stop_iptables
    stop_ssredir
    echo "stop end"
}

restart() {
    stop
    sleep 1
    start
}

main() {
    if [ $# -eq 0 ]; then
        echo "usage: $0 start|stop|restart ..."
        return 1
    fi

    for funcname in "$@"; do
        if [ "$(type -t $funcname)" != 'function' ]; then
            echo "'$funcname' not a shell function"
            return 1
        fi
    done

    for funcname in "$@"; do
        $funcname
    done
    return 0
}
main "$@"
```

## Security Tips

For any public server, to avoid users accessing localhost of your server, please add `--acl acl/server_block_local.acl` to the command line.

Although shadowsocks-libev can handle thousands of concurrent connections nicely, we still recommend
setting up your server's firewall rules to limit connections from each user:

    # Up to 32 connections are enough for normal usage
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## License

```
Copyright: 2013-2015, Clow Windy <clowwindy42@gmail.com>
           2013-2018, Max Lv <max.c.lv@gmail.com>
           2014, Linus Yang <linusyang@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
