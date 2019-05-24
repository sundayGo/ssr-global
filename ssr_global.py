#!/usr/bin/python
import re
import os
import sys
import base64

install_path = '/usr/local/share/shadowsocksr/'
work_path = '/usr/local/share/shadowsocksr/shadowsocks/'
ssr_config = '/usr/local/share/shadowsocksr/config.json'

pcap_config = '''
[Base]
Version = 0.45
File Refresh Time = 15
Large Buffer Size = 4096
Additional Path = 
Hosts File Name = Hosts.ini|Hosts.conf|Hosts.txt|WhiteList.txt
IPFilter File Name = IPFilter.ini|IPFilter.conf|IPFilter.dat|Routing.txt|chnroute.txt

[Log]
Print Log Level = 3
Log Maximum Size = 8MB

[Listen]
Process Unique = 1
Pcap Capture = 1
Pcap Devices Blacklist = AnyConnect|Host|Hyper|ISATAP|IKE|L2TP|Only|Oracle|PPTP|Pseudo|Teredo|Tunnel|Virtual|VMNet|VMware|VPN|any|gif|ifb|lo|nflog|nfqueue|stf|tunl|utun
Pcap Reading Timeout = 250
Listen Protocol = IPv6 + IPv4 + TCP + UDP
Listen Port = 53
Operation Mode = Server
IPFilter Type = Deny
IPFilter Level < 0
Accept Type = 

[DNS]
Outgoing Protocol = IPv4 + TCP
Direct Request = 0
Cache Type = Timer
Cache Parameter = 86400
Default TTL = 86400

[Local DNS]
Local Protocol = IPv4 + UDP
Local Hosts = 0
Local Routing = 1
Local Force Request = 0


[Addresses]
IPv4 Listen Address = 
IPv4 EDNS Client Subnet Address = 
IPv4 Main DNS Address = 8.8.4.4:53
IPv4 Alternate DNS Address = 8.8.8.8:53|208.67.220.220:443|208.67.222.222:5353
IPv4 Local Main DNS Address = 112.124.47.27:53
IPv4 Local Alternate DNS Address = 114.215.126.16:53
IPv6 Listen Address = 
IPv6 EDNS Client Subnet Address = 
IPv6 Main DNS Address = [2001:4860:4860::8844]:53
IPv6 Alternate DNS Address = [2606:4700:4700::1001]:53|[2620:FE::9]:53|[2620:0:CCD::2]:5353
IPv6 Local Main DNS Address = [240C::6644]:53
IPv6 Local Alternate DNS Address = [240C::6666]:53

[Values]
Thread Pool Base Number = 0
Thread Pool Maximum Number = 128
Thread Pool Reset Time = 120
Queue Limits Reset Time = 0
EDNS Payload Size = 1220
IPv4 Packet TTL = 72 - 255
IPv4 Main DNS TTL = 0
IPv4 Alternate DNS TTL = 0
IPv6 Packet Hop Limits = 72 - 255
IPv6 Main DNS Hop Limits = 0
IPv6 Alternate DNS Hop Limits = 0
Hop Limits Fluctuation = 1
Reliable Once Socket Timeout = 3000
Reliable Serial Socket Timeout = 1500
Unreliable Once Socket Timeout = 2000
Unreliable Serial Socket Timeout = 1000
TCP Fast Open = 0
Receive Waiting = 0
ICMP Test = 900
Domain Test = 900
Alternate Times = 10
Alternate Time Range = 60
Alternate Reset Time = 300
Multiple Request Times = 0

[Switches]
Domain Case Conversion = 1
Compression Pointer Mutation = 0
EDNS Label = 0
EDNS Client Subnet Relay = 0
DNSSEC Request = 0
DNSSEC Force Record = 0
Alternate Multiple Request = 0
IPv4 Do Not Fragment = 0
TCP Data Filter = 1
DNS Data Filter = 1
Blacklist Filter = 1
Resource Record Set TTL Filter = 0

[Data]
ICMP ID = 
ICMP Sequence = 
ICMP PaddingData = 
Domain Test Protocol = TCP + UDP
Domain Test ID = 
Domain Test Data = 
Local Machine Server Name = 

[Proxy]
SOCKS Proxy = 1
SOCKS Version = 5
SOCKS Protocol = IPv4 + TCP
SOCKS Reliable Socket Timeout = 6000
SOCKS Unreliable Socket Timeout = 3000
SOCKS UDP No Handshake = 1
SOCKS Proxy Only = 0
SOCKS IPv4 Address = 127.0.0.1:12345
SOCKS IPv6 Address = [::1]:1080
SOCKS Target Server = 8.8.4.4:53
SOCKS Username = 
SOCKS Password = 
HTTP Proxy = 0
HTTP Protocol = IPv4
HTTP Socket Timeout = 3000
HTTP Proxy Only = 0
HTTP IPv4 Address = 127.0.0.1:12345
HTTP IPv6 Address = [::1]:1080
HTTP Target Server = 8.8.4.4:53
HTTP Version = 1.1
HTTP Header Field = Content-Length: 0
HTTP Header Field = User-Agent: Pcap_DNSProxy/0.4
HTTP Header Field = Accept: */*
HTTP Header Field = Cache-Control: no-cache
HTTP Header Field = Pragma: no-cache
HTTP Proxy Authorization = 


[DNSCurve]
DNSCurve = 0
DNSCurve Protocol = IPv4 + UDP
DNSCurve Payload Size = 512
DNSCurve Reliable Socket Timeout = 3000
DNSCurve Unreliable Socket Timeout = 2000
DNSCurve Encryption = 1
DNSCurve Encryption Only = 0
DNSCurve Client Ephemeral Key = 0
DNSCurve Key Recheck Time = 1800

[DNSCurve Database]
DNSCurve Database Name = dnscrypt-resolvers.csv
DNSCurve Database IPv4 Main DNS = cisco
DNSCurve Database IPv4 Alternate DNS = 
DNSCurve Database IPv6 Main DNS = cisco-ipv6
DNSCurve Database IPv6 Alternate DNS = 

[DNSCurve Addresses]
DNSCurve IPv4 Main DNS Address = 208.67.220.220:443
DNSCurve IPv4 Alternate DNS Address = 
DNSCurve IPv6 Main DNS Address = [2620:0:CCC::2]:443
DNSCurve IPv6 Alternate DNS Address = 
DNSCurve IPv4 Main Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv4 Alternate Provider Name = 
DNSCurve IPv6 Main Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv6 Alternate Provider Name = 

[DNSCurve Keys]
DNSCurve Client Public Key = 
DNSCurve Client Secret Key = 
DNSCurve IPv4 Main DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
DNSCurve IPv4 Alternate DNS Public Key = 
DNSCurve IPv6 Main DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
DNSCurve IPv6 Alternate DNS Public Key = 
DNSCurve IPv4 Main DNS Fingerprint = 
DNSCurve IPv4 Alternate DNS Fingerprint = 
DNSCurve IPv6 Main DNS Fingerprint = 
DNSCurve IPv6 Alternate DNS Fingerprint = 

[DNSCurve Magic Number]
DNSCurve IPv4 Main Receive Magic Number = 
DNSCurve IPv4 Alternate Receive Magic Number = 
DNSCurve IPv6 Main Receive Magic Number = 
DNSCurve IPv6 Alternate Receive Magic Number = 
DNSCurve IPv4 Main DNS Magic Number = 
DNSCurve IPv4 Alternate DNS Magic Number = 
DNSCurve IPv6 Main DNS Magic Number = 
DNSCurve IPv6 Alternate DNS Magic Number =
'''


redsocks_config = '''
base {
	log_debug = off;
	log_info = on;
	log = "syslog:daemon";
	daemon = on;
	user = redsocks;
	group = redsocks;
	redirector = iptables;
}

redsocks {
	local_ip = 127.0.0.1;
	local_port = 12345;
	ip = 127.0.0.1;
	port = 1080;
	type = socks5;

}

'''

def base64_decode(strg):
	lens = len(strg)
	lenx = lens - (lens % 4 if lens % 4 else 4)
	try:
		result = base64.decodestring(strg[:lenx])
	except:
		pass

	return result

def subscribe(strg):
	try:
		strg = re.findall(r'ssr\://(.+)',strg)[0] + "=="
		ssrString = base64_decode(strg).split(':')
		passBase64 = re.findall(r'(.+)/',ssrString[5])[0] + "=="
		password = base64_decode(passBase64)
		print """
-----------------------------------------------
 server: %s
 server_port: %s
 password: %s
 method: %s
 protocol: %s
 obfs: %s
-----------------------------------------------
""" %(ssrString[0],ssrString[1],password,ssrString[3],ssrString[2],ssrString[4])
	except:
		print "[x] error"
		exit()

	config_json = """{
    "server": "%s",
    "server_ipv6": "::",
    "server_port": %s,
    "local_address": "127.0.0.1",
    "local_port": 1080,

    "password": "%s",
    "method": "%s",
    "protocol": "%s",
    "protocol_param": "",
    "obfs": "%s",
    "obfs_param": "",
    "speed_limit_per_con": 0,
    "speed_limit_per_user": 0,

    "additional_ports" : {}, // only works under multi-user mode
    "additional_ports_only" : false, // only works under multi-user mode
    "timeout": 120,
    "udp_timeout": 60,
    "dns_ipv6": false,
    "connect_verbose_info": 0,
    "redirect": "",
    "fast_open": false
}
	""" %(ssrString[0],ssrString[1],password,ssrString[3],ssrString[2],ssrString[4])
	
	with open(ssr_config,'w') as fout :
		fout.write(config_json)

	print '\033[1;32m[+] Success\n'

def install():
	os.system('sudo git clone -b manyuser https://github.com/shadowsocksr-backup/shadowsocksr.git %s' %install_path)
	os.system('apt-get install CMake libevent-dev libpcap-dev -y')
	os.system('rm -rvf /usr/src/libsodium-1.0*')
	os.system('cd /usr/src &&\
		wget https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz &&\
		tar zxvf libsodium-1.0.16.tar.gz &&\
		cd libsodium-1.0.16 &&\
		./configure --prefix=/usr &&\
		make && make install')

	os.system('rm -rvf Pcap_DNSProxy')
	os.system('cd /usr/src &&\
		git clone https://github.com/chengr28/Pcap_DNSProxy.git &&\
		cd Pcap_DNSProxy/Source/Auxiliary/Scripts &&\
		chmod +x CMake_Build.sh &&\
		./CMake_Build.sh &&\
		cp -r /usr/src/Pcap_DNSProxy/Source/Release /usr/local/Pcap_DNSProxy')


	os.system('mv /usr/local/Pcap_DNSProxy/Config.conf /usr/local/Pcap_DNSProxy/Config.conf.bak')
	with open('/usr/local/Pcap_DNSProxy/Config.conf','w') as fout:
		fout.write('%s' %pcap_config)

	os.system('mv /etc/redsocks.conf /etc/redsocks.conf.bak')
	with open('/etc/redsocks.conf','w') as fout:
		fout.write('%s' %redsocks_config)


	os.system('cp /etc/dhcp/dhclient.conf /etc/dhcp/dhclient.conf.bak')
	with open('/etc/dhcp/dhclient.conf','r') as fout:
		dhclient = fout.read()
		dhclient = re.sub('(.+pend domain-name-servers.+)', 'prepend domain-name-servers 127.0.0.1;', dhclient)
		with open('/etc/dhcp/dhclient.conf','w') as fout:
			fout.write(dhclient)

	os.system('rm -rvf /usr/src/libsodium-1.0*')
	os.system('rm -rvf Pcap_DNSProxy')
	os.system('sudo service network-manager restart')
	print '\033[1;32m[+] Success\n'


def uninstall():
	print "are you to remove shadowsocksr related documents?(y/N)"
	if raw_input() == 'y':
		os.system('killall Pcap_DNSProxy 2>/dev/null')
		os.chdir(work_path)
		os.system('sudo python local.py -d stop &&\
			sudo service redsocks stop &&\
			iptables -t nat -D OUTPUT -p tcp -j SHADOWSOCKS &&\
			sudo iptables -t nat -F SHADOWSOCKS &&\
			sudo iptables -t nat -X SHADOWSOCKS')


		os.system('sudo rm -rvf %s' %install_path)
		os.system('cd /etc/init.d &&\
					service PcapDNSProxyService stop &&\
					insserv -r PcapDNSProxyService &&\
					killall Pcap_DNSProxy 2>/dev/null &&\
					rm -rf PcapDNSProxyService')


        os.system('sudo rm -rvf /usr/local/Pcap_DNSProxy/')
        os.system('mv /etc/redsocks.conf.bak /etc/redsocks.conf')
        os.system('mv /etc/dhcp/dhclient.conf.bak /etc/dhcp/dhclient.conf')
        os.system('sudo service network-manager restart')


def config():
	os.chdir(work_path)
	os.system('vi %s' %ssr_config)
	os.system('sudo python local.py -d stop')
	os.system('sudo python local.py -d start')

def start():
	
	with open(ssr_config,'r') as fout:
		string = fout.read()
		ip = re.findall(r'server.*?"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',string)[0]
	os.chdir(work_path)
	os.system('sudo python local.py -d start') 
	os.system('cd /usr/local/Pcap_DNSProxy && ./Pcap_DNSProxy start')
	os.system('sudo service redsocks start &&\
sudo iptables -t nat -N SHADOWSOCKS &&\
sudo iptables -t nat -A SHADOWSOCKS -d %s -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 0.0.0.0/8 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 10.0.0.0/8 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 127.0.0.0/8 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 169.254.0.0/16 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 172.16.0.0/12 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 192.168.0.0/16 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 224.0.0.0/4 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -d 240.0.0.0/4 -j RETURN &&\
sudo iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-port 12345 &&\
sudo iptables -t nat -A OUTPUT -p tcp -j SHADOWSOCKS' %ip)
	print '[+]start proxy global'
	print '\tserver ip: %s\n' %ip

def stop():
	os.chdir(work_path)
	os.system('sudo python local.py -d stop &&\
sudo service redsocks stop &&\
killall Pcap_DNSProxy 2>/dev/null &&\
iptables -t nat -D OUTPUT -p tcp -j SHADOWSOCKS &&\
sudo iptables -t nat -F SHADOWSOCKS &&\
sudo iptables -t nat -X SHADOWSOCKS')

	print '[-] close proxy\n'


def main():
	if sys.argv[1] == 'install':
		install()

	if sys.argv[1] == 'uninstall':
		uninstall()

	if sys.argv[1] == 'config':
		config()

	if sys.argv[1] == 'start':
		start()

	if sys.argv[1] == 'stop':
		stop()


	if 'ssr://' in sys.argv[1]:
		subscribe(sys.argv[1])

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print"""if you have not install ssr global configure, please run "ssr install"
Usage:
	ssr_global.py config : edit config.json
	ssr_global.py install : install shadowsocksr client
	ssr_global.py uninstall : uninstall shadowsocksr client
	ssr_global.py start : start the shadowsocks service
	ssr_global.py stop : stop the shadowsocks service
	ssr_global.py ssr://base64... : import ssr:// link to config.json
	"""
		sys.exit()

	main()
