import re
import os
import sys
import base64

install_path = '/usr/local/share/shadowsocksr/'
work_path = '/usr/local/share/shadowsocksr/shadowsocks/'
ssr_config = '/usr/local/share/shadowsocksr/config.json'

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
	
		print """\033[1;32m
server: %s
server_port: %s
password: %s
method: %s
protocol: %s
obfs: %s
""" %(ssrString[0],ssrString[1],password,ssrString[3],ssrString[2],ssrString[4])
	except:
		print "error"
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

	print '\033[1;31m[+] Configuration updated\n'

def install():
	os.system('sudo git clone -b manyuser https://github.com/shadowsocksr-backup/shadowsocksr.git %s' %install_path)

def uninstall():
	print "Danger! are you to remove %s forever?(y/N)" %install_path
	if raw_input() == 'y':
		os.system('sudo rm -rvf %s' %install_path)

def config():
	os.chdir(work_path)
	os.system('vim %s' %ssr_config)
	os.system('sudo python local.py -d stop')
	os.system('sudo python local.py -d start')

def start():
	os.chdir(work_path)
	os.system('sudo python local.py -d start')

def stop():
	os.chdir(work_path)
	os.system('sudo python local.py -d stop')

def log():
	os.system('sudo tail -f /var/log/shadowsocks.log')

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

	if sys.argv[1] == 'log':
		log()

	if 'ssr://' in sys.argv[1]:
		subscribe(sys.argv[1])

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print"""if you have not install ssr, please run "ssr install"
Usage:
	ssr config : edit config.json
	ssr install : install shadowsocksr client
	ssr uninstall : uninstall shadowsocksr client
	ssr start : start the shadowsocks service
	ssr stop : stop the shadowsocks service
	ssr ssr://base64... : import ssr:// link to config.json
	"""
		sys.exit()

	main()