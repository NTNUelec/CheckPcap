import json
import time
import sys
import logging
import socket
import IndicatorTypes

# Third library
from OTXv2 import OTXv2
from scapy.all import *
import dpkt
from natsort import natsorted
import fnmatch

Input_dir = "Input/"
has_no_behavior_malware_dir = "has_no_behavior_malware/"
has_behavior_malware_dir    = "has_behavior_malware/"
not_analysis_dir     = "not_analysis/"
already_analysis_dir = "already_analysis/"
PcapSplitter_path = "./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter" # PcapSplitter path
cuckoo_storage_path = "/opt/cuckoo/storage/analyses/"
cuckoo_path = "/opt/cuckoo/"

url = 'http://ip.taobao.com/service/getIpInfo.php?ip='
API_KEY = 'f12f1aa045dadd4a269fc9bd74e2a5dd7f2b02eb8fa2111e86d6f7d75dbddc11'  #change your API_Key
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)


def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results


def Check_Ip_malicious(otx, ip):
    alerts = []
    try:
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
    # if can't analyze ip address
    except:
    	return False    
    
    pulses = getValue(result, ['pulse_info', 'pulses'])    
    if pulses:
        for pulse in pulses:
            if 'name' in pulse:            	
                alerts.append('In pulse: ' + pulse['name'])
    
    if len(alerts) > 0:
        return True
    else:
        return False


def check_pcap_malicious(pcap):
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80
	
	pkt_1 = pcap[0]	
	
	# check is tcp or udp	
	if (TCP not in pkt_1) and (UDP not in pkt_1):
		return False    
    	
	dst_ip = pkt_1[IP].dst
	src_ip = pkt_1[IP].src
	
	# check not NTP
	if (NTP in pkt_1):		
		return False
	
	# check not DNS
	if (DNS in pkt_1):		
		return False
		
	# check with hand shake in tcp
	if TCP in pkt_1:
		if len(pcap) < 4:
			return False
		else:			
			pkt_1_flag = pcap[0]['TCP'].flags			
			pkt_2_flag = pcap[1]['TCP'].flags				
			pkt_3_flag = pcap[2]['TCP'].flags	
			
			if (pkt_1_flag & SYN) == False:
				return False
			if (pkt_2_flag & SYN and pkt_2_flag & ACK) == False:
				return False
			if (pkt_3_flag & ACK) == False:
				return False	
		
	return Check_Ip_malicious(otx, dst_ip)


def get_exe_name(json_file_path):
	with open(json_file_path,'r') as file:
		for i, line in enumerate(file.readlines()):
			dic = json.loads(line)
			file_path = dic["target"]
			file_name = file_path.split("/")[-1][:-4]
			return file_name


def recaptcha():
	ans = "no"
	while str(ans) != 'yes':
		try:
			ans = input('please enter "yes" after you check:')		
		except:
			pass	
	return 

"""
# submit the sample to cuckoo	
def submit_sample_to_cuckoo():
	now_path = os.getcwd()	
	os.chdir(cuckoo_path)
	exe_names = os.listdir(not_analysis_dir)
	for exe_name in exe_names:
		cmd = "cuckoo submit " + now_path + "/" + not_analysis_dir + exe_name
		os.system(cmd)
	os.chdir(now_path)

	exe_number = len(exe_names)
	
	return exe_number


# check if there are after running exe or not
def check_have_analysis_or_not():
	after_running_dirs = os.listdir(cuckoo_storage_path)
	after_running_dirs = natsorted(after_running_dirs)
	
	if len(after_running_dirs) > 1:
		after_running_dirs = after_running_dirs[:-1]
		return after_running_dirs
	else:
		return None
	
def main():
	exe_number = submit_sample_to_cuckoo()
	
	while exe_number > 0:
		after_running_dirs = check_have_analysis_or_not()
		if after_running_dirs 
"""
def main():	
	file_names = os.listdir(Input_dir)
	file_names = natsorted(file_names)			
	
	for file_name in file_names:
		if file_name in ['.gitignore', 'latest']:
			continue
			
		print("now processing " + file_name)
		print("-" * 80)
	
		# get exe file name
		json_file_path = Input_dir + file_name + "/task.json"
		exe_name = get_exe_name(json_file_path)				
	
		if os.path.isdir(exe_name) == False:
			os.mkdir(exe_name)
	
		# split pcap by 5 tuples rule
		pcap_file_name = Input_dir + file_name + "/dump.pcap"
		cmd = PcapSplitter_path + ' -f ' + pcap_file_name + " -m connection -o " + exe_name
		os.system(cmd)	
	
		# check the every pcap has malicous behavior or not
		split_filenames = os.listdir(exe_name)	
		for split_filename in split_filenames:
			full_filename = exe_name + "/" + split_filename
			pcap = rdpcap(full_filename)
			is_malisious = check_pcap_malicious(pcap)		
			if is_malisious == False:
				cmd = "rm " + exe_name + "/" + split_filename
				os.system(cmd)						
	
	
		# check the exe malicious flow nubmer
		malicious_pcap_number = len(os.listdir(exe_name))
	
		if malicious_pcap_number > 0:
			if os.path.isdir(has_behavior_malware_dir + exe_name) == False:
				cmd = "mv " + exe_name + " " + has_behavior_malware_dir				
			else:		
				print(exe_name + " has already test, please check")
				recaptcha()
				cmd = "rm -r " + exe_name
		else:
			if os.path.isdir(has_no_behavior_malware_dir + exe_name) == False:
				cmd = "mv " + exe_name + " " + has_no_behavior_malware_dir				
			else:		
				print(exe_name + " has already test, please check")
				recaptcha()
				cmd = "rm -r " + exe_name
			
		os.system(cmd)
	
		print("-" * 80)
		print(exe_name + " has " + str(malicious_pcap_number) + " malicious flows")
		print("=" * 80)
	
		# If you want to rm dir after analyzing, you can uncommnet below line
		os.system("rm -r " + Input_dir + file_name)			
		
if __name__ == '__main__':
	main()
