import json
import time
import sys
import logging
import socket
import IndicatorTypes
import time
import subprocess

# Third library
from OTXv2 import OTXv2
from scapy.all import *
import dpkt
from natsort import natsorted
import psutil

Input_dir = "Input/"
has_no_behavior_malware_dir = "has_no_behavior_malware/"
has_behavior_malware_dir    = "has_behavior_malware/"
not_analysis_dir     = "not_analysis/"
already_analysis_dir = "already_analysis/"
PcapSplitter_path = "./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter" # PcapSplitter path
cuckoo_storage_path = "/opt/cuckoo/storage/analyses/"
cuckoo_path = "/opt/cuckoo/"
is_analysis_dir= []
neccesary_dirs = ["not_analysis/", "has_no_behavior_malware/", 
				 "has_behavior_malware/", "already_analysis/"]
				 
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

# If Ip is malicious, return True else return False
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

# If pcap has mailicious flow, return True
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
	
# submit the sample to cuckoo	
def submit_sample_to_cuckoo():

	exe_names = os.listdir(not_analysis_dir)	
	now_path = os.getcwd()	
	os.chdir(cuckoo_path)
	
	for exe_name in exe_names:
		cmd = "cuckoo submit " + now_path + "/" + not_analysis_dir + exe_name
		os.system(cmd)
	os.chdir(now_path)

	exe_number = len(exe_names)
	
	return exe_number

# check if there has after running exe or not
def check_have_analysis_or_not():
	after_running_dirs = os.listdir(Input_dir)
	after_running_dirs = natsorted(after_running_dirs)
	
	can_be_check_dirs = []
	
	for after_running_dir in after_running_dirs:
		if (after_running_dir not in ['.gitignore', 'latest']) and (after_running_dir not in is_analysis_dir):
			log_file_name = Input_dir + after_running_dir + "/cuckoo.log"
			
			if os.path.isfile(log_file_name):
				with open(log_file_name, 'r') as f:
					lines = f.read().splitlines()
					if len(lines) > 0:						
						analysis_log = lines[-1]			
						if analysis_log[-28:] == "analysis procedure completed":
							 can_be_check_dirs.append(after_running_dir)			
			
	return can_be_check_dirs

# get exe file name based on cuckoo task.json
def get_exe_name(can_be_check_dir):
	json_file_path = Input_dir + can_be_check_dir + "/task.json"
	
	if os.path.isfile(json_file_path) == False:
		return None
	 
	with open(json_file_path,'r') as file:
		for i, line in enumerate(file.readlines()):
			dic = json.loads(line)
			file_path = dic["target"]
			exe_name = file_path.split("/")[-1][:-4]
			
			if os.path.isdir(exe_name) == False:
				os.mkdir(exe_name)
				
			return exe_name
			
# split pcap by 5 tuples rule
def split_pcap(can_be_check_dir, exe_name):
	pcap_file_name = Input_dir + can_be_check_dir + "/dump.pcap"
	cmd = PcapSplitter_path + ' -f ' + pcap_file_name + " -m connection -o " + exe_name
	os.system(cmd)

# check the every pcap has malicous behavior or not
def check_malicious_flow(exe_name):
	split_filenames = os.listdir(exe_name)	
	for split_filename in split_filenames:
		full_filename = exe_name + "/" + split_filename
		pcap = rdpcap(full_filename)
		is_malisious = check_pcap_malicious(pcap)		
		if is_malisious == False:
			cmd = "rm " + exe_name + "/" + split_filename
			os.system(cmd)
			
# If you submit duplicated sample, it will alert
def recaptcha():
	ans = "no"
	while str(ans) != 'yes':
		try:
			ans = input('please enter "yes" after you check:')		
		except:
			pass	
	return 	
	
# check the exe malicious flow nubmer
def check_result(exe_name):
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
	
	cmd = "mv " + not_analysis_dir + exe_name + ".exe" + " " + already_analysis_dir
	os.system(cmd)
	
	return malicious_pcap_number


def checkIfProcessRunning(processName):
    '''
    Check if there is any running process that contains the given name processName.
    '''
    #Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False
    
   
def findProcessIdByName(processName):
    '''
    Get a list of all the PIDs of a all the running process whose name contains
    the given string processName
    '''
 
    listOfProcessObjects = []
 
    #Iterate over the all the running process
    for proc in psutil.process_iter():
       try:
           pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time'])
           # Check if process name contains the given name string.
           if processName.lower() in pinfo['name'].lower() :
               listOfProcessObjects.append(pinfo)
       except (psutil.NoSuchProcess, psutil.AccessDenied , psutil.ZombieProcess) :
           pass
 
    return listOfProcessObjects

# check the cuckoo and virtualbox is running
def check_environment():
	print("=" * 80)
	print("Now checking VirtualBox is running or not...")
	if checkIfProcessRunning("VirtualBox"):
		print("OK! VirtualBox is running.")
	else:
		print("Please open VirtualBox!")
		return False
	
	print("=" * 80)
	print("Now shutdown Cuckoo...")
	if checkIfProcessRunning("Cuckoo"):
		listOfProcessIds = findProcessIdByName("Cuckoo")
		for elem in listOfProcessIds:
			processID = elem['pid']
			os.system("kill " + str(processID))
			print("kill " + str(processID))	
	
	for neccesary_dir in neccesary_dirs:
		if os.path.isdir(neccesary_dir) == False:
			os.mkdir(neccesary_dir)
	
	# clean the database
	now_path = os.getcwd()		
	os.chdir(cuckoo_path)
	
	print("=" * 80)
	print("Clean the Input directory and stop any analysis...")
	os.system("cuckoo clean")
	time.sleep(1)		
	os.chdir(now_path)
	subprocess.Popen("python cuckoo.py", shell=True,stdin=None, stdout=None, stderr=None, close_fds=True)
	print("Restart Cuckoo...")	
	time.sleep(10)
	
	return True
	
def main():
	environment_is_ok = check_environment()
	if environment_is_ok == False:		
		return 
	
	print("=" * 80)
	exe_number = submit_sample_to_cuckoo()	
	print("Total has " + str(exe_number) + " exe need to run")	
	
	while exe_number > 0:
		can_be_check_dirs = check_have_analysis_or_not()
	
		for can_be_check_dir in can_be_check_dirs:
			print("=" * 80)
			print("now processing " + can_be_check_dir)
			print("-" * 80)		
		
			exe_name = get_exe_name(can_be_check_dir)
			if exe_name == None:
				continue		
			split_pcap(can_be_check_dir, exe_name)		
			check_malicious_flow(exe_name)
			malicious_pcap_number = check_result(exe_name)
		
			print("-" * 80)
			print(exe_name + " has " + str(malicious_pcap_number) + " malicious flows")
			print("=" * 80)
			
			time.sleep(5)			
			os.system("rm -r " + Input_dir + can_be_check_dir)
			exe_number -= 1
			is_analysis_dir.append(can_be_check_dir)
			
		time.sleep(10)			
	
	print("Finishing running")
		
if __name__ == '__main__':
	main()
