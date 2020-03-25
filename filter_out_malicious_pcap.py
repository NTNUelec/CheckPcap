import json
import time
import sys
import logging
import socket
import IndicatorTypes
import time
import csv
import datetime
import argparse

# Third library
from OTXv2 import OTXv2
from scapy.all import *
import dpkt
from natsort import natsorted
import psutil

Input_dir                   = "Input/"
has_no_behavior_malware_dir = "has_no_behavior_malware/"
has_behavior_malware_dir    = "has_behavior_malware/"
not_analysis_dir            = "not_analysis/"
already_analysis_dir        = "already_analysis/"
PcapSplitter_path           = "./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter" # PcapSplitter path
cuckoo_storage_path         = "/opt/cuckoo/storage/analyses/"
cuckoo_path                 = "/opt/cuckoo/"
Csv_dir                     = "csv_report/"
neccesary_dirs              = ["not_analysis/", "has_no_behavior_malware/", 
				 			   "has_behavior_malware/", "already_analysis/"]
vm_name = "cuckoo1"

was_analysis_dir= []
result_dic = dict()
				 
API_KEY = 'f12f1aa045dadd4a269fc9bd74e2a5dd7f2b02eb8fa2111e86d6f7d75dbddc11'  #change your API_Key
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

parser = argparse.ArgumentParser(description='Download SANS OnDemand videos using this script.')
parser.add_argument("-d", "--duplicated", help="deprecate duplicated sample", action="store_true")
args = parser.parse_args()

# Check the cuckoo and virtualbox is running
def check_environment():
	print("=" * 80)
	print("Now checking VirtualBox is running or not...")

	if checkIfProcessRunning("VirtualBox"):
		print("OK! VirtualBox is running.")
	else:
		print("Warning! VirtualBox is not running.")
		print("Now start VirtualBox!")
		# check you have VirtualBox or not 
		usr_bin_file_names = os.listdir("/usr/bin")
		usr_local_bin_file_names = os.listdir("/usr/local/bin")		
		if "virtualbox" not in usr_bin_file_names and "virtualbox" not in usr_local_bin_file_names: 
			print("Error! You don't install VirtualBox")
			return False
		cmd = "gnome-terminal -x python virtualbox.py"
		os.system(cmd)
		time.sleep(5)
		cmd = "VBoxManage startvm " + vm_name
		os.system(cmd)
		time.sleep(5)
	
	print("=" * 80)
	print("Before analyzing, we need to clean database.")
	print("Now checking Cuckoo is running or not...")
	
	if checkIfProcessRunning("Cuckoo"):
		print("Warning! Cuckoo is running.")
		print("Now shutdown Cuckoo...")
		listOfProcessIds = findProcessIdByName("Cuckoo")
		for elem in listOfProcessIds:
			processID = elem['pid']
			cmd = "kill " + str(processID)
			os.system(cmd)
			print("kill " + str(processID))
	else:
		print("OK! Cuckoo is not running.")

	for neccesary_dir in neccesary_dirs:
		if os.path.isdir(neccesary_dir) == False:
			os.mkdir(neccesary_dir)
	
	# clean the database
	now_path = os.getcwd()		
	os.chdir(cuckoo_path)
	
	print("=" * 80)
	print("Now clean the Input directory and stop any analysis...")
	# check you have cuckoo or not 
	usr_bin_file_names = os.listdir("/usr/bin")
	usr_local_bin_file_names = os.listdir("/usr/local/bin")		
	if "cuckoo" not in usr_bin_file_names and "cuckoo" not in usr_local_bin_file_names: 
		print("Error! You don't install cuckoo")
		return False

	cmd = "cuckoo clean"
	os.system(cmd)
	time.sleep(1)

	os.chdir(now_path)
	print("Now start Cuckoo...")
	cmd = "gnome-terminal -x python cuckoo.py"
	os.system(cmd)	
	time.sleep(10)
	
	return True

# Submit the sample to cuckoo	
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

# Check if there has after running exe or not
def check_have_analysis_or_not():
	after_running_dirs = os.listdir(Input_dir)
	after_running_dirs = natsorted(after_running_dirs)
	
	can_be_check_dirs = []
	
	for after_running_dir in after_running_dirs:
		if (after_running_dir not in ['.gitignore', 'latest']) and (after_running_dir not in was_analysis_dir):
			log_file_name = Input_dir + after_running_dir + "/cuckoo.log"
			
			if os.path.isfile(log_file_name):
				with open(log_file_name, 'r') as f:
					lines = f.read().splitlines()
					if len(lines) > 0:						
						analysis_log = lines[-1]			
						if analysis_log[-28:] == "analysis procedure completed":
							 can_be_check_dirs.append(after_running_dir)			
			
	return can_be_check_dirs

# Get exe file name based on cuckoo task.json
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
			else:	
				cmd = "rm -r " + exe_name
				os.system(cmd)
				os.mkdir(exe_name)
				
			return exe_name
			
# Split pcap by 5 tuples rule
def split_pcap(can_be_check_dir, exe_name):
	pcap_file_name = Input_dir + can_be_check_dir + "/dump.pcap"
	cmd = PcapSplitter_path + ' -f ' + pcap_file_name + " -m connection -o " + exe_name
	os.system(cmd)

# The function used for check_Ip_malicious
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
def check_Ip_malicious(otx, ip):
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
		
	# check tcp with hand shake or not 
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
		
	return check_Ip_malicious(otx, dst_ip)
	
# Check the every pcap has malicous behavior or not
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
	
# Check the exe malicious flow nubmer
def check_result(exe_name):
	malicious_pcap_number = len(os.listdir(exe_name))
	
	if os.path.isdir(has_behavior_malware_dir + exe_name):
		already_pcap_number = len(os.listdir(has_behavior_malware_dir + exe_name))
	else:
		already_pcap_number = 0

	pcap_names = os.listdir(exe_name)
	for i, pcap_name in enumerate(pcap_names):
		new_pcap_name = exe_name + "_" + str(i + already_pcap_number) + ".pcap"
		cmd = "mv " + exe_name + "/" + pcap_name + " " + exe_name + "/" + new_pcap_name
		os.system(cmd)

	if malicious_pcap_number > 0:
		if os.path.isdir(has_behavior_malware_dir + exe_name):
			print(exe_name + " has already test, please check")
			if args.duplicated:
				cmd = "rm -r " + exe_name
			else:
				pcap_names = os.listdir(exe_name)
				for i, pcap_name in enumerate(pcap_names):					
					cmd = "mv " + exe_name + "/" + pcap_name + " " + has_behavior_malware_dir + exe_name + "/" + pcap_name
					os.system(cmd)
		else:
			cmd = "mv " + exe_name + " " + has_behavior_malware_dir
			os.system(cmd)
	else:
		if os.path.isdir(has_no_behavior_malware_dir + exe_name):	
			print(exe_name + " has already test, please check")			
			cmd = "rm -r " + exe_name
			os.system(cmd)
		else:
			cmd = "mv " + exe_name + " " + has_no_behavior_malware_dir
			os.system(cmd)
	
	cmd = "mv " + not_analysis_dir + exe_name + ".exe" + " " + already_analysis_dir
	os.system(cmd)
	
	return malicious_pcap_number

# Check if there is any running process that contains the given name processName.
def checkIfProcessRunning(processName):
    # Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False
    
# Get a list of all the PIDs of a all the running process whose name contains  the given string processName
def findProcessIdByName(processName):
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


def write_result_to_csv():
	if os.path.isdir(Csv_dir) == False:
		os.mkdir(Csv_dir)

	file_name = Csv_dir + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ".csv"

	with open(file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')
		writer.writerow(['md5 value', '1 time pcap number'])
		for md5, times in result_dic.items():
			writer.writerow([md5, times])

def main():
	malicious_exe_number = 0
	not_malicious_exe_number = 0
	
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
			
			exe_number -= 1
			was_analysis_dir.append(can_be_check_dir)
			result_dic[exe_name] = malicious_pcap_number

			if malicious_pcap_number > 0:
				malicious_exe_number += 1
			else:
				not_malicious_exe_number += 1

		time.sleep(10)			
	
	print("Finishing running")
	print("Malicious exe number: " + str(malicious_exe_number))
	print("Benign    exe number: " + str(not_malicious_exe_number))

	if len(result_dic) > 0:
		write_result_to_csv()
		print("You can see detail in " + Csv_dir)

if __name__ == '__main__':
	main()
