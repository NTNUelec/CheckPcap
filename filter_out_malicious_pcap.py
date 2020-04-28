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
import requests
import json

# Third library
from OTXv2 import OTXv2
from scapy.all import *
import dpkt
from natsort import natsorted
import psutil

# our library
from config import *

was_analysis_dir= []
result_dic = dict()
exe_analysis_time_dic = dict()

# Check if there is any running process that contains the given name processName.
def check_if_process_running(processName):
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
def get_process_Id_by_name(processName):
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
    
# Check the cuckoo and virtualbox is running
def check_environment():
    print("=" * 80)
    print("Now checking VirtualBox is running or not...")

    if check_if_process_running("VirtualBox"):
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
    
    if check_if_process_running("Cuckoo"):
        print("Warning! Cuckoo is running.")
        print("Now shutdown Cuckoo...")
        listOfProcessIds = get_process_Id_by_name("Cuckoo")
        for elem in listOfProcessIds:
            processID = elem['pid']
            cmd = "kill " + str(processID)
            os.system(cmd)
            print("kill " + str(processID))
    else:
        print("OK! Cuckoo is not running.")
    
    # check you have neccesary directories
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
def submit_sample_to_cuckoo(args):
    timeout = args.timeout
    exe_names = os.listdir(not_analysis_dir)    
    now_path = os.getcwd()  
    os.chdir(cuckoo_path)
    exe_number = 0
    
    for exe_name in exe_names:
        if exe_name[-4:] != ".exe":
            continue
        for i in range(args.count):
            cmd = "cuckoo submit --timeout " + str(timeout) + " " + now_path + "/" + not_analysis_dir + exe_name
            os.system(cmd)
            exe_number += 1
        
    os.chdir(now_path)
    
    return exe_number

# Check if there has after running exe or not
def get_have_analysis_or_not():
    after_running_dirs = os.listdir(Input_dir)
    after_running_dirs = natsorted(after_running_dirs)
    
    can_be_check_dirs = []
    
    for after_running_dir in after_running_dirs:
        if (after_running_dir not in ['.gitignore', 'latest']) and (after_running_dir not in was_analysis_dir):
            log_file_name = Input_dir + "/" +  after_running_dir + "/cuckoo.log"
            
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
    json_file_path = Input_dir + "/" + can_be_check_dir + "/task.json"
    
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
    pcap_file_name = Input_dir + "/" + can_be_check_dir + "/dump.pcap"
    cmd = PcapSplitter_path + ' -f ' + pcap_file_name + " -m connection -o " + exe_name
    os.system(cmd)

# The function used for check_ip_malicious_alienvault
def get_value_for_alienvault(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return get_value_for_alienvault(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return get_value_for_alienvault(results[0], keys)
            else:
                return results
    else:
        return results

# Based on alienvault, check IP is malicious or not
def check_ip_malicious_alienvault(ip):
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(alienvault_api_key, server=OTX_SERVER)

    alerts = []
    try:
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
    # if can't analyze ip address
    except:
        return False    
    
    pulses = get_value_for_alienvault(result, ['pulse_info', 'pulses'])    
    if pulses:
        for pulse in pulses:
            if 'name' in pulse:             
                alerts.append('In pulse: ' + pulse['name'])
    
    if len(alerts) > 0:
        return True
    else:
        return False
        
# Based on alienvault, check IP is malicious or not
def check_ip_malicious_virustotal(ip):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey':virus_total_api_key,'ip': ip}

    response = requests.get(url, params=params)
    
    try:
        result = response.json()['detected_urls'][0]["positives"]
    except:
        return False
    
    if result > 0:
        return True
    else:
        return False
        

# If pcap has mailicious flow, return True
def check_flow_malicious(pcap, args):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
    SYN_ACK = (SYN | ACK)
    
    pkt_1 = pcap[0]     
    
    # check is tcp or udp   
    if (TCP not in pkt_1) and (UDP not in pkt_1):
        return False, 'notfound', 'notfound'    

    dst_ip = pkt_1[IP].dst
    src_ip = pkt_1[IP].src  
    
    if (TCP in pkt_1):
        dst_port = pkt_1[TCP].dport
        src_port = pkt_1[TCP].sport
    elif (UDP in pkt_1):
        dst_port = pkt_1[UDP].dport
        src_port = pkt_1[UDP].sport
	
	# query IP info
    ip_info = None
    try:
        ip_info_url = "http://ip-api.com/json/" + dst_ip + "?fbclid=IwAR0trByJ6IdU2KCFw7eM7I6Nz_yoBSj980iJCM8UFbpd2kNKik3-YFfqYFA"
        ip_info_res = requests.get(ip_info_url)
        ip_info = ip_info_res.json()
    except:
        time.sleep(5)
        return False, 'notfound', 'notfound'

    if ip_info['status'] == 'fail':
        ip_info['country'] = 'notfound'
        
    
    # check not NTP
    if (NTP in pkt_1):      
        return False, dst_ip, ip_info['country']    
    
    # check not NBNS
    if dst_port == 137 and src_port == 137:
        return False, dst_ip, ip_info['country']    
    
    # check not SSDP
    if dst_port == 1900:
        return False, dst_ip, ip_info['country']        
    
    # check not DNS
    if (DNS in pkt_1):
        if args.keepdns:
            domain_name = pkt_1[DNS].summary().split(" ")[-2].strip('"').strip('.')
            return "DNS", domain_name, ip_info['country']    
        else:
            return False, dst_ip, ip_info['country']    
        
    # check tcp with hand shake or not 
    if TCP in pkt_1:
        if len(pcap) < 4:
            return False, dst_ip, ip_info['country']    
        else:           
            pkt_1_flag = int(pcap[0]['TCP'].flags)          
            pkt_2_flag = int(pcap[1]['TCP'].flags)          
            pkt_3_flag = int(pcap[2]['TCP'].flags)  
            
            if (pkt_1_flag != SYN):
                return False, dst_ip, ip_info['country']    
            if (pkt_2_flag != SYN_ACK):
                return False, dst_ip, ip_info['country']  
            if (pkt_3_flag != ACK):
                return False, dst_ip, ip_info['country']      


    if args.filterbenign:
        fp = open('benign_ip_list.txt', "r")
        lines = fp.readlines()
        fp.close()
        for line in lines:
            benign_ip = line.strip()
            if dst_ip == benign_ip:
                return False, dst_ip, ip_info['country']    
    
    
    if args.virustotal:
        return check_ip_malicious_virustotal(dst_ip), dst_ip, ip_info['country']
    else:
        return check_ip_malicious_alienvault(dst_ip), dst_ip, ip_info['country']
    
# Check the every pcap has malicous behavior or not
def check_pcap_malicious(exe_name, args):
    ip_info={}
    domain_name_list=[]

    split_filenames = os.listdir(exe_name)  
    for split_filename in split_filenames:
        full_filename = exe_name + "/" + split_filename
        pcap = rdpcap(full_filename)
        is_malisious, flow_dst_ip, flow_dst_ip_country = check_flow_malicious(pcap, args)
        
        if is_malisious == "DNS":
            if args.keepdns:
                if os.path.isdir("dns_query/" + exe_name) == False:
                    cmd = "mkdir dns_query/" + exe_name
                    os.system(cmd)
                cmd = "mv " + exe_name + "/" + split_filename + " " + "dns_query/" + exe_name               
                os.system(cmd)
                
        elif is_malisious == False:
            cmd = "rm " + exe_name + "/" + split_filename
            os.system(cmd)

        if is_malisious != "DNS" and is_malisious==True:
            ip_info[flow_dst_ip] = flow_dst_ip_country
        elif is_malisious == "DNS":
            default_dns = ["ipv6.msftncsi.com",	"teredo.ipv6.microsoft.com", "1.56.168.192.in-addr.arpa", "dns.msftncsi.com"]
            if flow_dst_ip not in default_dns:
                domain_name_list.append(flow_dst_ip)
    
    return ip_info, list(set(domain_name_list))

            
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
def check_result(exe_name, args):

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
                cmd = "rm -r " + exe_name
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
    
    if exe_name not in exe_analysis_time_dic.keys():
        exe_analysis_time_dic[exe_name] = 1
    else:
        exe_analysis_time_dic[exe_name] += 1

    if exe_analysis_time_dic[exe_name] == args.count:
        cmd = "mv " + not_analysis_dir + exe_name + ".exe" + " " + already_analysis_dir
        os.system(cmd)
    
    return malicious_pcap_number

# Record the exe and the number of malicious flow which it generates.
def write_result_to_csv():
    if os.path.isdir(Csv_dir) == False:
        os.mkdir(Csv_dir)

    file_name = Csv_dir + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ".csv"

    with open(file_name, 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['md5 value', '1 time pcap number'])
        for md5, times in result_dic.items():
            writer.writerow([md5, times])

# Check api key is valid or not (default use alienvault)
def check_api_key_state(args):
    print("=" * 80)
    print("Now checking api key is valid or not...")
    
    test_ip = "8.8.8.8"
    
    if args.virustotal == False:
        OTX_SERVER = 'https://otx.alienvault.com/'
        otx = OTXv2(alienvault_api_key, server=OTX_SERVER)
        try:
            result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, test_ip, 'general')
            print("Your alienVault API Key is valid.")
            return True     
        except:
            print("Your alienVault API Key is Invalid, Please check")
            return False 
        
    elif args.virustotal == True:
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey':virus_total_api_key,'ip': test_ip}
        response = requests.get(url, params=params)
    
        try:
            result = response.json()
            print("Your virustotal API Key is valid.")
            return True
        except:
            print("Your virustotal API Key is Invalid, Please check")
            return False


def generate_json_analysis(args, ip_info, domain_name_list, malicious_pcap_number):
	if args.jsonformat:
		malware_json = None
		
		json_path = "malware_jsons/" + exe_name + ".json"
		with open(json_path) as json_file:
		    malware_json = json.load(json_file)
		json_file.close()

		malware_json['ip_info'] = ip_info
		malware_json['domain_name'] = domain_name_list
		malware_json['num_malicious_flow'] = malicious_pcap_number

		with open(json_path, 'w') as json_file_out:
		    json.dump(malware_json, json_file_out)		    
		json_file_out.close()	
		
	return
    
    
def main():
    parser = argparse.ArgumentParser(description='Download SANS OnDemand videos using this script.')
    parser.add_argument("-d", "--duplicated",   help="If the sample has already run, it will deprecate the pcap result.", action="store_true")
    parser.add_argument("-v", "--virustotal",   help="If you have virustotal api key, you can use this parameter.", action="store_true")
    parser.add_argument("-k", "--keepdns",      help="If you want keep dns query, you can use this parameter.", action="store_true")
    parser.add_argument("-t", "--timeout",      help="Determine one sample run time.", type=int, default=180)
    parser.add_argument("-c", "--count",        help="How many time of one sample should run.", type=int, default=1)
    parser.add_argument("-j", "--jsonformat",   help="If you want to change record format to json, you can use this parameter.", action="store_true")
    parser.add_argument("-f", "--filterbenign", help="If you want to filter benign IP, you can use this parameter.", action="store_true")

    args = parser.parse_args()
    
    malicious_exe_number = 0
    not_malicious_exe_number = 0    
    
    api_key_is_ok = check_api_key_state(args)
    if api_key_is_ok == False:      
        return 
        
    environment_is_ok = check_environment()
    if environment_is_ok == False:      
        return 
    
    print("=" * 80)
    exe_number = submit_sample_to_cuckoo(args)  
    print("Total has " + str(exe_number) + " exe need to run") 
        
    while exe_number > 0:

        can_be_check_dirs = get_have_analysis_or_not()
    
        for can_be_check_dir in can_be_check_dirs:
            print("=" * 80)
            print("now processing " + can_be_check_dir)
            print("-" * 80)     
        
            exe_name = get_exe_name(can_be_check_dir)
            if exe_name == None:
                continue        

            split_pcap(can_be_check_dir, exe_name)

            ip_info, domain_name_list = check_pcap_malicious(exe_name, args)      

            malicious_pcap_number = check_result(exe_name, args)        
        	
            generate_json_analysis(args, ip_info, domain_name_list, malicious_pcap_number)
            
            print("-" * 80)
            print("The analysis data have written into the "+ exe_name + ".json")
            
            print("-" * 80)
            print(exe_name + " has " + str(malicious_pcap_number) + " malicious flows")            
            
            exe_number -= 1
            was_analysis_dir.append(can_be_check_dir)
            result_dic[exe_name] = malicious_pcap_number

            if malicious_pcap_number > 0:
                malicious_exe_number += 1
            else:
                not_malicious_exe_number += 1
                
            print("=" * 80)
            
            cmd = "rm -r " + Input_dir + "/" + can_be_check_dir
            os.system(cmd)

        time.sleep(10)          
    
    print("Finishing running")
    print("Malicious exe number: " + str(malicious_exe_number))
    print("Benign    exe number: " + str(not_malicious_exe_number))


    if len(result_dic) > 0:
        write_result_to_csv()
        print("You can see detail in " + Csv_dir)

if __name__ == '__main__':
    main()
