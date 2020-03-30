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

# our library
from config import *


def open_pcap(path):
	pcap = rdpcap(path)
	return pcap
	
	
def get_malicious_and_benign_sample_number():
	malicious_sample_number = len(os.listdir(has_behavior_malware_dir))
	benign_sample_number    = len(os.listdir(has_no_behavior_malware_dir))

	return malicious_sample_number, benign_sample_number


def get_malicious_flow_number():
	sample_file_names = os.listdir(has_behavior_malware_dir)
	total_pcap_file_number = 0
	
	for sample_file_name in sample_file_names:		
		pcap_file_number = len(os.listdir(sample_full_path_name))
		total_pcap_file_number += pcap_file_number
	
	return total_pcap_file_number


def get_sort_key_dic(original_dic):
	new_dic = dict()
	
	for key in sorted(original_dic):
		new_dic[key] = original_dic[key]
	
	return new_dic	
	 

def get_malicious_ip_and_exist_times():
	sample_file_names = os.listdir(has_behavior_malware_dir)
	ip_times_dic = dict()
	
	for sample_file_name in sample_file_names:
		pcap_file_names = os.listdir(has_behavior_malware_dir + sample_file_name)
		for pcap_file_name in pcap_file_names:
			pcap_file_path = has_behavior_malware_dir + sample_file_name + "/" + pcap_file_name
			pcap = open_pcap(pcap_file_path)
			
			pkt_1 = pcap[0]
			malicious_ip = pkt_1[IP].dst
			
			if malicious_ip not in ip_times_dic.keys():
				ip_times_dic[malicious_ip] = 1
			else:
				ip_times_dic[malicious_ip] += 1		
	
	return get_sort_key_dic(ip_times_dic)


def get_malicious_ip_and_packet_number():
	sample_file_names = os.listdir(has_behavior_malware_dir)
	ip_packet_dic = dict()
	
	for sample_file_name in sample_file_names:
		pcap_file_names = os.listdir(has_behavior_malware_dir + sample_file_name)
		for pcap_file_name in pcap_file_names:
			pcap_file_path = has_behavior_malware_dir + sample_file_name + "/" + pcap_file_name
			pcap = open_pcap(pcap_file_path)
			
			pkt_1 = pcap[0]
			malicious_ip = pkt_1[IP].dst
			packet_num = len(pcap)
			
			if malicious_ip not in ip_packet_dic.keys():
				ip_packet_dic[malicious_ip] = list()				
		
			ip_packet_dic[malicious_ip].append(packet_num)
	
	ip_ave_packet_dic = dict()
	ip_std_packet_dic = dict()
	
	for key in ip_packet_dic.keys():
		ip_ave_packet_dic[key] = np.average(ip_packet_dic[key])
		ip_std_packet_dic[key] = np.std(ip_packet_dic[key])
	
	ip_ave_packet_dic = get_sort_key_dic(ip_ave_packet_dic)
	ip_std_packet_dic = get_sort_key_dic(ip_std_packet_dic)
	
	return ip_ave_packet_dic, ip_std_packet_dic
	
	
def main():
	ip_times_dic = get_malicious_ip_and_exist_times()
	for key in ip_times_dic.keys():
		print(key, ip_times_dic[key])

main()
			
			
			
		
		
	
