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
import numpy as np

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
		pcap_file_number = len(os.listdir(has_behavior_malware_dir + sample_file_name))
		total_pcap_file_number += pcap_file_number
	
	return total_pcap_file_number


def get_sort_key_dic(original_dic):
	new_dic = dict()
	
	for key in sorted(original_dic.keys()):
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


def get_malicious_ip_and_country():
	sample_file_names = os.listdir(has_behavior_malware_dir)
	ip_country_dic = dict()
	
	for sample_file_name in sample_file_names:
		pcap_file_names = os.listdir(has_behavior_malware_dir + sample_file_name)
		for pcap_file_name in pcap_file_names:
			pcap_file_path = has_behavior_malware_dir + sample_file_name + "/" + pcap_file_name
			pcap = open_pcap(pcap_file_path)
			
			pkt_1 = pcap[0]
			malicious_ip = pkt_1[IP].dst
			
			if malicious_ip not in ip_country_dic.keys():
				OTX_SERVER = 'https://otx.alienvault.com/'
				otx = OTXv2(alienvault_api_key, server=OTX_SERVER)
				try:
					result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, malicious_ip, 'general')
					country = result["country_code"] 
				except: 
					country = "unknown"
				ip_country_dic[malicious_ip] = country
	
	return ip_country_dic	
				
				
def get_malicious_ip_and_packet_len():
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


def get_malware_and_related_ip():
	sample_file_names = os.listdir(has_behavior_malware_dir)
	malware_ip_dic = dict()
	
	for sample_file_name in sample_file_names:
		pcap_file_names = os.listdir(has_behavior_malware_dir + sample_file_name)
		ip_set = set()
		for pcap_file_name in pcap_file_names:
			pcap_file_path = has_behavior_malware_dir + sample_file_name + "/" + pcap_file_name
			pcap = open_pcap(pcap_file_path)
			
			pkt_1 = pcap[0]
			ip = pkt_1[IP].dst
			ip_set.add(ip)
		
		malware_ip_dic[sample_file_name] = ip_set
			
	return malware_ip_dic
	

def get_malware_and_dns_query():
	default_dns = ["ipv6.msftncsi.com",	"teredo.ipv6.microsoft.com", "1.56.168.192.in-addr.arpa", "dns.msftncsi.com"]

	sample_file_names = os.listdir("dns_query/")
	malware_dns_dic = dict()

	for sample_file_name in sample_file_names:
		pcap_file_names = os.listdir("dns_query/" + sample_file_name)
		dns_set = set()
		pcap_file_names = sorted(pcap_file_names)
		for pcap_file_name in pcap_file_names:
			pcap_file_path = "dns_query/" + sample_file_name + "/" + pcap_file_name
		
			pcap = open_pcap(pcap_file_path)
			pkt_1 = pcap[0]	
			
			try: 
				domain_name = pkt_1[DNS].summary().split(" ")[-2].strip('"').strip('.')
			except:
				continue
				
			if domain_name not in default_dns:
				dns_set.add(domain_name)
	
		malware_dns_dic[sample_file_name] = dns_set
		
	return malware_dns_dic
	
	
def main():
	if os.path.isdir(analysis_dir) == False:
		os.mkdir(analysis_dir)
	
	print("=" * 80)
	malicious_sample_number, benign_sample_number = get_malicious_and_benign_sample_number()
	malicious_flow_number = get_malicious_flow_number()
	
	print("total malicious sample number: " + str(malicious_sample_number))
	print("total benign    sample number: " + str(benign_sample_number))
	print("total malicious flow   number: " + str(malicious_flow_number))
	
	print("=" * 80)
	print("Start count report times of every IP...")
	file_name = "IP_report_times.csv"	
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')
		writer.writerow(['IP', 'exist times'])		
			
		ip_times_dic = get_malicious_ip_and_exist_times()
		for key in sorted(ip_times_dic.keys()):
			writer.writerow([key, ip_times_dic[key]])
	
	print("=" * 80)
	print("Start count packet length of every IP...")
	file_name = "IP_packet_len.csv"	
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')
		writer.writerow(['IP', 'ave pkt len', 'std pkt len'])		
			
		ip_ave_packet_dic, ip_std_packet_dic = get_malicious_ip_and_packet_len()
		for key in sorted(ip_ave_packet_dic.keys()):
			writer.writerow([key, int(ip_ave_packet_dic[key]), int(ip_std_packet_dic[key])])
	
	print("=" * 80)
	print("Start count related ip of every Malware...")
	file_name = "Malware_related_ip.csv"
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')
		
		head_row = ['Malware']
		for i in range(100):
			head_row.append("IP_" + str(i+1))
		writer.writerow(head_row)		
			
		malware_ip_dic = get_malware_and_related_ip()
		for key in sorted(malware_ip_dic.keys()):
			ip_set = malware_ip_dic[key]
			row = [key]
			for ip in ip_set:
				row.append(ip)
			writer.writerow(row)
	
	print("=" * 80)
	print("Start query ip and its country...")
	file_name = "IP_country.csv"
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')		
		writer.writerow(['IP', 'country'])		
			
		ip_country_dic = get_malicious_ip_and_country()
		for key in sorted(ip_country_dic.keys()):
			writer.writerow([key, ip_country_dic[key]])	
		
	print("=" * 80)
	print("Start query malware and dns...")
	file_name = "Malware_dns.csv"
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')			
		
		head_row = ['Malware']
		for i in range(100):
			head_row.append("DNS_" + str(i+1))
		writer.writerow(head_row)		
			
		malware_dns_dic = get_malware_and_dns_query()
		for key in sorted(malware_dns_dic.keys()):
			dns_set = malware_dns_dic[key]
			row = [key]
			for dns in dns_set:
				row.append(dns)
			writer.writerow(row)
	
	
	print("=" * 80)
	print("Results are in " + analysis_dir)

if __name__ == '__main__':
	main()			
			
		
		
	
