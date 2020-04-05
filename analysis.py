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
import itertools
import os

# Third library
from OTXv2 import OTXv2
from scapy.all import *
import dpkt
from natsort import natsorted
import psutil
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import plotly.graph_objects as go

# our library
from config import *


def open_pcap(path):
	pcap = rdpcap(path)
	return pcap
	
	
def get_malicious_and_benign_sample_number():
	malicious_sample_number = 0
	benign_sample_number    = 0
	
	file_names = os.listdir("./")
	csv_file_names = []
	for file_name in file_names:
		if file_name[-4:] == ".csv":
			csv_file_names.append(file_name)			
	
	for csv_file_name in csv_file_names:
		with open(csv_file_name) as csvfile:
			rows = csv.reader(csvfile)
			headers = next(rows)
			
			for row in rows:
				malicious_flow_num = int(row[1])
				
				if malicious_flow_num > 0:
					malicious_sample_number += 1
				else:
					benign_sample_number += 1
	
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
				
				
def get_malicious_ip_and_packet_len_duration():
	sample_file_names = os.listdir(has_behavior_malware_dir)
	ip_packet_dic = dict()
	ip_duration_dic   = dict()

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
				
			pkt_n = pcap[-1]
			start_time = pkt_1.time
			end_time   = pkt_n.time
			duration   = end_time - start_time
		
			if malicious_ip not in ip_time_dic.keys():
				ip_duration_dic[malicious_ip] = list()
		
			ip_duration_dic[malicious_ip].append(duration)


	ip_ave_packet_dic = dict()
	ip_std_packet_dic = dict()
	ip_ave_duration_dic = dict()
	ip_std_duration_dic = dict()

	for key in ip_packet_dic.keys():
		ip_ave_packet_dic[key] = np.average(ip_packet_dic[key])
		ip_std_packet_dic[key] = np.std(ip_packet_dic[key])
		ip_ave_duration_dic[key] = np.average(ip_duration_dic[key])
		ip_std_duration_dic[key] = np.std(ip_duration_dic[key])
	
	ip_ave_packet_dic = get_sort_key_dic(ip_ave_packet_dic)
	ip_std_packet_dic = get_sort_key_dic(ip_std_packet_dic)
	ip_ave_duration_dic = get_sort_key_dic(ip_ave_duration_dic)
	ip_std_duration_dic = get_sort_key_dic(ip_std_duration_dic)

	return ip_ave_packet_dic, ip_std_packet_dic, ip_ave_duration_dic, ip_std_duration_dic



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
	

def get_ip_and_malware_number():
	sample_file_names = os.listdir(has_behavior_malware_dir)
	ip_malware_number_dic = dict()
	
	for sample_file_name in sample_file_names:
		pcap_file_names = os.listdir(has_behavior_malware_dir + sample_file_name)
		ip_set = set()
		
		for pcap_file_name in pcap_file_names:
			pcap_file_path = has_behavior_malware_dir + sample_file_name + "/" + pcap_file_name
			pcap = open_pcap(pcap_file_path)
			
			pkt_1 = pcap[0]
			ip = pkt_1[IP].dst
			ip_set.add(ip)
		
		for ip in ip_set:
			if ip not in ip_malware_number_dic.keys():
				ip_malware_number_dic[ip] = 1
			else:
				ip_malware_number_dic[ip] += 1
		
	return ip_malware_number_dic
			

def create_the_edge_node_csv():
	malware_related_ip_csv = analysis_dir + "Malware_related_ip.csv"	

	with open(malware_related_ip_csv) as csvfile:
		rows = csv.reader(csvfile)
		headers = next(rows)
	
		total_ip_combinations = set()
		for row in rows:
			ip_list = row[1:]
			ip_combinations = list(itertools.combinations(ip_list, 2))
		
			for ip_combination in ip_combinations:			
				if ip_combination not in total_ip_combinations:
					total_ip_combinations.add(ip_combination)


	IP_malware_number_csv = analysis_dir + "IP_malware_number.csv"	
	
	with open(IP_malware_number_csv) as csvfile:
		rows = csv.reader(csvfile)
		headers = next(rows)
	
		ip_malware_number_dic = dict()
		for row in rows:
			ip = row[0]
			malware_num = int(row[1])
			ip_malware_number_dic[ip] = malware_num		

	network_edge_file_name = analysis_dir + "network_edge.csv"
	
	with open(network_edge_file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')		
		writer.writerow(['source', 'target', 'value'])
	
		for ip_combination in total_ip_combinations:
			src_node = ip_combination[0]
			dst_node = ip_combination[1]
			row = [src_node, dst_node, 1]
			writer.writerow(row)

	network_node_file_name = analysis_dir + "network_node.csv"

	with open(network_node_file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')		
		writer.writerow(['name', 'group', 'nodesize'])
	
		for ip in ip_malware_number_dic.keys():
			row = [ip, 1, ip_malware_number_dic[ip]]
			writer.writerow(row)

def show_ip_network_figure():
	G = nx.Graph(day="Stackoverflow")
	df_nodes = pd.read_csv(analysis_dir + 'network_node.csv')
	df_edges = pd.read_csv(analysis_dir + 'network_edge.csv')

	for index, row in df_nodes.iterrows():
		G.add_node(row['name'], group=row['group'], nodesize=row['nodesize'])
		
	for index, row in df_edges.iterrows():
		G.add_weighted_edges_from([(row['source'], row['target'], row['value'])])

	node_pos = nx.spring_layout(G, k=0.25, iterations=50)

	edge_x = []
	edge_y = []
	for edge in G.edges():
		x0, y0 = node_pos[edge[0]]   
		x1, y1 = node_pos[edge[1]]
		edge_x.append(x0)
		edge_x.append(x1)
		edge_x.append(None)
		edge_y.append(y0)
		edge_y.append(y1)
		edge_y.append(None)

	edge_trace = go.Scatter(
		x=edge_x, y=edge_y,
		line=dict(width=1, color='#000000'),
		hoverinfo='none',
		mode='lines')

	node_x = []
	node_y = []
	for node in G.nodes():   
		x, y = node_pos[node]
		node_x.append(x)
		node_y.append(y)

	node_trace = go.Scatter(
		x=node_x, y=node_y,
		mode='markers',
		hoverinfo='text',
		marker=dict(
		    showscale=True,        
		    colorscale='YlGnBu',
		    reversescale=True,
		    color=[],
		    size=30,
		    colorbar=dict(
		        thickness=30,
		        title='Node Connections',
		        xanchor='left',
		        titleside='right'
		    ),
		    line_width=2))


	node_adjacencies = []
	node_text = []
	for node, adjacencies in enumerate(G.adjacency()):
		node_adjacencies.append(len(adjacencies[1]))
		node_text.append('IP: ' + str(list(G.nodes())[node]) + '\n' + '# of connections: '+ str(len(adjacencies[1])))

	node_trace.marker.color = node_adjacencies
	node_trace.text = node_text


	fig = go.Figure(data=[edge_trace, node_trace],
		         layout=go.Layout(
		            title='IP Network graph',
		            titlefont_size=24,
		            showlegend=False,
		            hovermode='closest',
		            margin=dict(b=20,l=5,r=5,t=40),                
		            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
		            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
		            )
	fig.show()
	

def get_malware_and_type():
	filter_list = ["None", "Win32", "A", "Malware"]
	malware_type_dic = dict()
	sample_file_names = os.listdir("already_analysis/")

	for sample_file_name in sample_file_names:
		if sample_file_name[-5:] == ".json":
			with open("already_analysis/" + sample_file_name) as json_file:
				data = json.load(json_file)
			
			malware_type_times_dic = dict()
			for company in data["scans"].keys():
				malware_types = str(data["scans"][company]["result"]).split(".")
				for malware_type in malware_types:
					if malware_type not in malware_type_times_dic.keys():
						malware_type_times_dic[malware_type] = 1
					else:
						malware_type_times_dic[malware_type] += 1
		
			malware_type_times_dic = sorted(malware_type_times_dic.items(), key = lambda d: d[1]) 
		
			for malware_type_set in malware_type_times_dic[::-1]:					
				if malware_type_set[0] not in filter_list:
					malware_type_dic[sample_file_name[:-5]] = malware_type_set[0]
					break

	return malware_type_dic
	
	
def main():
	print("You need to put dns_query/ , has_behavior_malware/ and all csv files in the same position with this file.")
	
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
	file_name = "IP_flow_number.csv"	
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')
		writer.writerow(['IP', 'exist times'])		
			
		ip_times_dic = get_malicious_ip_and_exist_times()
		for key in sorted(ip_times_dic.keys()):
			writer.writerow([key, ip_times_dic[key]])
	
	print("=" * 80)
	print("Start count packet length of every IP...")
	file_name = "IP_packet_len_duration.csv"	
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')
		writer.writerow(['IP', 'ave pkt len', 'std pkt len', 'ave duration', 'std duration'])		
			
		ip_ave_packet_dic, ip_std_packet_dic, ip_ave_duration_dic, ip_std_duration_dic = get_malicious_ip_and_packet_len_duration()
		for key in sorted(ip_ave_packet_dic.keys()):
			writer.writerow([key, int(ip_ave_packet_dic[key]), int(ip_std_packet_dic[key]), int(ip_ave_duration_dic[key]), int(ip_std_duration_dic[key])])
	
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
	print("Start count ip and its malware_number...")
	file_name = "IP_malware_number.csv"
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')		
		writer.writerow(['IP', 'malware number'])		
			
		ip_malware_number_dic = get_ip_and_malware_number()
		for key in sorted(ip_malware_number_dic.keys()):
			writer.writerow([key, ip_malware_number_dic[key]])		
	
	print("=" * 80)
	print("show IP Network...")
	show_ip_network_figure()	
	
	print("=" * 80)
	print("Start count malware and its type...")
	file_name = "Malware_type.csv"
	with open(analysis_dir + file_name, 'w') as csvfile:
		writer = csv.writer(csvfile, delimiter=',')		
		writer.writerow(['Malware', 'type'])		
		
		malware_type_dic = get_malware_and_type()
		for key in sorted(malware_type_dic.keys()):
			writer.writerow([key, malware_type_dic[key]])		
		
	print("=" * 80)
	print("Results are in " + analysis_dir)

if __name__ == '__main__':
	main()			
			
		
		
	
