import os

# our library
from config import *

for neccesary_dir in neccesary_dirs:
	if os.path.isdir(neccesary_dir) == False:
		os.mkdir(neccesary_dir)

# python 3rd part lib
os.system("sudo apt-get install libpcap-dev")
os.system("pip install scapy")
os.system("pip install OTXv2")
os.system("pip install dpkt")
os.system("pip install natsort")
os.system("pip install psutil")
os.system("pip install whois")
os.system("pip install networkx")
os.system("pip install matplotlib")
os.system("pip install plotly")

# PcapPlusPlus install
if os.path.isdir("PcapPlusPlus") == False:
	os.system("git clone https://github.com/seladb/PcapPlusPlus.git")
	
	now_work_path = os.getcwd()
	os.chdir("PcapPlusPlus")
	os.system("./configure-linux.sh --default")
	os.system("sudo make")
	os.system("sudo make libs")
	#os.system("sudo make install")
	os.chdir(now_work_path)

# Link /opt/cuckoo/storage/analyses to Input
if os.path.isdir(cuckoo_storage_path) == True and os.path.isdir(Input_dir) == False:
	os.symlink(cuckoo_storage_path, Input_dir)
	
