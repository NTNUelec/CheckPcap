import os

cuckoo_path = "/opt/cuckoo/"
os.chdir(cuckoo_path)
os.system("cuckoo -d")
