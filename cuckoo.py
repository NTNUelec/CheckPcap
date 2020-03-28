import os

# our library
from config import *

os.chdir(cuckoo_path)
os.system("cuckoo -d")
