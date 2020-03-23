import os


not_analysis_dir = "not_analysis/"
already_analysis_dir = "already_analysis/"
cuckoo_path = "/opt/cuckoo/"

def main():
	now_work_path = os.getcwd()	
	exe_names = os.listdir(not_analysis_dir)
	os.chdir(cuckoo_path)
	
	print("There are " + str(len(exe_names)) + " submit to analyze")
	print("-" * 80)
	
	for exe_name in exe_names:
		cmd = "cuckoo submit " + now_work_path + "/" + not_analysis_dir + exe_name
		os.system(cmd)		
	os.chdir(now_work_path)

	for exe_name in exe_names:
		cmd = "mv " + not_analysis_dir + exe_name + " " + already_analysis_dir
		os.system(cmd)

if __name__ == '__main__':
	main()
