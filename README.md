# Check_Pcap
This is a script for using cuckoo sandbox to collect the traffic flow.

## Get malware(exe)
1. You can based on https://hackmd.io/yuD9uyblQsiqq9GxESk39w to download malware sample.

## Install environment
1. Based on https://hackmd.io/iMQJ_zD-R6CFXAEn_tTnHg to install cuckoo sandbox.
2. Run the environment.py to install requirement.
3. Make sure you have set the iptables correctly and your sandbox is able to connect Internet. (If you reboot, the iptables may be cleared. You can use "sudo iptables -S" to check)
4. Modify the contents in config.py if your cuckoo path is different and change the api key. 

## Submit exe to analyze
1. The exe name is composed of "md5 value" and ".exe". (e.g., "780fff83b0d5b54fc0488d0dd8d0f4d0.exe")
2. Put the exe which you want to analyze in "not_analysis/"
3. Run filter_out_malicious_pcap.py

## Get the results
1. If the exe has malicious flow, you will see the result in has_behavior_malware/
2. If the exe has no malicious flow, you will see the result in has_no_behavior_malware/
3. The reports about number of flow is in csv_report/

## Get the analysis
1. Make sure you have dns_query/ , has_behavior_malware/ and csv_report/
2. Run analysis.py
3. You will get the reports in analysis/

## Notice! (Before run filter_out_malicious_pcap.py)
1. Make sure you have set the iptables. (If you reboot, the iptables may be cleared. You can use "sudo iptables -S" to check)
