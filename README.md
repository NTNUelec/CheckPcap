# Check_Pcap
Check pcap with malicious flow or not

## Install environment
1. Based on to install cuckoo sandbox.
2. Run the environment.py to install requirement and make some neccessary directories.

## Submit exe to analyze
1. The exe name will compose of md5 value and ".exe". e.g. "780fff83b0d5b54fc0488d0dd8d0f4d0.exe"
1. Put the exe which you want to analyze in not_analysis/
2. Run the submit_analysis.py and it will submit the exe to cuckoo

## Check pcap is malicious or not
1. Run filter_out_malicious_pcap.py
2. If the exe has malicious flow, you will see the result in has_behavior_malware/
3. If the exe has no malicious flow, you will see the result in has_no_behavior_malware/
4. The result would only keep malicious flow.
