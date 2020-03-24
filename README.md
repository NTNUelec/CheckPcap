# Check_Pcap

## Get malware(exe)
1. You can based on https://hackmd.io/yuD9uyblQsiqq9GxESk39w to download malware sample.

## Install environment
1. Based on https://hackmd.io/iMQJ_zD-R6CFXAEn_tTnHg to install cuckoo sandbox.
2. Run the environment.py to install requirement and make some neccessary directories.

## Submit exe to analyze
1. The exe name will compose of md5 value and ".exe". e.g. "780fff83b0d5b54fc0488d0dd8d0f4d0.exe"
2. Put the exe which you want to analyze in not_analysis/
3. Run filter_out_malicious_pcap.py
4. If the exe has malicious flow, you will see the result in has_behavior_malware/
5. If the exe has no malicious flow, you will see the result in has_no_behavior_malware/
6. The result would only keep malicious flow.
