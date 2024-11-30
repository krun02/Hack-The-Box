Project Overview:

Red Trails is a medium-level forensic analysis challenge hosted on Hack The Box. The task involves analyzing network data and encrypted payloads to uncover hidden flags. By leveraging various tools and techniques, participants are required to retrieve and decrypt three parts of a flag.

Tools Utilized
1. Snort
A real-time network intrusion detection and prevention system.
Identifies threats by analyzing traffic patterns and matching against known attack signatures.
2. NetFlow Analyzer
Monitors network traffic flows.
Detects anomalies and assists in incident investigations with detailed network logs.
3. Wireshark
A network protocol analyzer for capturing and dissecting packet data.
Used here to analyze PCAP files and inspect Redis protocol packets.
4. Ghidra
A reverse engineering tool for analyzing assembly code and encrypted data.
Helps uncover decryption algorithms and cryptographic keys.
5. IDA Pro
Similar to Ghidra but a paid alternative.
Used for in-depth malware analysis and reverse engineering.
Methodology and Steps

Flag 1
Tool: Strings command

Command: strings –n 6 capture.pcap
Searched for readable strings in the PCAP file to locate the first part of the flag.
Tool: Wireshark

Analyzed Redis protocol packets to confirm the string identified by the strings command.

Flag 2

Inspected HTTP requests within the PCAP file using Wireshark.
Found suspicious, encoded text transmitted in a server status request.
Decoded the text using Base64 via a custom script to retrieve the second part of the flag.

Flag 3
Identified a suspicious hexadecimal string:
Copy code
h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz
YDP7ECjzuV7sagMN
Extracted the payload from the PCAP file in hexadecimal format using Wireshark.
Decompiled the payload using Ghidra, revealing the AES encryption algorithm, along with the key and IV.

Created a Bash script to decrypt the payload:
#!/bin/bash
key="$(echo 'h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz' | tr -d '\n'| xxd -p | xargs | tr -d '\ ')"
IV="$(echo 'YDP7ECjzuV7sagMN' | tr -d '\n'| xxd -p | xargs)"
echo "$1" | xxd -r -p > encrypted_data.bin
openssl enc -aes-256-cbc -d -in encrypted_data.bin -out decrypted_data.txt -K "$key" -iv "$IV" -nopad
cat ./decrypted_data.txt

Successfully retrieved the final part of the flag.
