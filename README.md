- 👋 Hi, I’m @Abiyu24
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...
- 😄 Pronouns: ...
- ⚡ Fun fact: ...

<!---
Abiyu24/Abiyu24 is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
import scapy.all as scapy


def read_pcap(file_path):
 # Read the pcap file
 packets = scapy.rdpcap(file_path)
 return packets


def filter_smbv2_packets(packets):
 # Filter SMBv2 packets (TCP port 445 is typically used for SMB traffic)
 smbv2_packets = [pkt for pkt in packets if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].dport == 445]
 return smbv2_packets


def extract_smb_data(smbv2_packets):
 attachments = []
 metadata = []

 for packet in smbv2_packets:
 if packet.haslayer(scapy.Raw):
 # Extract raw data from the SMB packet
 smb_data = packet[scapy.Raw].load

 # Placeholder for actual extraction logic
 # Extract attachments (if any) and metadata from smb_data
 attachment = extract_attachment(smb_data)
 meta = extract_metadata(smb_data)

 if attachment:
 attachments.append(attachment)
 if meta:
 metadata.append(meta)

 return attachments, metadata


def extract_attachment(smb_data):
 # Implement the logic to extract attachments from smb_data
 # Placeholder function
 return None


def extract_metadata(smb_data):
 # Implement the logic to extract metadata from smb_data
 # Placeholder function
 return None


def main():
 pcap_file = r'C:\Users\admin\Downloads\smb.pcap'

 # Step 1: Read the PCAP file
 packets = read_pcap(pcap_file)

 # Step 2: Filter SMBv2 packets
 smbv2_packets = filter_smbv2_packets(packets)

 # Step 3: Extract attachments and metadata
 attachments, metadata = extract_smb_data(smbv2_packets)

 print("Extracted Attachments:", attachments)
 print("Extracted Metadata:", metadata)


if __name__ == "__main__":
 main()
import pyshark


def extract_smb_operations(pcap_file):
 # Open the PCAP file using pyshark
 cap = pyshark.FileCapture(pcap_file, display_filter='smb')

 write_requests = []
 write_responses = []
 read_requests = []
 read_responses = []

 for packet in cap:
 try:
 smb2_layer = packet['smb']
 smb2_cmd = smb2_layer.cmd

 if smb2_cmd == '9': # SMB2 WRITE Request
 write_requests.append(packet)
 elif smb2_cmd == '10': # SMB2 WRITE Response
 write_responses.append(packet)
 elif smb2_cmd == '8': # SMB2 READ Request
 read_requests.append(packet)
 elif smb2_cmd == '9': # SMB2 READ Response
 read_responses.append(packet)
 except KeyError:
 continue

 return write_requests, write_responses, read_requests, read_responses


def main():
 # Path to the PCAP file
 pcap_file = r'C:\Users\admin\Downloads\smb.pcap'

 # Extract SMB operations
 write_requests, write_responses, read_requests, read_responses = extract_smb_operations(pcap_file)

 print("Write Requests:", len(write_requests))
 print("Write Responses:", len(write_responses))
 print("Read Requests:", len(read_requests))
 print("Read Responses:", len(read_responses))

 # Optionally, you can further process these packets
 for wr in write_requests:
 print("Write Request:")
 print(wr)

 for wr in write_responses:
 print("Write Response:")
 print(wr)

 for rr in read_requests:
 print("Read Request:")
 print(rr)

 for rr in read_responses:
 print("Read Response:")
 print(rr)


if __name__ == "__main__":
 main()
import os


# Example path to TShark
tshark_path = r'C:\Program Files\Wireshark'

# Add TShark path to the system PATH temporarily for this script
os.environ['PATH'] += os.pathsep + tshark_path

# Now TShark should be accessible within this script
# You can test it
os.system('tshark -v')
import socket
import struct

# SMB2 Header Constants
SMB2_HEADER = b"\xfeSMB" # SMB2 Protocol Identifier
SMB2_COMMAND_WRITE = 0x09 # SMB2 Command: Write

# SMB2 Write Request Structure
STRUCTURE_SIZE = 49 # Size of the request structure (excluding header)

def construct_smb2_write_request(file_id, offset, data_to_write):
 # Construct the SMB2 Write Request packet
 header = SMB2_HEADER
 structure_size = STRUCTURE_SIZE
 data_offset = 64 # Data offset from SMB2 header
 length = len(data_to_write) # Length of data to write
 remaining_bytes = 0 # No channel information, so remaining bytes are 0
 write_channel_info_offset = 0
 write_channel_info_length = 0
 flags = 0 # No special flags for this example

 # Pack the SMB2 Write Request structure
 packet = (
 header +
 struct.pack('<H', structure_size) +
 struct.pack('<H', data_offset) +
 struct.pack('<I', length) +
 struct.pack('<Q', offset) +
 file_id + # SMB2_FILEID structure (16 bytes)
 struct.pack('<I', 0) + # Channel: SMB2_CHANNEL_NONE
 struct.pack('<I', remaining_bytes) +
 struct.pack('<H', write_channel_info_offset) +
 struct.pack('<H', write_channel_info_length) +
 struct.pack('<I', flags) +
 data_to_write # Actual data to write
 )

 return packet

# Example usage
if __name__ == "__main__":
 # Replace these values with actual file ID, offset, and data
 file_id = b'\x00' * 16 # Replace with actual SMB2_FILEID
 offset = 0 # Offset in the file where data should be written
 data_to_write = b"Hello, SMB2 World!" # Replace with actual data to write

 # Construct the SMB2 Write Request packet
 smb2_write_request = construct_smb2_write_request(file_id, offset, data_to_write)

 # Example: Send the packet to a server (replace with actual server details)
 server_ip = 'server_ip'
 server_port = 445

 try:
 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 sock.connect((server_ip, server_port))
 sock.sendall(smb2_write_request)
 print("SMB2 Write Request sent successfully.")
 except Exception as e:
 print(f"Failed to send SMB2 Write Request: {e}")
 finally:
 sock.close()
