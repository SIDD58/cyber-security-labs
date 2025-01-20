from scapy.all import *

def req_icmp(pkt):
	if ICMP in pkt and pkt[ICMP].type == 0:
		# Priting inital source and dest IP
		print("Initial source IP and destination IP (ICMP response)")
		print("Source IP: ",pkt[IP].src)
		print("Destination IP: ",pkt[IP].dst)
		# Creating new ICMP ,IP headers 
		ip=IP(src=pkt[IP].dst,dst=pkt[IP].src,ihl=pkt[IP].ihl)
		icmp=ICMP(type=8,id=pkt[ICMP].id,seq=pkt[ICMP].seq)
		icmp.chksum = None
		#Creating the packet with new data
		data='COMP8677-Siddharth_Samber'
		pkt=ip/icmp/data
		#Printing new source and dest IP
		print("Modified source IP and destination (ICMP request)")
		print("Source IP: ",pkt[IP].src)
		print("Destination IP: ",pkt[IP].dst)
		print("Data Sent: ",pkt[ICMP].load)
		#sending the packet
		send(pkt,verbose=1)

pkt=sniff(filter="icmp and src 10.10.10.10",prn=req_icmp,iface="enp0s3")


























#def print_pkt(pkt):
	#if IP in pkt and ICMP in pkt and pkt[IP].dst == '10.10.10.10':
		#pkt[IP].src,pkt[IP].dst=pkt[IP].dst,pkt[IP].src

		#Loading our Data in ICMP payload
		#pkt[ICMP].load=b"COMP8677"
		#pkt[ICMP].type="echo-reply"
		#print("Payload: ",pkt[ICMP].load)
		#print("Payload in hex: ",pkt[ICMP].load.hex())
		#pkt.show2()
		#send(pkt,verbose=1)
	#Swapping destination and source address
	#temp=pkt[IP].src
	#pkt[IP].src=pkt[IP].dst
	#pkt[IP].dst=temp
