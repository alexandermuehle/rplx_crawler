from server import Endpoint, PingNode, PingServer
from secp256k1 import PrivateKey
import queue
import sys

#read threadcount from args
threadcount = 1
if len(sys.argv) == 2:
	threadcount = int(sys.argv[1])

#generate private key
k = PrivateKey(None)
with open("priv_key", 'w') as f:
	f.write(k.serialize())

#init queue and fill it with bootstraps
q = queue.Queue()
qset = queue.Queue()
q.put(Endpoint(u'52.16.188.185', 30303, 30303, bytes.fromhex("a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c"))) #geth
q.put(Endpoint(u'174.112.32.157', 30303, 30303, bytes.fromhex("e809c4a2fec7daed400e5e28564e23693b23b2cc5a019b612505631bbe7b9ccf709c1796d2a3d29ef2b045f210caf51e3c4f5b6d3587d43ad5d6397526fa6179"))) #parity
q.put(Endpoint(u'144.76.62.101', 30303, 30303, bytes.fromhex("2676755dd8477ad3beea32b4e5a144fa10444b70dfa3e05effb0fdfa75683ebd4f75709e1f8126cb5317c5a35cae823d503744e790a3a038ae5dd60f51ee9101"))) #pyethapp

out = queue.Queue()

#start threads for discovery
server = PingServer(Endpoint(u'127.0.0.1', 30303, 30303, k.serialize()))
for x in range(threadcount):
	server.discover(q, qset, out, x).start()


with open("crawl_result.txt", 'w') as f:
	while True:
		message = out.get()
		f.write(message + "\n")
	
