from crawler import Endpoint, PingNode, PingServer
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
q.put(Endpoint(u'52.16.188.185', 30303, 30303, bytes.fromhex("a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c")))

#start threads for discovery
server = PingServer(Endpoint(u'127.0.0.1', 30303, 30303, k.serialize(compressed=False))
for x in range(threadcount):
	discover_thread = server.discover(q, x).start()
