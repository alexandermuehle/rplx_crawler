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
q.put(Endpoint(u'199.247.23.117', 30303, 30303))

#start threads for discovery
server = PingServer(Endpoint(u'127.0.0.1', 30303, 30303))
for x in range(threadcount):
	discover_thread = server.discover(q, x).start()
