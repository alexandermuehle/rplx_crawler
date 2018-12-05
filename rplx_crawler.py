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
q.put(Endpoint(u'210.183.44.34', 30303, 30303, bytes.fromhex("288b97262895b1c7ec61cf314c2e2004407d0a5dc77566877aad1f2a36659c8b698f4b56fd06c4a0c0bf007b4cfb3e7122d907da3b005fa90e724441902eb19e")))

out = queue.Queue()

#start threads for discovery
server = PingServer(Endpoint(u'127.0.0.1', 30303, 30303, k.serialize()))
for x in range(threadcount):
	server.discover(q, qset, out, x).start()


with open("crawl_result.txt", 'w') as f:
	while True:
		message = out.get()
		f.write(message + "\n")
	
