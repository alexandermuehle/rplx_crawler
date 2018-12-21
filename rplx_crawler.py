import logging
import queue
import sys
import threading
from server import Endpoint, PingMsg, CrawlServer
from secp256k1 import PrivateKey

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

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
q.put(Endpoint(u'13.93.211.84', 30303, 30303, bytes.fromhex("3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99")))
q.put(Endpoint(u'191.235.84.50', 30303, 30303, bytes.fromhex("78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d")))
q.put(Endpoint(u'13.75.154.138', 30303, 30303, bytes.fromhex("158f8aab45f6d19c6cbf4a089c2670541a8da11978a2f90dbf6a502a4a3bab80d288afdbeb7ec0ef6d92de563767f3b1ea9e8e334ca711e9f8e2df5a0385e8e6")))
q.put(Endpoint(u'174.112.32.157', 30303, 30303, bytes.fromhex("e809c4a2fec7daed400e5e28564e23693b23b2cc5a019b612505631bbe7b9ccf709c1796d2a3d29ef2b045f210caf51e3c4f5b6d3587d43ad5d6397526fa6179"))) #parity
q.put(Endpoint(u'144.76.62.101', 30303, 30303, bytes.fromhex("2676755dd8477ad3beea32b4e5a144fa10444b70dfa3e05effb0fdfa75683ebd4f75709e1f8126cb5317c5a35cae823d503744e790a3a038ae5dd60f51ee9101"))) #pyethapp
#fill queue set also
for point in list(q.queue):
	qset.put(point)

out = queue.Queue()

#start threads for discovery
threads = []
running = threading.Event()
running.set()
server = CrawlServer(Endpoint(u'127.0.0.1', 30303, 30303, k.serialize()))
for x in range(threadcount):
	t = threading.Thread(target = server.discover, args = (q, qset, out, x, running))
	t.start()
	threads.append(t)

with open("crawl_result.txt", 'w') as f:
	try:	
		while True:
			message = out.get()
			f.write(message + "\n")
	except KeyboardInterrupt:
		logger.info("Shutting down writer")
		running.clear()
		logging.info("Shutting down Discovery")
		for thread in threads:
			thread.join()
