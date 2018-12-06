import logging
import time
import struct
import rlp
import socket
import threading
import hashlib
import sha3
import random
import queue
from threading import Thread
from bitstring import BitArray
from secp256k1 import PrivateKey, PublicKey
from ipaddress import ip_address

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

#keccak hashing
def keccak256(s):
	k = sha3.keccak_256()
	k.update(s)
	return k.digest()

#endpoint object
class Endpoint(object):
	def __init__(self, address, udpPort, tcpPort, nodeID):
		self.address = ip_address(address)
		self.udpPort = udpPort
		self.tcpPort = tcpPort
		self.nodeID = nodeID

	def pack(self):
		return [self.address.packed,
			struct.pack(">H", self.udpPort),
			struct.pack(">H", self.tcpPort)]

	def serialize(self):
		return self.nodeID.hex() + ", " + str(self.address.exploded) + ", " + str(self.udpPort) + ", " + str(self.tcpPort)

#ping message
class PingNode(object):
	packet_type = b'\x01';
	version = b'\x04';	
	def __init__(self, endpoint_from, endpoint_to):
		self.endpoint_from = endpoint_from
		self.endpoint_to = endpoint_to

	def pack(self):
		return [self.version,
			self.endpoint_from.pack(),
			self.endpoint_to.pack(),
			struct.pack(">I", int(time.time() + 60))]

#pong message
class PongNode(object):
	packet_type = b'\x02';
	version = b'\x04';	
	def __init__(self, endpoint_to, ping_hash):
		self.endpoint_to = endpoint_to
		self.ping_hash = ping_hash

	def pack(self):
		return [self.endpoint_to.pack(),
			self.ping_hash,
			struct.pack(">I", int(time.time() + 60))]

#neighbour message
class NeighbourNode(object):
	packet_type = b'\x03'
	version = b'\x04'
	def __init__(self, pubkey):
		self.pubkey = pubkey

	def pack(self):
		return [self.pubkey,
			struct.pack(">I", int(time.time() + 60))]


class PingServer(object):
	def __init__(self, my_endpoint):
		self.endpoint = my_endpoint
		with open('priv_key', 'r') as priv_key_file:
			priv_key_serialized = priv_key_file.read()
		self.priv_key = PrivateKey()
		self.priv_key.deserialize(priv_key_serialized)

	def wrap_packet(self, packet):
		#packet_type + packet_data
		signature_payload = packet.packet_type + rlp.encode(packet.pack())
		# signature = sign(packet_type + packet_data)
		sig = self.priv_key.ecdsa_sign_recoverable(keccak256(signature_payload), raw=True)
		sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
		#signature encoded
		payload = sig_serialized[0] + bytes([sig_serialized[1]])
		#signature + packet_type + packet_data
		payload = payload + signature_payload
		#hash = keccak256(signature + packet_type + packet_data)
		payload_hash = keccak256(payload)
		#hash + signature + packet_type + packet_data
		return payload_hash + payload
	
	def discover(self, q, qset, out, count):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind(('0.0.0.0', self.endpoint.udpPort+count))
		sock.settimeout(5)
		self.their_endpoint = q.get()

		def conversation():

			def request_neighbour_lsb(bucket):
				#generate nodeID to discover specified bucket
				hashedID = keccak256(self.their_endpoint.nodeID)
				match = False
				mask = 1
				while match is False:
					generatedID = bytes(random.randint(0,255) for _ in range(64))
					genHashed = keccak256(generatedID)
					if bucket == 0:
						if (genHashed[0] ^ hashedID[0]) & mask == mask:
							match = True
						else:
							match = False
					else:
						#get the bytes in which the relevant bits are and iterate over them
						for x in range(int(bucket/8)+1):
							#make mask according to position in byte array (if last relevant byte get specific bit mask)
							if x == int(bucket/8):
								mask = pow(2, bucket%8)-1
							else:
								mask = 255
							#actual comparing
							if ~(genHashed[x] ^ hashedID[x]) & mask == mask:
								match = True
							else:
								match = False
								break

				#send request
				find_neighbour = NeighbourNode(generatedID)
				message = self.wrap_packet(find_neighbour)
				logging.debug("sending find_node")
				sock.sendto(message, (self.their_endpoint.address.exploded, self.their_endpoint.udpPort))

			def request_neighbour_msb(bucket):
				#generate nodeID to discover specified bucket
				hashedID = keccak256(self.their_endpoint.nodeID)
				match = False
				mask = 1 << 7
				while match is False:
					generatedID = bytes(random.randint(0,255) for _ in range(64))
					genHashed = keccak256(generatedID)
					if bucket == 0:
						if (genHashed[31] ^ hashedID[31]) & mask == mask:
							match = True
						else:
							match = False
					else:
						#get the bytes in which the relevant bits are and iterate over them
						for x in range(int(bucket/8)+1):
							#make mask according to position in byte array (if last relevant byte get specific bit mask)
							if x == int(bucket/8):
								mask = pow(2, bucket%8)-1
								mask = mask << (8-bucket%8)
							else:
								mask = 255
							#actual comparing
							if ~(genHashed[31-x] ^ hashedID[31-x]) & mask == mask:
								match = True
							else:
								match = False
								break

				#send request
				find_neighbour = NeighbourNode(generatedID)
				message = self.wrap_packet(find_neighbour)
				logging.debug("sending find_node")
				sock.sendto(message, (self.their_endpoint.address.exploded, self.their_endpoint.udpPort))


			def decode_worker(q, data, workerOut):
				nodes = rlp.decode(data[98:])[0] #[0] nodes [1] expiration
				for node in nodes:
					ip = ip_address(node[0])
					if len(node[1]) == 2:	
						udp_port = struct.unpack(">H", node[1])
					if len(node[2]) == 2:
						tcp_port = struct.unpack(">H", node[2])
					else:
						tcp_port = (0, ">I")
					nodeID = node[3]
					neighbour = Endpoint(str(ip), udp_port[0], tcp_port[0], nodeID)
					logging.debug("Neighbour: " + neighbour.serialize())
					if neighbour not in list(qset.queue):
						q.put(neighbour)
						qset.put(neighbour)
						
					workerOut.put(neighbour)

			while True:
				#start ping pong
				ping = PingNode(self.endpoint, self.their_endpoint)
				message = self.wrap_packet(ping)
				logging.info("sending ping to " + self.their_endpoint.address.exploded)
				sock.sendto(message, (self.their_endpoint.address.exploded, self.their_endpoint.udpPort))
				serializeOut = self.their_endpoint.serialize()
				greeted = False
				while not greeted:
					try:
						data, addr = sock.recvfrom(1280)
						if data[97] == 1:
							logging.info("received ping from " + addr[0])	
							pinger = Endpoint(addr[0], addr[1], addr[1], b'')
							pong = PongNode(pinger, data[:32])
							message = self.wrap_packet(pong)
							logging.info("sending pong to " + str(pinger.address))
							sock.sendto(message, (pinger.address.exploded, pinger.udpPort))	
							greeted = True
						if data[97] == 2:
							logging.info("received pong from " + addr[0])
					except socket.timeout:
						serializeOut += ", no greeting"
						break
				#discover top 14 buckets of a neigbour (finding targets for all buckets would be hard/impossible)
				if greeted:
					for bucket in range(14):
						#discover a bucket
						request_neighbour_msb(bucket)
						counter = 0
						workerOut = queue.Queue()
						workers = []
						while counter < 2:
							try:
								data, addr = sock.recvfrom(1280)
								if data[97] == 4:
									#get up to 16 neighbours and add them to the q (12 neighbours per packet)
									workers.append(Thread(target = decode_worker, args = (q, data, workerOut)))
									workers[counter].start()
									logging.debug("received neighbours from " + addr[0])
									counter += 1
							#timeout because we received all neighbours available (less than 16) or didnt receive ping 
							except socket.timeout:
								break
						for worker in workers:
							worker.join()
						serializeOut += ", \"["
						for item in list(workerOut.queue):
							serializeOut += "[" + item.serialize() + "], "
						if serializeOut[-2] == ',':
							serializeOut = serializeOut[:-2]
						serializeOut += "]\""
				logging.debug(serializeOut)
				out.put(serializeOut)
				self.their_endpoint = q.get()

		return threading.Thread(target = conversation)
