from aes import AES_CTR, hex2str, str2hex
from message import Message, _IV, _MSG
from urllib import urlopen, urlencode
from terminal import Terminal
from hashlib import sha1
import json

_BASE = "http://cs387.udacity-extras.appspot.com/final"
_P = 'p'
_G = 'g'


def check_output(output):
    data = output.read()
    if output.getcode() != 200:
        raise Exception(data)
    data = json.loads(data)
    return data

def get_pg():
    output = urlopen(_BASE)
    data = check_output(output)
    # returns {"p":<large prime>, "g":<generator for p>}
    return data

# the following function will be used to provide the public keys
# for the MiTM attack
def mitm_keys(gy):
    # get both prime p and generator g
    pg = get_pg()
    p = int(pg[_P], 16)
    g = int(pg[_G], 16)
    x = 2
    gx = pow(g, x, p)
    key = pow(int(gy, 16), x, p) # === g^(xy) mod p
    return hex(key)[2:-1], hex(gx)[2:-1]

# the following function will be used to compute the key and nonce
# for AES-CTR given Diffie-Hellam shared secret
def get_key_nonce(_hex_shared_secret):
	sha1_machine = sha1()
	sha1_machine.update(hex2str(_hex_shared_secret))
	hex_digest = str2hex(sha1_machine.digest())
	key = hex_digest[:32]	# first 16-bytes (32-hex-digits)
	nonce = hex_digest[32:]	# last 4-bytes (8-hex-digits)
	return key, nonce

# the following function will be used to construct AES-CTR objects
# for messages decoding/encoding given Diffie-Hellman shared secret
def get_aes(_hex_shared_secret):
	key, nonce = get_key_nonce(_hex_shared_secret)
	return AES_CTR(key, nonce)

def decipher(aes_machine, message):
	hex_msg = aes_machine.decode(hex2str(message.data), message.iv)
	return hex2str(hex_msg)

def cipher(aes_machine, message_str, message_iv):
	hex_message_data = aes_machine.encode(message_str, message_iv)
	return Message({_MSG:hex_message_data, _IV:message_iv})

class MiTM:

	def __init__(self, term_a, term_b):
		self.term_a = term_a
		a_key, fake_b_public = mitm_keys(term_a.public)
		self.term_b = term_b
		b_key, fake_a_public = mitm_keys(term_b.public)
		# Setup the fake terminals
		self.fake_term_b = Terminal(term_b.name, term_b.uri, True)
		self.fake_term_b.public = fake_b_public
		self.fake_term_b.token = term_b.token
		self.fake_term_a = Terminal(term_a.name, term_a.uri, True)
		self.fake_term_a.public = fake_a_public
		self.fake_term_a.token = term_a.token
		self.diffie_hellman_keys = {term_a.uri:a_key, term_b.uri:b_key}

	def exchange_keys(self):
		# Exchange keys between terminal a and fake terminal b
		if not self.term_a.send_key_of(self.fake_term_b):
			raise Exception('Error while exchange keys between Terminal a and Fake Terminal b')
		# Exchange keys between terminal b and fake terminal a
		if not self.term_b.send_key_of(self.fake_term_a):
			raise Exception('Error while exchange keys between Terminal b and Fake Terminal a')
		print 'MiTM attack passed Diffie-Hellman protocol for key exchange'
	
	def exchange_messages(self):
		# Relay messages between terminal a and terminal b
		end_a = self.term_a
		a_aes = get_aes(self.diffie_hellman_keys[self.term_a.uri])
		end_b = self.term_b
		b_aes = get_aes(self.diffie_hellman_keys[self.term_b.uri])
		reply_msg = Message({})
		done_flag = False
		while not done_flag:
			if reply_msg.is_empty():
				print 'Try to receive from', end_a.name
				reply_msg = end_a.receive_msg()
				print 'From', end_a.name, '>>>\n', reply_msg

			# Try to decode the message before relaying it to the other terminal
			reply_msg_str = decipher(a_aes, reply_msg)
			print 'Deciphered Message:', reply_msg_str
			reply_msg = cipher(b_aes, reply_msg_str, reply_msg.iv)
			print 'Try to send message to', end_b.name
			reply_msg = end_b.send_msg(reply_msg)
			if not reply_msg.is_empty() and reply_msg.is_hex():
				print 'From', end_b.name, '>>>\n', reply_msg
			elif reply_msg.is_empty():
				print 'Empty Response ... Terminating communications...'
				done_flag = True
			elif not reply_msg.is_hex():
				print 'From', end_b.name, '>>>\n', reply_msg.data
				reply_msg = Message({})

			temp = end_a
			end_a = end_b
			end_b = temp
			temp = a_aes
			a_aes = b_aes
			b_aes = temp
			print '-'*100

class Eve:
	"""
	This class will be used to establish communications between Eve (me :D)
	and any other terminal
	"""
	def  __init__(self, other_term):
		self.other_term = other_term
		key, eve_public = mitm_keys(other_term.public)
		self.eve = Terminal('Eve', _BASE+'/eve', True)
		self.eve.public = eve_public
		self.eve.token = 'dbb0aef3592e476fa4b84848df032ef6'	# some random token
		self.diffie_hellman_key = key
		# Exchange keys between Eve and the other terminal
		if not self.other_term.send_key_of(self.eve):
			raise Exception('Error while exchange keys between Eve and ' + self.other_term.name)
		print 'Eve exchanged keys with ' + self.other_term.name + ' successfully :)'
	
	def exchange_messages(self, msg_reply_list):
		# Relay messages between terminal a and terminal b
		end_a = self.other_term
		end_b = self.eve
		aes = get_aes(self.diffie_hellman_key)
		
		reply_msg = Message({})
		done = False
		m = 0
		while not done:
			if reply_msg.is_empty():
				print 'Try to receive from', end_a.name
				reply_msg = end_a.receive_msg()
				print 'From', end_a.name, '>>>\n', reply_msg
			# Try to decode the message before relaying it to the other terminal
			reply_msg_str = decipher(aes, reply_msg)
			print 'Deciphered Message:', reply_msg_str
			done = m == len(msg_reply_list)
			if not done:
				reply_msg = cipher(aes, msg_reply_list[m], reply_msg.iv)
				m += 1
				print 'Try to send message to', end_a.name
				reply_msg = end_a.send_msg(reply_msg)
				if not reply_msg.is_empty() and reply_msg.is_hex():
					print 'From', end_a.name, '>>>\n', reply_msg
				elif reply_msg.is_empty():
					print 'Empty Response ... Terminating communications...'
					done = True
				elif not reply_msg.is_hex():
					print 'From', end_b.name, '>>>\n', reply_msg.data
					done = True

			
