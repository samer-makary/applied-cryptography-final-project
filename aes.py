from unit6_util import string_to_bits, ASCII_BITS, convert_to_bits, pad_to_block, bits_to_string, display_bits
from Crypto.Util import Counter
from Crypto.Cipher import AES
from string import hexdigits

def is_hex(_str):
	return all(c in hexdigits for c in _str)

def hex2str(_hex):
	"""
	the following function will be used to convert
	a hex message into a string of characters
	"""
	if not is_hex(_hex):
		raise Exception('Key to AES_CTR must be hex-digits')
	hex_int = int(_hex, 16)
	hex_bin = convert_to_bits(hex_int)
	return bits_to_string(pad_to_block(hex_bin, len(_hex) * 4))

def str2hex(_str):
	"""
	the following function will be used to convert
	a strin chr message into hex-digits string
	"""
	str_bin = pad_to_block(string_to_bits(_str), ASCII_BITS)
	return hex(int(display_bits(str_bin), 2))[2:-1].zfill(len(str_bin) / 4)
		
class AES_CTR:

	def __init__(self, hex_key, hex_nonce):
		self.key = hex2str(hex_key)
		self.bin_nonce = pad_to_block(convert_to_bits(int(hex_nonce, 16)), len(hex_nonce)*4)

	def encode(self, plaintext, hex_iv):
		"""
		plaintext: a string representing the plaintext which will be encrypted
		hex_iv: a hex-digit string representing the initialization vector
		return hex-digit string representing the ciphertext
		"""
		bin_iv = pad_to_block(convert_to_bits(int(hex_iv, 16)), len(hex_iv)*4)
		ctr = Counter.new(32)	# counter is 32-bits (4-bytes) long
		def counter_block():
			return bits_to_string(self.bin_nonce + bin_iv + string_to_bits(ctr()))
		encoder = AES.new(self.key, AES.MODE_CTR, counter=counter_block)
		ciphertext = encoder.encrypt(plaintext)
		return str2hex(ciphertext)	# cipher is 32-hex-digits (128 bits) long
	
	def decode(self, ciphertext, hex_iv):
		"""
		ciphertext: a string representing the ciphertext which will be decrypted
		hex_iv: a hex-digit string representing the initialization vector
		return hex-digit string representing the plaintext
		"""
		bin_iv = pad_to_block(convert_to_bits(int(hex_iv, 16)), len(hex_iv)*4)
		ctr = Counter.new(32)	# counter is 32-bits (4-bytes) long
		def counter_block():
			return bits_to_string(self.bin_nonce + bin_iv + string_to_bits(ctr()))
		decoder = AES.new(self.key, AES.MODE_CTR, counter=counter_block)
		plaintext = decoder.decrypt(ciphertext)
		return str2hex(plaintext)


# The following part includes the functions that I used to test 
# different modules of the class
def test_counter_block_function():	
	hex_nonce = ''.join('00 6C B6 DB'.split())
	print hex_nonce
	hex_iv = ''.join('C0 54 3B 59 DA 48 D9 0B'.split())
	print hex_iv
	bin_nonce = pad_to_block(convert_to_bits(int(hex_nonce, 16)), len(hex_nonce)*4)
	print bin_nonce
	bin_iv = pad_to_block(convert_to_bits(int(hex_iv, 16)), len(hex_iv)*4)
	ctr = Counter.new(32)
	def counter_block():
		return bits_to_string(bin_nonce + bin_iv + string_to_bits(ctr()))

	final_str = hex(int(display_bits(string_to_bits(counter_block())), 2))[2:-1].zfill(32)
	print final_str
	print final_str == ''.join('00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01'.lower().split())
	final_str = hex(int(display_bits(string_to_bits(counter_block())), 2))[2:-1].zfill(32)
	print final_str
	print final_str == ''.join('00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 02'.lower().split())

