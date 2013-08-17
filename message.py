from unit6_util import pad_to_block, bits_to_string, convert_to_bits, ASCII_BITS
from string import hexdigits

_MSG = 'msg'
_IV = 'iv'

class Message:

	def __init__(self, msg_dict):
		if _MSG in msg_dict and _IV in msg_dict:
			self.data = msg_dict[_MSG]
			self.iv = msg_dict[_IV]
			self.empty_msg = False
		elif len(msg_dict) == 0:
			self.empty_msg = True

	def is_empty(self):
		"""
		this function returns True if the message was empty
		"""
		return self.empty_msg

	def __str__(self):
		if not self.is_empty():
			line_labels = ['Message', 'IV']
			line_info = [self.data, self.iv]
			max_width = max(list(map(len, line_labels)))
			tab_line_labels = list(map(lambda x: x + (' '*(max_width-len(x))) + ': ', line_labels))
			start_str = '===Start Message Data===\n'
			end_str = '\n===End Message Data==='
			return start_str + '\n'.join([l+i for l,i in zip(tab_line_labels, line_info)]) + end_str
		else:
			return 'Message: '

	def is_hex(self):
		""" 
		this function checks if all the digits of _str are hexdigits
		"""
		if not self.is_empty():
			return all(c in hexdigits for c in self.data)
		else:
			raise Exception('Message is EMPTY')

	def msg_hex2str(self):
		"""
		the following function will be used to convert
		a hex message into a string of characters
		"""
		if not self.is_empty():
		    hex_int = int(self.data, 16)
		    hex_bin = convert_to_bits(hex_int)
		    return bits_to_string(pad_to_block(hex_bin, ASCII_BITS))
		else:
			raise Exception('Message is EMPTY')

