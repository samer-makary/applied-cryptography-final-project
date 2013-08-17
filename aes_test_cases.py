from unit6_util import ASCII_BITS, convert_to_bits, pad_to_block, bits_to_string
from aes import AES_CTR

class TestCase:

	def __init__(self, hex_key, hex_iv, hex_nonce, hex_pt_blks_list, hex_ctr_blks_list, hex_ct_blks_list):
		self.hex_key = hex_key
		self.hex_iv = hex_iv
		self.hex_nonce = hex_nonce
		self.hex_pt_blks_list = hex_pt_blks_list
		self.hex_ctr_blks_list = hex_ctr_blks_list
		self.hex_ct_blks_list = hex_ct_blks_list

	def __str__(self):
		line_labels = ['AES Key', 'AES-CTR IV', 'Nonce', 'Plaintext Blk(s)', 'Counter Blk(s)', 'Ciphertext Blk(s)']
		max_width = max([len(l) for l in line_labels])
		tab_line_labels = list(map(lambda x: x + (' '*(max_width-len(x))) + ': ', line_labels))
		line_data = [self.hex_key, self.hex_iv, self.hex_nonce,\
						('\n'+' '*max_width+': ').join(self.hex_pt_blks_list),\
						('\n'+' '*max_width+': ').join(self.hex_ctr_blks_list),\
						('\n'+' '*max_width+': ').join(self.hex_ct_blks_list)]
		return '\n'.join([l+d for l,d in zip(tab_line_labels, line_data)])

case1 = TestCase(\
		'AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E',\
		'00 00 00 00 00 00 00 00',\
		'00 00 00 30',\
		['53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67'],\
		['00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01'],\
		['E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8']\
	)	# End of init of case1

case2 = TestCase(\
		'7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63',\
		'C0 54 3B 59 DA 48 D9 0B',\
		'00 6C B6 DB',\
		['00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',\
			'10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F'],\
		['00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01',\
			'00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 02'],\
		['51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88',\
			'EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28']\
	)	# End of init of case2

case3 = TestCase(\
		'76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC',\
		'27 77 7F 3F  4A 17 86 F0',\
		'00 E0 01 7B',\
		['00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',\
			'10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F',\
			'20 21 22 23'],\
		['00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 01',\
			'00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 02',\
			'00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 03'],\
		['C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7',\
			'45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53',\
			'25 B2 07 2F']\
	)	# End of init of case3

# print case1
# print case2
# print case3

def hex_blks2str(_blks_list):
	"""
	the following function will be used to convert hex-digits blocks
	of the plaintext into a single string of ASCII-characters
	"""
	list_str = ''.join((' '.join(_blks_list)).split())
	num_hex_digits = len(list_str)
	hex_int = int(list_str, 16)
	hex_bin = convert_to_bits(hex_int)
	return bits_to_string(pad_to_block(hex_bin, num_hex_digits * 4))

cases = [case1, case2, case3]
for idx,_c in enumerate(cases):
	print 'Test Case #', (idx + 1)
	print _c
	k = ''.join(_c.hex_key.split())
	n = ''.join(_c.hex_nonce.split())
	i = ''.join(_c.hex_iv.split())
	p = hex_blks2str(_c.hex_pt_blks_list)
	c = hex_blks2str(_c.hex_ct_blks_list)
	aes_machine = AES_CTR(k, n)
	enc = aes_machine.encode(p, i)
	dec = aes_machine.decode(c, i)
	p = ''.join(' '.join(_c.hex_pt_blks_list).split()).lower()
	c = ''.join(' '.join(_c.hex_ct_blks_list).split()).lower()
	check_bool = enc == c and dec == p
	if check_bool:
		print 'Test Case Passed'
	else:
		print 'Test Case Failed'
	print '---------------------------------------------------'

print 'Done'