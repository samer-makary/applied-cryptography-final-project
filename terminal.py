from urllib import urlopen, urlencode
from message import Message
import json

_TOKEN = 'token'
_PUBLIC = 'public'
_STATUS = 'status'
_SUCCESS = 'success'
_REPLY = 'reply'
_ERR = 'error'

def check_output(output):
    data = output.read()
    if output.getcode() != 200:
        raise Exception(data)
    data = json.loads(data)
    return data

def initialize(person):
    data = {'type':'init'}
    output = urlopen(person, urlencode(data))
    data = check_output(output)
    # returns a dictionary 
    # {"token":<token_value>, "public": <g^x>}
    return data

def send_key(person, token, public, name):
    """
    person: url of Alice/Bob
    token: token used to track session
    public: the public value of the other party
    name: the name of the other party - "alice", "bob"
    """
    data = {'type':'key',
            'token':token,
            'public':public,
            'name':name}
    output = urlopen(person, urlencode(data))
    data = check_output(output)
    # Should be a response {"status":"success"}
    return data

def receive_msg_from(person, token):
    data = {'type':'msg',
            'token':token}
    output = urlopen(person, urlencode(data))
    data = check_output(output)
    # should be a response
    # {"msg":<cipher>, "iv":<initialization vector>}
    return data

def send_msg_to(person, token, cipher, iv):
    data = {'type':'msg',
            'token':token,
            'message':cipher,
            'iv':iv}
    output = urlopen(person, urlencode(data))
    data = check_output(output)
    # If the person doesn't have
    # a response to the message, the response will
    # just be {"status":"success"}
    # else, the response will be {"status":"sucess", 
    #                             "reply":{"msg":<cipher>,
    #                                      "iv":<initialization vector>}}
    return data


class Terminal:

	def __init__ (self, name, uri, mitm=False):
		self.name = name
		self.uri = uri
		if not mitm:
			init_dict = initialize(uri)
			self.public = init_dict[_PUBLIC]
			self.token = init_dict[_TOKEN]
		else:
			self.public = ''
			self.token = ''

	def __str__(self):
		line_labels = ['Name', 'URI', 'Public Key', 'Token']
		line_info = [self.name, self.uri, self.public, self.token]
		max_width = max(list(map(len, line_labels)))
		tab_line_labels = list(map(lambda x: x + (' '*(max_width-len(x))) + ': ', line_labels))
		start_str = '===Start Terminal Info===\n'
		end_str = '\n===End Terminal Info==='
		return start_str + '\n'.join([l+i for l,i in zip(tab_line_labels, line_info)]) + end_str

	def __eq__(self, other):
		return self.uri == other.uri

	def send_key_of(self, other):
		"""
		other: represents the terminal whose key will be send to this terminal
		returns True if sending succeeded, False otherwise
		"""
		resp_dict = send_key(self.uri, self.token, other.public, other.name)
		return resp_dict[_STATUS] == _SUCCESS

	def receive_msg(self):
		"""
		this function receive a message from this terminal
		returns a Message object
		"""
		resp_dict = receive_msg_from(self.uri, self.token)
		return Message(resp_dict)

	def send_msg(self, msg):
		"""
		msg: Message object that contains the cipher and the iv that will
		be send to this terminal.
		return Message object that could be EMPTY is there was no response
		from this terminal after msg was sent
		"""
		resp_dict = send_msg_to(self.uri, self.token, msg.data, msg.iv)
		if resp_dict[_STATUS] == _SUCCESS:
			if _REPLY in resp_dict:
				return Message(resp_dict[_REPLY])
			else:
				return Message({})
		else:
			raise Exception('Unidentified response >>> ' + str(resp_dict))

