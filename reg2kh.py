import _winreg, getopt, sys, socket
from base64 import *

subkeys = {
	"putty": "Software\SimonTatham\PuTTY\SshHostKeys",
	"winscp": "Software\Martin Prikryl\WinSCP 2\SshHostKeys"
}

def get_values(root, subkey):
	""" Enum values at a paticular key in the registry """
	key = _winreg.OpenKey(root, subkey)
	idx = 0
	try:
		while True:
			val = _winreg.EnumValue(key, idx)
			yield val
			idx = idx + 1
	except WindowsError:
		pass
	_winreg.CloseKey(key)
	
def decode(h):
	"""Convert a hex string in the format
		0x0123456789ABCDEF
		- or -
		0123456789ABCDEF
		
		to a byte array
	"""
	if h.startswith('0x'):
		h = h[2:]
	if len(h) % 2 != 0:
		h = "0" + h
	data = []
	for i in range(0, len(h), 2):
		data.append(int(h[i:i + 2], 16))
	return data

def parse_meta(data):
	# Split the name to get the type@port:host
	type, address = data.split('@')			
	port, host = address.split(':')			
	# Convert the key type
	if type == "rsa2": type = "ssh-rsa"
	elif type == "dsa": type = "ssh-dss"
	return (type, host, port)
	
def convert_key(data, type):
	# Putty seems to store the keys as 0x[Exponent],0x[Modulus]		
	exponent, modulus = data.split(",")		
	
	# start building the buffer from the key's parts
	# from decoding some known_hosts entries it looks like the key starts with 0x 00 00 00 07
	buffer = [0, 0, 0, 7]
	
	# then we add the key type followed by three more nulls
	for c in type:
		buffer.append(ord(c))
	buffer.append(0)
	buffer.append(0)
	buffer.append(0)
	
	# next byte is the length of the exponent in bytes
	exponent = decode(exponent)
	for b in decode(hex(len(exponent))):
		buffer.append(b)
	
	# followed by the exponent's bytes
	for e in exponent:
		buffer.append(e)
	
	# and three more nulls
	buffer.append(0)
	buffer.append(0)
	buffer.append(0)
	
	# add the length of the modulus in bytes - put a 0 on the front of it first
	# beware that this may span multiple bytes(!)
	modulus = decode(modulus)
	modulus.insert(0, 0)
	for b in decode(hex(len(modulus))):
		buffer.append(b)
	
	# add the bytes from the modulus
	for m in modulus:
		buffer.append(m)
	
	out = ""
	for b in buffer:
		out = out + chr(b)
	
	# return the out buffer as base 64
	return b64encode(out)

def usage():
	print "reg2kh --putty --winscp [--resolve]"
	print "Exports SSH host keys from PuTTY or WinSCP to known_hosts format."
	print "    --putty          Export keys from PuTTY"
	print "    --winscp         Export keys from WinSCP"
	print "    --noresolve      Don't resolve hosts to IP addresses"
	
def export(type, resolve):
	for v in get_values(_winreg.HKEY_CURRENT_USER, subkeys[type]):
		type, host, port = parse_meta(v[0])
		key = convert_key(v[1], type)
		if resolve:
			addr = socket.gethostbyname(host)

		if resolve and addr != host:
			print "%s,%s %s %s" % (host, addr, type, key)
		else:
			print "%s %s %s" % (host, type, key)
	
def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], '', ["putty", "winscp", "noresolve"])
		toexport = []
		resolve = True
		for o, a in opts:
			if o in ["--putty", "--winscp"]:
				toexport.append(o[2:])
			if o == "--noresolve":
				resolve = False
		if len(opts) == 0 or len(toexport) == 0:
			usage();
		for t in toexport:
			export(t, resolve)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit(2)
	
if __name__ == "__main__":
	main()