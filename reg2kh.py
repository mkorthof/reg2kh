
# 2011-08-31 reg2kh.py by Matt (kobowi)
# Exports SSH host keys from PuTTY or WinSCP to known_hosts format

# source: https://bitbucket.org/kobowi/reg2kh
#					http://kobowi.co.uk/blog/2011/08/convert-winscpputty-ssh-host-keys-to-known_hosts-format/#comment-14794

# 2017-03-24 MK:
# - changed _winreg to winreg (python 3)
# - changed print format (python 3)
# - changed def convert_key:
#			out = out.encode("iso-8859-1")
# 		return b64encode(out).decode("iso-8859-1")
# - added comma_cnt var and "if" statements (different amount of fields)
# - added fingerprint, showerrors and showdebug options
# - catch socket.errors

import winreg, getopt, sys, socket
from base64 import *
import hashlib

subkeys = {
	"putty": "Software\SimonTatham\PuTTY\SshHostKeys",
	"winscp": "Software\Martin Prikryl\WinSCP 2\SshHostKeys"
}

def get_values(root, subkey):
	""" Enum values at a particular key in the registry """
	key = winreg.OpenKey(root, subkey)
	idx = 0
	try:
		while True:
			val = winreg.EnumValue(key, idx)
			yield val
			idx = idx + 1
	except WindowsError:
		pass
	winreg.CloseKey(key)
	
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

def parse_meta(data, showdebug):
	# Split the name to get the type@port:host
	type, address = data.split('@')			
	port, host = address.split(':')			
	# Convert the key type
	if type == "rsa2": type = "ssh-rsa"
	elif type == "dsa": type = "ssh-dss"
	elif type == "dss": type = "ssh-dss"
	if showdebug:
		print ("[DEBUG] data: %s type: %s address: %s port: %s host: %s" % (data, type, address, port, host))
	return (type, host, port)
	
def convert_key(data, type):
	# Putty seems to store the keys as 0x[Exponent],0x[Modulus]
	comma_cnt=data.count(',')
	if comma_cnt == 2:
		f1, exponent, modulus = data.split(",")		
	elif comma_cnt == 3:
		exponent, modulus, f3, f4 = data.split(",")		
	else:
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
	return b64encode(out.encode('iso-8859-1')).decode('ascii'), out

def fp(out, hash):
	if hash == "md5": fp_plain=hashlib.md5(out.encode('iso-8859-1')).hexdigest()
	if hash == "sha256": fp_plain=hashlib.sha256(out.encode('iso-8859-1')).hexdigest()
	return '(' + hash.upper() + ') ' + ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))
    
def usage():
	print ("reg2kh --putty --winscp [--noresolve] [--fp-md5|sha256]")
	print ("Exports SSH host keys from PuTTY or WinSCP to known_hosts format.")
	print ("    --putty          Export keys from PuTTY")
	print ("    --winscp         Export keys from WinSCP")
	print ("    --noresolve      Don't resolve hosts to IP addresses")
	print ("    --fp-md5         Display md5 key fingerprint")
	print ("    --fp-sha256      Display sha256 key fingerprint")
	print ("")
	print ("    --showerrors     Show error messages")
	print ("    --showdebug      Show debug messages")
	
def export(type, resolve, hash, showerrors, showdebug):
	for v in get_values(winreg.HKEY_CURRENT_USER, subkeys[type]):
		(type, host, port) = parse_meta(v[0], showdebug)
		(key, out) = convert_key(v[1], type)
		if resolve:
			try:
				addr = socket.gethostbyname(host)
			except socket.error as e:
				if showerrors:
					print ("[ERROR] can't resolve %s %s" % (host, e))
		if hash:
			print ("%s " % (fp(out, hash)), end="")
		if resolve and addr != host:
			print ("%s,%s %s %s" % (host, addr, type, key))
		else:
			print ("%s %s %s" % (host, type, key))
		if hash or showerrors or showdebug:
			print ("")
	
def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], '', ["putty", "winscp", "noresolve", "fp-md5", "fp-sha256", "showerrors", "showdebug"])
		toexport = []
		resolve = True
		hash = False
		showerrors = False
		showdebug = False
		for o, a in opts:
			if o in ["--putty", "--winscp"]:
				toexport.append(o[2:])
			if o == "--noresolve":
				resolve = False
			if o == "--fp-md5":
				hash = "md5"
			if o == "--fp-sha256":
				hash = "sha256"
			if o == "--showerrors":
				showerrors = True
			if o == "--showdebug":
				showerrors = True
				showdebug = True
		if len(opts) == 0 or len(toexport) == 0:
			usage();
		for t in toexport:
			export(t, resolve, hash, showerrors, showdebug)
	except getopt.GetoptError as err:
		print (str(err))
		usage()
		sys.exit(2)
	
if __name__ == "__main__":
	main()