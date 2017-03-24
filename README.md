# reg2kh.py
#### by Matt (kobowi)<br>
Exports SSH host keys from PuTTY or WinSCP to known_hosts format

Tested with Python 3.6 (64-bit) for Windows

###### (reverse of kh2reg.py inlcuded with putty src)

## Source:
https://bitbucket.org/kobowi/reg2kh<br>
http://kobowi.co.uk/blog/2011/08/convert-winscpputty-ssh-host-keys-to-known_hosts-format/#comment-14794<br>

## Usage:

```
C:\Users\foo>reg2kh --putty --winscp [--noresolve] [--fp-md5|sha256]

    --putty          Export keys from PuTTY
    --winscp         Export keys from WinSCP
    --noresolve      Don't resolve hosts to IP addresses
    --fp-md5         Display md5 key fingerprint
    --fp-sha256      Display sha256 key fingerprint

    --showerrors     Show error messages
    --showdebug      Show debug messages
```

## Changes:
- 160812 changed _winreg to winreg (python 3)
- 160812 changed print format (python 3)
- 160812 changed def convert_key:
    - out = out.encode("iso-8859-1")
    - return b64encode(out).decode("iso-8859-1")
- 160812 added comma_cnt var and "if" statements (different amount of fields)
- 170324 added fingerprint, showerrors and showdebug options
