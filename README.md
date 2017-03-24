# reg2kh
#### by Matt (kobowi)<br>
Exports SSH host keys from PuTTY or WinSCP to known_hosts format<br>

## Source:
https://bitbucket.org/kobowi/reg2kh<br>
http://kobowi.co.uk/blog/2011/08/convert-winscpputty-ssh-host-keys-to-known_hosts-format/#comment-14794<br>

## Changes:
- 160812 changed _winreg to winreg (python 3)
- 160812 changed print format (python 3)
- 160812 changed def convert_key:
    - out = out.encode("iso-8859-1")
    - return b64encode(out).decode("iso-8859-1")
- 160812 added comma_cnt var and "if" statements (different amount of fields)
- 170324 added fingerprint, showerrors and showdebug options
