# atsshd
An sshd that bruteforces attackers with their own passwords.

## Description
atsshd listens for incoming SSH connections and logs the username and password.  It has an attack mode option where it will try the username/password combo against the attacker IP in realtime, as the credentials come in.  All incoming authentication attempts will always fail.  The sshd will not attack 127.0.0.1 in order to avoid loops.

```
Usage of ./atsshd:
  -A	turn on attack mode
  -b banner
    	SSH server banner (default "SSH-2.0-OpenSSH_6.1p2")
  -h string
    	server host key private pem file
  -l string
    	output log file
  -p int
    	port to listen on (default 22)
```

Note: golang ssh lib only allows u to attempt one password per tcp connection.  I should fix this.
In attack mode, the attacker will get attacked serially.  If 3 network failures happen in a row, we give up on attacking and just log the incoming passwords.

## TODO
- add an option to port scan the attacker to find an sshd on non-standard port?

## Disclaimer
This tool is for demonstration purposes only
