# atsshd
An sshd that logs passwords and pubkey auth attempts.  It can also bruteforce attackers with their own passwords.

## Description
atsshd listens for incoming SSH connections and logs the username, password, and/or pubkey fingerprint.  It has an attack mode option where it will try the username/password combo against the attacker IP in realtime, as the credentials come in.  All incoming authentication attempts will always fail.  The sshd will not attack 127.0.0.1 in order to avoid loops.

```console
$ atsshd --help
Usage of atsshd:
  -A	enable attack mode
  -b banner
    	SSH server banner (default "SSH-2.0-OpenSSH_6.1p2")
  -h file
    	SSH server host key PEM files
  -l file
    	output log file
  -p port
    	port to listen on (default 22)
  -s source
    	source IP of interface to bind to
```

In attack mode, the attacker will get attacked serially.  If 3 network failures happen in a row, we give up on attacking and just log the incoming passwords.

## Disclaimer
This tool is for demonstration purposes only
