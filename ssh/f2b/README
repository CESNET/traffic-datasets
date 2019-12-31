Installation
============

Prerequisites: fail2ban

a) "Honeypot"
-------------

This action redirects incoming malicious traffic to `destip` and `destport`.
You need to set up new sshd to start "honeypot".
For CentOS7, see [honeypot_sshd_config](honeypot_sshd_config) config of sshd
that will listen on port 2222.  The file should be placed into `/etc/ssh/`
and the new server can be started as follows:
`/usr/sbin/sshd -f /etc/ssh/honeypot_sshd_config`

Copy `iptables-honeypot.conf` into `/etc/fail2ban/actions.d/`.

Example of `/etc/fail2ban/jail.conf`, you can change parameters of
`iptables-honeypot` as you need.

```
[ssh-iptables]

enabled  = true
filter   = sshd
action   = iptables-honeypot[name=SSHhoney, port=ssh, protocol=tcp, destip=, destport=2222]
logpath  = /var/log/secure
maxretry = 3
```

b) "Export to JSON"
-------------------

This action creates JSON file from each ban event.
The JSON file is possible to send to [Warden server](https://warden.cesnet.cz) using `warden_filer`.

Copy `f2ban_ssh.sh` into `/usr/bin/`, it should have `x` (executable)
permission.

Copy `f2b-warden.conf` into `/etc/fail2ban/actions.d/`.

Example of `/etc/fail2ban/jail.conf`:

```
[ssh-iptables]

enabled  = true
filter   = sshd
action   = iptables-honeypot[name=SSHhoney, port=ssh, protocol=tcp, destip=, destport=2222]
logpath  = /var/log/secure
maxretry = 3
```

c) Note
-------

The parameter `action` can contain multiple lines in jail.conf.
The example of both actions is in the [jail.conf](jail.conf).


