# netfilter_test

## usage
```
$ iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE
$ make
$ nfq_test
```
