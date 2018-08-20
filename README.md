# netfilter_test

## usage
```
$ iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE
$ make
$ nfq_test top-1m.txt
```

## mal url file entry format
```
<any_num>,<url>
e.g.,
1,google.com
2,githwe.net
```
