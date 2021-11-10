# hive-library-examples

Set of useful hive-library example scripts that can be used standalone.

### first of all
Get latest hive-library
```
pip3 install hive-library
```

### whois2hive.py

Get all IPs from Hive project, make WHOIS query and create tags with NET-Name value

```
python3 ./whois2hive.py -P 11111111-2222-47ff-5555-66666666
```

### responder2hive.py

Uploads to Hive project credentials loot from Responder.db:
```
python3 ./responder2hive.py -P 11111111-2222-47ff-5555-66666666 -f ./Responder.db
```

### gowitness2hive.py

Uploads to Hive project:
* Screensots
* Server Headers
* CN's from TLS certs
Also creates tag "GoWitness" for ports
```
python3 ./gowitness2hive.py -P 11111111-2222-47ff-5555-66666666 -f ./gowitness.sqlite3
```
"screenshots" dir should be next to gowitness.sqlite3 location

### whatweb2hive.py
Import WhatWeb json results to Hive. 

1) run WhatWeb smth like:
```
whatweb -i ./targets.txt --log-json=whatweb_result.json 
```
2) Run import to Hive:
```
python3 ./whatweb2hive.py -P 11111111-2222-47ff-5555-66666666 -f whatweb_result.json
```

### risq2hive.py
Query Riskiq service and imports to Hive all subdomains.
1) Login to https://community.riskiq.com/
2) Get `pts` cookie value
3) run your recon query and import results to Hive

```
python3 ./risq2hive.py -P 11111111-2222-47ff-5555-66666666 -d domain.tld -C [pts cookie value]
```

### get_target_list_4_web.py

If you have a Hive project and want to feed it into your favorite web scanning/crawling tools.

```
python3 ./get_target_list_4_web.py -P 11111111-2222-47ff-5555-66666666 > targets_web.list
```
gives you a combined list with all ips, hostnames, ports with a related URI schemas (http:// or https://)

### resolve_noip_hostnames.py

Try to resolve all 'noip' hostnames on your Hive project

```
python3 ./resolve_noip_hostnames.py -P 11111111-2222-47ff-5555-66666666
```

### snippets.py
Bunch of functions you can use to operate with Hive data:
* `delete_ip()`
* `delete_ips_by_filter()`
* `delete_node(node_id)`
* `delete_noip_hostnames()`
* `delete_not_open_ports()`
* `delete_pics_by_record()`
* `delete_similar_pics_for_port()`
* `delete_wildcard_hostnames()`
* `fix_http_2_https_4_443()`
* `resolve_hostmanes_without_ip()`
* `add_lowercase_hostmanes()`


