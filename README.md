dnsdb-query
===========

These clients are reference implementations of the [DNSDB HTTP API](https://api.dnsdb.info/).  Output is
compliant with the [Passive DNS Common Output Format](http://tools.ietf.org/html/draft-dulaunoy-kaplan-passive-dns-cof-01).

Please see https://www.dnsdb.info/ for more information.

dnsdb-query
-----------

dnsdb-query is a simple curl-based wrapper for the DNSDB HTTP API.

The script sources the config file `/etc/dnsdb-query.conf` as a shell fragment.
If the config file is not present in `/etc`, the file `$HOME/.dnsdb-query.conf`
is sourced instead.

The config file MUST set the value of the APIKEY shell variable to the API
key provided to you by Farsight Security.

For example, if your API key is d41d8cd98f00b204e9800998ecf8427e, place the
following line in `/etc/dnsdb-query.conf` or `$HOME/.dnsdb-query.conf`:

```
APIKEY="d41d8cd98f00b204e9800998ecf8427e"
```

Other shell variables that may be set via the config file or command line
are:

DNSDB_SERVER
The base URL of the DNSDB HTTP API, minus the /lookup component. Defaults to
`https://api.dnsdb.info.`

DNSDB_FORMAT
The result format to use, either text or json. Defaults to text.

dnsdb-query supports the following usages:

```
Usage: dnsdb-query rrset <ONAME>[/<RRTYPE>[/<BAILIWICK>]]
Usage: dnsdb-query rdata ip <IPADDRESS>
Usage: dnsdb-query rdata name <NAME>[/<RRTYPE>]
Usage: dnsdb-query rdata raw <HEX>[/<RRTYPE>]
```

If your rrname, bailiwick or rdata contains the `/` character you
will need to escape it to `%2F` on the command line.  eg:

`./dnsdb_query -r 1.0%2F1.0.168.192.in-addr.arpa`
	
retrieves the rrsets for `1.0/1.0.168.192.in-addr.arpa`.

dnsdb_query.py
--------------

dnsdb_query.py is a more advanced Python client for the DNSDB HTTP API. It
is similar to the dnsdb-query shell script but supports some additional
features like sorting and setting the result limit parameter. It is also
embeddable as a Python module.

```
Usage: dnsdb_query.py [options]

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config=CONFIG
                        config file
  -r RRSET, --rrset=RRSET
                        rrset <ONAME>[/<RRTYPE>[/BAILIWICK]]
  -n RDATA_NAME, --rdataname=RDATA_NAME
                        rdata name <NAME>[/<RRTYPE>]
  -i RDATA_IP, --rdataip=RDATA_IP
                        rdata ip <IPADDRESS|IPRANGE|IPNETWORK>
  -s SORT, --sort=SORT  sort key
  -R, --reverse         reverse sort
  -j, --json            output in JSON format
  -l LIMIT, --limit=LIMIT
                        limit number of results
  --before=BEFORE       only output results seen before this time
  --after=AFTER         only output results seen after this time
```

Or, from Python:

```
from dnsdb_query import DnsdbClient

server='https://api.dnsdb.info'
apikey='d41d8cd98f00b204e9800998ecf8427e'

client = DnsdbClient(server,apikey)
for rrset in client.query_rrset('www.dnsdb.info'):
    # rrset is a decoded JSON blob
    print repr(rrset)
```
