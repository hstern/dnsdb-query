#!/usr/bin/env python

# Copyright (c) 2013-2014 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Reference implementation of the DNSDB HTTP API.

Copyright (c) 2013-2014 by U{Farsight Security, Inc.
<https://www.farsightsecurity.com/>}

See U{https://api.dnsdb.info/} for more details about the DNSDB API.  You
may obtain new versions of this tool from
U{https://github.com/dnsdb/dnsdb-query}.

JSON output is compatible with the U{Passive DNS Common Output Format
<http://tools.ietf.org/html/draft-dulaunoy-kaplan-passive-dns-cof-01>}.

Usage::

    from dnsdb_query import DnsdbClient

    server='https://api.dnsdb.info'
    apikey='d41d8cd98f00b204e9800998ecf8427e'

    client = DnsdbClient(server,apikey)
    for rrset in client.query_rrset('www.dnsdb.info'):
        # rrset is a decoded JSON blob
        print repr(rrset)
"""

import calendar
import errno
import locale
import optparse
import os
import re
import sys
import time
import urllib
import urllib2
import cStringIO as StringIO

try:
    import json
except ImportError:
    import simplejson as json

DEFAULT_CONFIG_FILES = filter(os.path.isfile, ('/etc/dnsdb-query.conf', os.path.expanduser('~/.dnsdb-query.conf')))
DEFAULT_DNSDB_SERVER = 'https://api.dnsdb.info'

locale.setlocale(locale.LC_ALL, '')

class QueryError(Exception):
    """
    Error raised if a communication error occurs with the DNSDB server,
    such as if authentication fails.
    """

class DnsdbClient(object):
    """
    Python client for the DNSDB API.
    """

    def __init__(self, server, apikey, limit=None):
        """
        @param server: URL to DNSDB server, no trailing slash
        @type server: string (url)

        @param apikey: API key, long hexadecimal string
        @type apikey: string

        @param limit: Maximum number of rows per query
        @type limit: int
        """
        self.server = server
        self.apikey = apikey
        self.limit = limit

    def query_rrset(self, oname, rrtype=None, bailiwick=None):
        """
        Look up an rrset in DNSDB.

        @param oname: Search for this name.  May include wildcards.
        @type oname: string

        @param rrtype: A DNS rrtype
        @type rrtype: string

        @param bailiwick: Limit the search to this bailiwick.
        @type bailiwick: string

        @return: a list of decoded json blobs
        @rtype: list(dict)

        @raise QueryError: if the DNSDB query fails
        """
        if bailiwick:
            if not rrtype:
                rrtype = 'ANY'
            path = 'rrset/name/%s/%s/%s' % (quote(oname), rrtype, quote(bailiwick))
        elif rrtype:
            path = 'rrset/name/%s/%s' % (quote(oname), rrtype)
        else:
            path = 'rrset/name/%s' % quote(oname)
        return self._query(path)

    def query_rdata_name(self, rdata_name, rrtype=None):
        """
        Look up an rdata in DNSDB by name.

        @param rdata_name: Search for this name.  May include wildcards.
        @type rdata_name: string

        @param rrtype: A DNS rrtype
        @type rrtype: string

        @return: a list of decoded json blobs
        @rtype: list(dict)

        @raise QueryError: if the DNSDB query fails
        """
        if rrtype:
            path = 'rdata/name/%s/%s' % (quote(rdata_name), rrtype)
        else:
            path = 'rdata/name/%s' % quote(rdata_name)
        return self._query(path)

    def query_rdata_ip(self, rdata_ip):
        """
        Look up an rdata in DNSDB by ip.

        @param rdata_ip: Search for this ip.  May include wildcards.
        @type rdata_ip: string

        @return: a list of decoded json blobs
        @rtype: list(dict)

        @raise QueryError: if the DNSDB query fails
        """
        path = 'rdata/ip/%s' % rdata_ip.replace('/', ',')
        return self._query(path)

    def _query(self, path):
        """
        Internal function to run a query against DNSDB.

        @param path: URL in dnsdb to query
        @type path: string

        @return: a list of decoded json blobs
        @rtype: list(dict)

        @raise QueryError: if the DNSDB query fails
        """
        res = []
        url = '%s/lookup/%s' % (self.server, path)
        if self.limit:
            url += '?limit=%d' % self.limit
        req = urllib2.Request(url)
        req.add_header('Accept', 'application/json')
        req.add_header('X-Api-Key', self.apikey)
        try:
            http = urllib2.urlopen(req)
            while True:
                line = http.readline()
                if not line:
                    break
                res.append(json.loads(line))
        except urllib2.HTTPError, e:
            raise QueryError, e.message, sys.exc_traceback
        return res

dns_types = '''
    A A6 AAAA AFSDB ANY APL ATMA AXFR CAA CDS CERT CNAME DHCID DLV DNAME
    DNSKEY DS EID GPOS HINFO HIP IPSECKEY ISDN IXFR KEY KX LOC MAILA MAILB
    MB MD MF MG MINFO MR MX NAPTR NIMLOC NINFO NS NSAP NSAP_PTR NSEC NSEC3
    NSEC3PARAM NULL NXT OPT PTR PX RKEY RP RRSIG RT SIG SINK SOA SPF SRV
    SSHFP TA TALINK TKEY TSIG TXT URI WKS X25'''.split()
"""
@var dns_types: All DNS types supported by libwdns 0.5.
"""

param_split_re = re.compile(r'/(%s)(?:$|/)' % "|".join(dns_types), re.I)
"""
@var param_split_re: Regular expression that is used to split rrset and rdata
input parameters.  Needed because they are slash delimited and both rname and
bailiwick may contain slashes.
"""

def split_rrset(rrset):
    """
    Takes a parameter of the form 'rname/rrtype/bailiwick' and splits it
    into three strings, working around slashes that may be embedded in rname
    or bailiwick.

    @param rrset: The rrset to split.
    @type rrset: string

    @return (rname, rrtype, bailiwick)
    """
    parts = param_split_re.split(rrset, maxsplit=1)
    if len(parts) == 1:
        return (parts[0],None,None)
    else:
        parts[1] = parts[1].upper()
        return parts

def split_rdata(rrset):
    """
    Takes a parameter of the form 'rname/rrtype' and splits it
    into two strings, working around slashes that may be embedded in
    rname or bailiwick.

    @param rrset: The rrset to split.
    @type rrset: string

    @return: (rname, rrtype)
    @rtype: collection
    """
    parts = param_split_re.split(rrset, maxsplit=1)
    if parts[2]:
        raise ValueError, "Invalid rrset: '%s'" % rrset

    if len(parts) == 1:
        return parts[0],None
    else:
        parts[1] = parts[1].upper()
        return parts[:2]

def quote(path):
    """
    Wraps urllib.quote with no safe characters such that slashes are
    escaped.

    @type path: string
    @rtype: string
    """
    return urllib.quote(path, safe='')

def sec_to_text(ts):
    """
    Converts a UNIX timesetamp to a human-readable date string in UTC.

    @param ts: UNIX timestamp
    @type ts: int

    @return: formatted timestamp in UTC
    @rtype: string
    """
    return time.strftime('%Y-%m-%d %H:%M:%S -0000', time.gmtime(ts))

def rrset_to_text(m):
    """
    Returns the presentation format of an rrset blob.

    @param m: decoded JSON blob
    @type m: dict

    @return: presentation format of an rrset
    @rtype: string
    """
    s = StringIO.StringIO()

    if 'bailiwick' in m:
        s.write(';;  bailiwick: %s\n' % m['bailiwick'])

    if 'count' in m:
        s.write(';;      count: %s\n' % locale.format('%d', m['count'], True))

    if 'time_first' in m:
        s.write(';; first seen: %s\n' % sec_to_text(m['time_first']))
    if 'time_last' in m:
        s.write(';;  last seen: %s\n' % sec_to_text(m['time_last']))

    if 'zone_time_first' in m:
        s.write(';; first seen in zone file: %s\n' % sec_to_text(m['zone_time_first']))
    if 'zone_time_last' in m:
        s.write(';;  last seen in zone file: %s\n' % sec_to_text(m['zone_time_last']))

    if 'rdata' in m:
        for rdata in m['rdata']:
            s.write('%s IN %s %s\n' % (m['rrname'], m['rrtype'], rdata))

    s.seek(0)
    return s.read()

def rdata_to_text(m):
    """
    Returns the presentation format of an rdata blob.  It is
    formatted like a record in a zone file.

    @param m: decoded JSON blob
    @type m: dict

    @return: presentation format of an rdata blob
    @rtype: string
    """
    return '%s IN %s %s' % (m['rrname'], m['rrtype'], m['rdata'])

def parse_config(cfg_files):
    """
    Loads configuration information from a list of configuration files.
    If a key occurs in a subsequent file it is replaced.

    Configuration files should be of the form::
    
        KEY="value"

    @param cfg_files: List of configuration files to parse.
    @type cfg_files: list(string)

    @return: Dictionary of configuration options.
    @rtype: dict

    @raise IOError: If a configuration file is missing or if cfg_files
    is empty.
    """
    config = {}

    if not cfg_files:
        raise IOError(errno.ENOENT, 'No config files to parse.')

    for fname in cfg_files:
        for line in open(fname):
            key, eq, val = line.strip().partition('=')
            val = val.strip('"')
            config[key] = val

    return config

def time_parse(s):
    """
    Parses a time value and returns a UNIX timestamp.

    @param s: time value (int, Y-M-D, or Y-M-D H:M:S)
    @type s: string

    @return: A UNIX timestamp
    @rtype: int

    @raise ValueError: If the time value is not parseable.
    """
    try:
        epoch = int(s)
        return epoch
    except ValueError:
        pass

    try:
        epoch = int(calendar.timegm(time.strptime(s, '%Y-%m-%d')))
        return epoch
    except ValueError:
        pass

    try:
        epoch = int(calendar.timegm(time.strptime(s, '%Y-%m-%d %H:%M:%S')))
        return epoch
    except ValueError:
        pass

    raise ValueError, 'Invalid time: "%s"' % s

def filter_before(res_list, before_time):
    """
    Filters out records older than before_time.

    @param res_list: list of json blobs
    @type res_list: list(dict)

    @param before_time: UNIX timestamp or Y-M-D or Y-M-D H:M:S
    @type before_time: int, string

    @return: All blobs with time_first < before_time
    @rtype: list(dict)

    @raise ValueError: if before_time is unparseable by time_parse
    """
    before_time = time_parse(before_time)
    new_res_list = []

    for res in res_list:
        if 'time_first' in res:
            if res['time_first'] < before_time:
                new_res_list.append(res)
        elif 'zone_time_first' in res:
            if res['zone_time_first'] < before_time:
                new_res_list.append(res)
        else:
            new_res_list.append(res)

    return new_res_list

def filter_after(res_list, after_time):
    """
    Filters out records newer than after_time.

    @param res_list: list of json blobs
    @type res_list: list(dict)

    @param before_time: UNIX timestamp or Y-M-D or Y-M-D H:M:S
    @type before_time: int, string

    @return: All blobs with time_first > before_time
    @rtype: list(dict)

    @raise ValueError: if after_time is unparseable by time_parse
    """
    after_time = time_parse(after_time)
    new_res_list = []

    for res in res_list:
        if 'time_last' in res:
            if res['time_last'] > after_time:
                new_res_list.append(res)
        elif 'zone_time_last' in res:
            if res['zone_time_last'] > after_time:
                new_res_list.append(res)
        else:
            new_res_list.append(res)

    return new_res_list

def main():
    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', dest='config', 
        help='config file', action='append')
    parser.add_option('-r', '--rrset', dest='rrset', type='string',
        help='rrset <ONAME>[/<RRTYPE>[/BAILIWICK]]')
    parser.add_option('-n', '--rdataname', dest='rdata_name', type='string',
        help='rdata name <NAME>[/<RRTYPE>]')
    parser.add_option('-i', '--rdataip', dest='rdata_ip', type='string',
        help='rdata ip <IPADDRESS|IPRANGE|IPNETWORK>')
    parser.add_option('-s', '--sort', dest='sort', type='string', help='sort key')
    parser.add_option('-R', '--reverse', dest='reverse', action='store_true', default=False,
        help='reverse sort')
    parser.add_option('-j', '--json', dest='json', action='store_true', default=False,
        help='output in JSON format')
    parser.add_option('-l', '--limit', dest='limit', type='int', default=0,
        help='limit number of results')

    parser.add_option('', '--before', dest='before', type='string', help='only output results seen before this time')
    parser.add_option('', '--after', dest='after', type='string', help='only output results seen after this time')

    options, args = parser.parse_args()
    if args:
        parser.print_help()
        sys.exit(1)

    try:
        cfg = parse_config(options.config or DEFAULT_CONFIG_FILES)
    except IOError, e:
        print >>sys.stderr, str(e)
        sys.exit(1)

    if not 'DNSDB_SERVER' in cfg:
        cfg['DNSDB_SERVER'] = DEFAULT_DNSDB_SERVER
    if not 'APIKEY' in cfg:
        sys.stderr.write('dnsdb_query: APIKEY not defined in config file\n')
        sys.exit(1)

    client = DnsdbClient(cfg['DNSDB_SERVER'], cfg['APIKEY'], options.limit)
    try:
        if options.rrset:
            res_list = client.query_rrset(*split_rrset(options.rrset))
            fmt_func = rrset_to_text
        elif options.rdata_name:
            res_list = client.query_rdata_name(*split_rdata(options.rdata_name))
            fmt_func = rdata_to_text
        elif options.rdata_ip:
            res_list = client.query_rdata_ip(options.rdata_ip)
            fmt_func = rdata_to_text
        else:
            parser.print_help()
            sys.exit(1)
    except QueryError, e:
        print >>sys.stderr, e.message
        sys.exit(1)

    if options.json:
        fmt_func = json.dumps

    if len(res_list) > 0:
        if options.sort:
            if not options.sort in res_list[0]:
                sort_keys = res_list[0].keys()
                sort_keys.sort()
                sys.stderr.write('dnsdb_query: invalid sort key "%s". valid sort keys are %s\n' % (options.sort, ', '.join(sort_keys)))
                sys.exit(1)
            res_list.sort(key=lambda r: r[options.sort], reverse=options.reverse)
        if options.before:
            res_list = filter_before(res_list, options.before)
        if options.after:
            res_list = filter_after(res_list, options.after)

    for res in res_list:
        sys.stdout.write('%s\n' % fmt_func(res))

if __name__ == '__main__':
    main()
