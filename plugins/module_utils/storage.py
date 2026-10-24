# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Objects in a central storage, named by the URLs of ump's state backends:
a directory here or over SSH, S3, R2, Consul, Vault. The cache plugin
ofzhur.ansible.facts and the host files in a storage (ofzhur.ansible.host)
share it, and the options of the doc fragment ofzhur.ansible.storage.
Python standard library only."""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
import shlex
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

HTTP_TIMEOUT = 30
SSH_TIMEOUT = 60
SECTION = 'ofzhur_storage'
ENV = 'ANSIBLE_OFZHUR_STORAGE_'
SCHEMES = 'file, ssh, s3, r2, consul, http+consul, vault, http+vault'


class StoreError(Exception):
    pass


def read_file(path, what):
    try:
        with open(os.path.expanduser(path)) as f:
            return f.read().strip()
    except OSError as e:
        raise StoreError(f'{what}: {e.strerror}: {path}') from None


def select(names, prefix, suffixes):
    """The names that start with prefix and end with one of suffixes (any, without), but for dot names and the
    empty name (the folder marker PREFIX/ of a bucket)."""
    return [n for n in names if n and n.startswith(prefix) and not n.startswith('.') and '/' not in n
            and (not suffixes or n.endswith(tuple(suffixes)))]


# --- storages -----------------------------------------------------------------
#
# A storage holds named objects (bytes) under a prefix of its own: it reads
# one (None when there is none) or every one whose name starts with a prefix
# and ends with a suffix, writes, deletes and lists them. Names never contain
# "/"; deeper objects are not listed.

class Directory:
    """A directory on this machine (file:///path)."""

    def __init__(self, path):
        self.dir = path

    def read(self, name):
        try:
            with open(os.path.join(self.dir, name), 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except OSError as e:
            raise StoreError(f'reading {name}: {e.strerror}') from None

    def write(self, name, data):
        try:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f'.{name}.')
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(data)
                os.replace(tmp, os.path.join(self.dir, name))
            except BaseException:
                os.unlink(tmp)
                raise
        except OSError as e:
            raise StoreError(f'writing {name}: {e.strerror}') from None

    def delete(self, names):
        for name in names:
            try:
                os.remove(os.path.join(self.dir, name))
            except FileNotFoundError:
                pass
            except OSError as e:
                raise StoreError(f'deleting {name}: {e.strerror}') from None

    def read_all(self, prefix='', suffixes=()):
        return [(n, d) for n in self.list(prefix, suffixes) if (d := self.read(n)) is not None]

    def list(self, prefix='', suffixes=()):
        try:
            names = os.listdir(self.dir)
        except FileNotFoundError:
            return []
        except OSError as e:
            raise StoreError(f'listing: {e.strerror}') from None
        return [n for n in select(names, prefix, suffixes) if os.path.isfile(os.path.join(self.dir, n))]


class SSH:
    """A directory on another machine, through the local ssh client (ssh://[user@]host[:port]/path)."""

    def __init__(self, target, port, path, args):
        self.argv = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', *args]
        if port:
            self.argv += ['-p', str(port)]
        self.argv += ['--', target]
        self.dir = path.rstrip('/') or '/'

    def path(self, name):
        return shlex.quote(os.path.join(self.dir, name))

    def run(self, what, script, data=None, codes=(0,)):
        try:
            r = subprocess.run([*self.argv, 'sh -c ' + shlex.quote(script)], input=data or b'',
                               capture_output=True, timeout=SSH_TIMEOUT)
        except FileNotFoundError:
            raise StoreError('ssh is not installed') from None
        except subprocess.TimeoutExpired:
            raise StoreError(f'{what}: no answer within {SSH_TIMEOUT} seconds') from None
        if r.returncode not in codes:
            err = r.stderr.decode(errors='replace').strip().splitlines()
            why = err[-1] if err else f'exit status {r.returncode}'
            # 255: ssh itself, whose own messages start with "ssh: " already
            if r.returncode == 255 and not why.startswith('ssh: '):
                why = 'ssh: ' + why
            raise StoreError(f'{what}: {why}')
        return r

    def read(self, name):
        r = self.run(f'reading {name}', f'f={self.path(name)}; [ -f "$f" ] || exit 3; exec cat -- "$f"', codes=(0, 3))
        return r.stdout if r.returncode == 0 else None

    def write(self, name, data):
        d = shlex.quote(self.dir)
        self.run(f'writing {name}',
                 f'set -e; umask 077; mkdir -p -- {d}; t=$(mktemp {shlex.quote(os.path.join(self.dir, "." + name + "."))}XXXXXX);'
                 f' trap \'rm -f -- "$t"\' EXIT; cat > "$t"; mv -f -- "$t" {self.path(name)}', data)

    def delete(self, names):
        if names:
            self.run('deleting', 'rm -f -- ' + ' '.join(self.path(n) for n in names))

    def each(self, prefix, suffixes, command):
        """A script that runs command for each file f whose name starts with prefix and ends with a suffix."""
        d = shlex.quote(self.dir)
        globs = ' '.join(f'{shlex.quote(prefix)}*{shlex.quote(s)}' for s in suffixes or ('',))
        return (f'export LC_ALL=C; [ -d {d} ] || exit 0; cd -- {d} || exit 1;'
                f' for f in {globs}; do [ -f "$f" ] || continue; {command}; done; exit 0')

    def list(self, prefix='', suffixes=()):
        r = self.run('listing', self.each(prefix, suffixes, 'printf "%s\\n" "$f"'))
        return select(r.stdout.decode(errors='replace').splitlines(), prefix, suffixes)

    def read_all(self, prefix='', suffixes=()):
        # one connection: each file as "SIZE NAME\n" and its content
        r = self.run('reading', self.each(prefix, suffixes, 'c=$(cat -- "$f" && echo .) || continue; c=${c%.};'
                                                            ' printf "%s %s\\n%s" "${#c}" "$f" "$c"'))
        out, objects, i = r.stdout, [], 0
        try:
            while i < len(out):
                j = out.index(b'\n', i)
                size, name = out[i:j].decode().split(' ', 1)
                i = j + 1 + int(size)
                objects.append((name, out[j + 1:i]))
        except ValueError:
            raise StoreError('reading: not the output of the script') from None
        names = set(select([n for n, _ in objects], prefix, suffixes))
        return [(n, d) for n, d in objects if n in names]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never followed: the credentials stay with the storage."""

    def redirect_request(self, *args, **kwargs):
        return None


class HTTPStore:

    def __init__(self, ca_file):
        try:
            context = ssl.create_default_context(cafile=os.path.expanduser(ca_file) if ca_file else None)
        except ssl.SSLError:
            raise StoreError(f'ca_file: no certificate (PEM) in it: {ca_file}') from None
        except OSError as e:
            raise StoreError(f'ca_file: {e.strerror}: {ca_file}') from None
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))

    def request(self, what, method, url, body=None, headers=None):
        req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            with self.opener.open(req, timeout=HTTP_TIMEOUT) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.headers, e.read()
            except (OSError, http.client.HTTPException):
                return e.code, e.headers, b''
            finally:
                e.close()
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                reason = reason.verify_message or reason
            raise StoreError(f'{what}: {reason}') from None
        except (OSError, http.client.HTTPException) as e:
            raise StoreError(f'{what}: {e}') from None

    def read_all(self, prefix='', suffixes=()):
        names = self.list(prefix, suffixes)
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            return [(n, d) for n, d in zip(names, pool.map(self.read, names)) if d is not None]

    @staticmethod
    def message(status, body):
        body = ' '.join(body.split())[:200]
        return f'{body} (HTTP {status})' if body else f'HTTP {status}'


class S3(HTTPStore):
    """A bucket of S3 or of an S3-compatible store; requests are signed with AWS Signature Version 4."""

    PAGE = 1000

    def __init__(self, endpoint, bucket, prefix, region, access_key, secret_key, session_token, ca_file):
        super().__init__(ca_file)
        u = urllib.parse.urlsplit(endpoint) if endpoint else None
        if u is None:
            # AWS: virtual-hosted, unless a dot in the name breaks the certificate
            if '.' in bucket:
                self.base, self.root = f'https://s3.{region}.amazonaws.com', f'/{bucket}/'
            else:
                self.base, self.root = f'https://{bucket}.s3.{region}.amazonaws.com', '/'
        else:
            if u.scheme not in ('http', 'https') or not u.hostname or u.query or u.username:
                raise StoreError(f'endpoint {endpoint!r}: not an http(s) address of a host')
            self.base = f'{u.scheme}://{u.netloc}'
            self.root = u.path.rstrip('/') + f'/{bucket}/'
        self.host = urllib.parse.urlsplit(self.base).netloc
        self.prefix = prefix + '/' if prefix else ''
        self.region = region
        self.access_key, self.secret_key, self.session_token = access_key, secret_key, session_token

    def signed(self, method, path, query, payload):
        payload_hash = hashlib.sha256(payload).hexdigest()
        amz_date = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        headers = {'host': self.host, 'x-amz-content-sha256': payload_hash, 'x-amz-date': amz_date}
        if self.session_token:
            headers['x-amz-security-token'] = self.session_token
        headers['Authorization'] = sigv4(method, path, query, headers, payload_hash, self.access_key,
                                         self.secret_key, self.region, amz_date)
        return headers

    def call(self, what, method, key='', query=None, body=b''):
        path = urllib.parse.quote(self.root + key, safe='/')
        q = '&'.join(f'{urllib.parse.quote(k, safe="")}={urllib.parse.quote(v, safe="")}'
                     for k, v in sorted((query or {}).items()))
        headers = self.signed(method, path, q, body)
        if method == 'PUT':
            headers['Content-Type'] = 'application/yaml' if key.endswith(('.yml', '.yaml')) else 'application/json'
        return self.request(what, method, self.base + path + ('?' + q if q else ''), body if method == 'PUT' else None, headers)

    @classmethod
    def error(cls, status, body):
        try:
            root = ET.fromstring(body)
            code, message = root.findtext('Code'), root.findtext('Message')
        except ET.ParseError:
            code = message = None
        if code:
            return f'{code}: {message} (HTTP {status})' if message else f'{code} (HTTP {status})'
        return f'HTTP {status}'

    def read(self, name):
        what = f'reading {name}'
        status, _, body = self.call(what, 'GET', self.prefix + name)
        if status == 200:
            return body
        if status == 404:
            return None
        raise StoreError(f'{what}: {self.error(status, body)}')

    def write(self, name, data):
        what = f'writing {name}'
        status, _, body = self.call(what, 'PUT', self.prefix + name, body=data)
        if status != 200:
            raise StoreError(f'{what}: {self.error(status, body)}')

    def delete(self, names):
        for name in names:
            what = f'deleting {name}'
            status, _, body = self.call(what, 'DELETE', self.prefix + name)
            if status not in (200, 204, 404):
                raise StoreError(f'{what}: {self.error(status, body)}')

    def list(self, prefix='', suffixes=()):
        names, token = [], None
        while True:
            query = {'list-type': '2', 'prefix': self.prefix + prefix, 'delimiter': '/', 'max-keys': str(self.PAGE)}
            if token:
                query['continuation-token'] = token
            status, _, body = self.call('listing', 'GET', query=query)
            if status != 200:
                raise StoreError(f'listing: {self.error(status, body)}')
            try:
                root = ET.fromstring(body)
            except ET.ParseError:
                raise StoreError('listing: not an S3 answer') from None
            ns = root.tag[:root.tag.index('}') + 1] if root.tag.startswith('{') else ''
            names += [c.findtext(f'{ns}Key', '')[len(self.prefix):] for c in root.iterfind(f'{ns}Contents')]
            token = root.findtext(f'{ns}NextContinuationToken')
            if root.findtext(f'{ns}IsTruncated') != 'true' or not token:
                return select(names, prefix, suffixes)


def sigv4(method, path, query, headers, payload_hash, access_key, secret_key, region, amz_date):
    """The Authorization header of AWS Signature Version 4 for S3. path and query are sent as given:
    encoded the SigV4 way, the query sorted."""
    names = sorted(k.lower() for k in headers)
    canonical_headers = ''.join(f'{k}:{" ".join(str(headers[k]).split())}\n' for k in names)
    signed = ';'.join(names)
    canonical = '\n'.join([method, path, query, canonical_headers, signed, payload_hash])
    scope = f'{amz_date[:8]}/{region}/s3/aws4_request'
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ('AWS4' + secret_key).encode()
    for part in (amz_date[:8], region, 's3', 'aws4_request'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return f'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}'


class Consul(HTTPStore):
    """A prefix in Consul's KV store."""

    def __init__(self, address, prefix, token, ca_file):
        super().__init__(ca_file)
        self.address, self.prefix = address, prefix + '/'
        self.headers = {'X-Consul-Token': token} if token else {}

    def call(self, what, method, key, query='', body=None):
        url = f'{self.address}/v1/kv/{urllib.parse.quote(self.prefix + key, safe="/")}' + (f'?{query}' if query else '')
        status, _, out = self.request(what, method, url, body, self.headers)
        if status not in (200, 404):
            raise StoreError(f'{what}: {self.message(status, out.decode(errors="replace"))}')
        return status, out

    def read(self, name):
        status, out = self.call(f'reading {name}', 'GET', name, 'raw')
        return out if status == 200 else None

    def write(self, name, data):
        status, out = self.call(f'writing {name}', 'PUT', name, body=data)
        if status != 200 or out.strip() != b'true':
            raise StoreError(f'writing {name}: {self.message(status, out.decode(errors="replace"))}')

    def delete(self, names):
        for name in names:
            self.call(f'deleting {name}', 'DELETE', name)

    def names(self, keys, prefix, suffixes):
        return select([k[len(self.prefix):] for k in keys if k.startswith(self.prefix)], prefix, suffixes)

    def list(self, prefix='', suffixes=()):
        status, out = self.call('listing', 'GET', prefix, 'keys&separator=/')
        if status == 404:
            return []
        try:
            return self.names(json.loads(out), prefix, suffixes)
        except (ValueError, TypeError, AttributeError):
            raise StoreError('listing: not a Consul answer') from None

    def read_all(self, prefix='', suffixes=()):
        # one request: every key with its value
        status, out = self.call('reading', 'GET', prefix, 'recurse')
        if status == 404:
            return []
        try:
            values = {e['Key']: e['Value'] for e in json.loads(out)}
            return [(n, base64.b64decode(values[self.prefix + n] or ''))
                    for n in self.names(list(values), prefix, suffixes)]
        except (ValueError, TypeError, KeyError, AttributeError):
            raise StoreError('reading: not a Consul answer') from None


class Vault(HTTPStore):
    """A prefix in a KV version 2 engine of Vault; each object is a secret with the field json."""

    def __init__(self, address, mount, prefix, token, namespace, ca_file):
        super().__init__(ca_file)
        self.address, self.mount, self.prefix = address, mount, prefix + '/'
        self.headers = {'X-Vault-Token': token}
        if namespace:
            self.headers['X-Vault-Namespace'] = namespace

    def call(self, what, method, kind, name, query='', doc=None):
        url = f'{self.address}/v1/{urllib.parse.quote(f"{self.mount}/{kind}/{self.prefix}{name}", safe="/")}'
        headers = dict(self.headers)
        body = None
        if doc is not None:
            body = json.dumps(doc).encode()
            headers['Content-Type'] = 'application/json'
        status, _, out = self.request(what, method, url + (f'?{query}' if query else ''), body, headers)
        if status not in (200, 204, 404):
            try:
                why = '; '.join(json.loads(out)['errors'])
            except (ValueError, KeyError, TypeError):
                why = ''
            raise StoreError(f'{what}: {self.message(status, why)}')
        return status, out

    def read(self, name):
        status, out = self.call(f'reading {name}', 'GET', 'data', name)
        if status == 404:
            return None
        try:
            data = json.loads(out)['data']['data']
        except (ValueError, KeyError, TypeError):
            raise StoreError(f'reading {name}: not a Vault answer') from None
        if isinstance(data, dict) and isinstance(data.get('json'), str):
            return data['json'].encode()
        # a secret without the field json: its fields, an object like any other that is none of ours
        return json.dumps(data).encode()

    def write(self, name, data):
        status, _ = self.call(f'writing {name}', 'POST', 'data', name, doc={'data': {'json': data.decode()}})
        if status == 404:
            raise StoreError(f'writing {name}: HTTP 404 (is {self.mount} a KV version 2 engine?)')

    def delete(self, names):
        for name in names:
            self.call(f'deleting {name}', 'DELETE', 'metadata', name)

    def list(self, prefix='', suffixes=()):
        status, out = self.call('listing', 'GET', 'metadata', '', 'list=true')
        if status == 404:
            return []
        try:
            keys = json.loads(out)['data']['keys']
            return select(keys, prefix, suffixes)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise StoreError('listing: not a Vault answer') from None


# --- the URL ----------------------------------------------------------------------

def label_of(uri):
    """The URL without what may be secret: a password, a user (but ssh's), the query string, the fragment."""
    try:
        u = urllib.parse.urlsplit(uri)
        netloc = u.hostname or ''
        if u.port:
            netloc += f':{u.port}'
        if u.username and u.scheme == 'ssh':
            netloc = f'{u.username}@{netloc}'
        return urllib.parse.urlunsplit((u.scheme, netloc, u.path, '', ''))
    except ValueError:
        return uri.split('?', 1)[0].split('#', 1)[0]


def missing(*names):
    """Where the credentials of names are set."""
    files = ' and '.join(f'{n}_file' for n in names)
    values = ' and '.join(names)
    env = ' and '.join(f'{ENV}{n.upper()}_FILE' for n in names)
    return f'{files} (or {values}) in [{SECTION}] of ansible.cfg, or {env}'


def open_store(uri, option, origin=None):
    """The storage a URL names. option(name) is an option of the doc fragment ofzhur.ansible.storage;
    a file (NAME_file) wins over its value (NAME). A plain path set in a file (origin) is relative to it."""
    def value(name):
        f = option(name + '_file')
        if f:
            return read_file(f, name + '_file')
        return option(name)

    if '://' not in uri:
        path = os.path.expanduser(uri)
        if not os.path.isabs(path) and origin and os.path.isfile(origin):
            path = os.path.join(os.path.dirname(origin), path)
        return Directory(os.path.abspath(path))

    try:
        u = urllib.parse.urlsplit(uri)
        port = u.port
    except ValueError as e:
        raise StoreError(f'not a URL: {e}') from None
    if u.query or u.fragment:
        raise StoreError(f'a query string in the URL is not read; credentials go into [{SECTION}] of ansible.cfg')
    if u.password is not None:
        raise StoreError('a password in the URL is not read')
    if u.username is not None and u.scheme != 'ssh':
        raise StoreError(f'a user in the URL is not read ({u.scheme}://)')
    if port and u.scheme in ('s3', 'r2'):
        raise StoreError(f'a port in the URL is not read ({u.scheme}://)')
    path = u.path.strip('/')
    ca_file = option('ca_file')

    if u.scheme == 'file':
        p = u.path if u.netloc in ('', 'localhost') else '/' + u.netloc + u.path
        if not p.strip('/'):
            raise StoreError('file:///path')
        return Directory(p)

    if u.scheme == 'ssh':
        if not u.hostname or not path or u.hostname.startswith('-'):
            raise StoreError('ssh://[user@]host[:port]/path')
        target = f'{u.username}@{u.hostname}' if u.username else u.hostname
        try:
            args = shlex.split(option('ssh_args') or '')
        except ValueError as e:
            raise StoreError(f'ssh_args: {e}') from None
        return SSH(target, port, '/' + path, args)

    if u.scheme in ('s3', 'r2'):
        if u.scheme == 's3':
            if not u.hostname:
                raise StoreError('s3://bucket/prefix')
            bucket, prefix = u.netloc, path
            endpoint, region = option('endpoint'), option('region') or 'us-east-1'
        else:
            bucket, _, prefix = path.partition('/')
            if not u.hostname or not bucket:
                raise StoreError('r2://account/bucket/prefix, where account is the Cloudflare account ID')
            endpoint, region = f'https://{u.netloc}.r2.cloudflarestorage.com', 'auto'
        access_key, secret_key = value('access_key'), value('secret_key')
        if not access_key or not secret_key:
            raise StoreError(f'the access key and the secret key are missing: {missing("access_key", "secret_key")}')
        return S3(endpoint, bucket, prefix.strip('/'), region, access_key, secret_key, value('session_token'), ca_file)

    if u.scheme in ('consul', 'http+consul'):
        if not u.hostname or not path:
            raise StoreError('consul://host:8500/prefix')
        scheme = 'http' if u.scheme == 'http+consul' else 'https'
        return Consul(f'{scheme}://{u.netloc}', path, value('consul_token'), ca_file)

    if u.scheme in ('vault', 'http+vault'):
        mount, _, prefix = path.partition('/')
        if not u.hostname or not prefix:
            raise StoreError('vault://host:8200/mount/prefix')
        token = value('vault_token')
        if not token:
            raise StoreError(f'the token is missing: {missing("vault_token")}')
        scheme = 'http' if u.scheme == 'http+vault' else 'https'
        return Vault(f'{scheme}://{u.netloc}', mount, prefix, token, option('vault_namespace'), ca_file)

    raise StoreError(f'unknown scheme {u.scheme} ({SCHEMES})')
