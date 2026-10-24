# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

from __future__ import annotations

DOCUMENTATION = r"""
name: facts
short_description: Facts in a central storage (S3, R2, Consul, Vault, a directory over SSH)
version_added: 0.3.0
author: Oleg Zhurko (@ofzhur)
description:
  - Keeps the fact cache in a storage that every machine running Ansible on the servers shares,
    control machines that push and servers that pull; a run sees the facts the others gathered.
  - One JSON object per host under the prefix of the URL O(_uri), named O(_prefix) and the host name
    (characters other than letters, digits, C(-), C(.) and C(_) as C(~XX)). It holds the facts and
    the time they were written, which O(_timeout) is measured against.
  - A run reads the facts of every host once, at its first use of the cache, and writes those it
    gathers. Facts read are data, never templates, also where ansible-core 2.19 and later would
    keep a string of them trusted as a template.
  - The URLs are those of ump's state backends; the options of the storage are those of
    C([ofzhur_storage]) in C(ansible.cfg), shared with the host files in a storage (C(ofzhur.ansible.host)).
  - A storage that cannot be reached or refuses a request fails the run, as does an invalid
    configuration. Ansible would otherwise go on with a cache in memory, and the facts of the other
    servers would be missing. An object that is not one of the plugin's is a warning; the next facts
    of its host replace it, but for one of the other scheme (see below), which is not read and is
    removed by hand.
  - Python standard library only; nothing to install besides ansible-core.
notes:
  - Facts are input to every run, and can be sensitive. Whoever writes the storage changes what runs
    do; whoever reads it reads them. Give them a bucket or prefix of their own, and the credentials of
    the machines that share them alone.
  - ansible-core 2.19 and later name the objects C(s1_HOST), earlier versions C(HOST); machines
    share facts with the machines of the same scheme only.
options:
  _uri:
    description:
      - The storage, required.
      - V(s3://BUCKET/PREFIX) is a bucket of AWS S3, or of any S3-compatible store when O(endpoint) is
        set (path-style).
      - V(r2://ACCOUNT/BUCKET/PREFIX) is a bucket of Cloudflare R2; ACCOUNT is the account ID.
      - V(consul://HOST:8500/PREFIX) is Consul's KV store over https, V(http+consul://) over http.
      - V(vault://HOST:8200/MOUNT/PREFIX) is a KV version 2 engine of Vault over https, V(http+vault://)
        over http.
      - V(ssh://[USER@]HOST[:PORT]/PATH) is a directory on another machine, reached with the ssh
        client of this one (its keys, agent and C(~/.ssh/config)); it needs C(sh), C(mktemp) and
        C(mv) there.
      - V(file:///PATH), or a plain path, is a directory on this machine.
    type: str
    env:
      - name: ANSIBLE_CACHE_PLUGIN_CONNECTION
    ini:
      - key: fact_caching_connection
        section: defaults
  _prefix:
    description: A prefix of the object names, after the prefix of the URL. No C(/).
    type: str
    default: ''
    env:
      - name: ANSIBLE_CACHE_PLUGIN_PREFIX
    ini:
      - key: fact_caching_prefix
        section: defaults
  _timeout:
    description: Seconds after which facts are expired; V(0) keeps them for ever.
    type: integer
    default: 86400
    env:
      - name: ANSIBLE_CACHE_PLUGIN_TIMEOUT
    ini:
      - key: fact_caching_timeout
        section: defaults
extends_documentation_fragment:
  - ofzhur.ansible.storage
"""

EXAMPLES = r"""
# ansible.cfg
[defaults]
fact_caching = ofzhur.ansible.facts
fact_caching_connection = r2://0123456789abcdef0123456789abcdef/fleet-facts/facts
fact_caching_timeout = 604800

[ofzhur_storage]
access_key_file = secrets/storage.access_key
secret_key_file = secrets/storage.secret_key
"""

import json
import re
import time
import urllib.parse

from ansible.errors import AnsibleError
from ansible.plugins.cache import BaseCacheModule
from ansible.utils.display import Display

from ansible_collections.ofzhur.ansible.plugins.module_utils.storage import StoreError, label_of, open_store

if hasattr(BaseCacheModule, '_persistent'):
    # ansible-core >= 2.19 hands every cache plugin {"__payload__": JSON TEXT}, in which it keeps
    # vault values and the tags of data itself, the trust of a template among them.
    PAYLOAD = '__payload__'
    try:
        # the prefix of the keys this ansible-core writes: s1_ in 2.19 and 2.20
        from ansible._internal._plugins._cache import PluginInterposer
        WRITTEN = PluginInterposer._get_wrapped_key_prefix()
    except (ImportError, AttributeError):
        WRITTEN = 's1_'

    def encode(doc):
        return json.dumps(doc).encode()

    def decode(data):
        return json.loads(data)
else:
    from ansible.parsing.ajson import AnsibleJSONDecoder, AnsibleJSONEncoder

    PAYLOAD = WRITTEN = None

    def encode(doc):
        return json.dumps(doc, cls=AnsibleJSONEncoder, preprocess_unsafe=True).encode()

    def decode(data):
        return json.loads(data, cls=AnsibleJSONDecoder)

display = Display()

NAME = 'ofzhur.ansible.facts'
# the key of a host for ansible-core >= 2.19: s, the schema, _, the host
SCHEMA = re.compile(r's\d+_')
# the tag of ansible-core >= 2.19 that makes a string a template
TRUSTED = 'TrustedAsTemplate'


def object_name(prefix, key):
    """The object of a host: its name but for the characters other than letters, digits, "-", "." and "_",
    which are ~XX (UTF-8). Every storage takes such a name as it is."""
    return prefix + urllib.parse.quote(str(key), safe='').replace('~', '%7E').replace('%', '~')


def key_of(name):
    return urllib.parse.unquote(name.replace('~', '%'))


def host_of(key):
    """The host of a key, without the schema of ansible-core >= 2.19."""
    return SCHEMA.sub('', key, count=1) if PAYLOAD else key


def written(key):
    """Whether key is of the scheme this ansible-core writes: s1_HOST from 2.19, HOST before."""
    return key.startswith(WRITTEN) if PAYLOAD else not SCHEMA.match(key)


def is_trust(value):
    return isinstance(value, dict) and value.get('__ansible_type') == TRUSTED


def untrusted(value):
    """The JSON of ansible-core's cache without the tag TrustedAsTemplate, wherever it is."""
    if isinstance(value, dict):
        return {k: untrusted(v) for k, v in value.items() if not is_trust(v)}
    if isinstance(value, list):
        return [untrusted(v) for v in value if not is_trust(v)]
    return value


def facts_of(key, value):
    """The facts of a cache object as Ansible takes them; ValueError when they are none."""
    if PAYLOAD and SCHEMA.match(key):
        if not isinstance(value, dict) or set(value) != {PAYLOAD} or not isinstance(value[PAYLOAD], str):
            raise ValueError(f'no {PAYLOAD}')
        facts = json.loads(value[PAYLOAD])
        if not isinstance(facts, dict) or is_trust(facts):
            raise ValueError('no facts')
        # a template among the facts would run on the control machine: whoever writes the storage
        # would run commands there
        return {PAYLOAD: json.dumps(untrusted(facts))}
    # ansible-core < 2.19 takes the facts as data; another schema is never asked for
    if not PAYLOAD and not isinstance(value, dict):
        raise ValueError('no facts')
    return value


class CacheModule(BaseCacheModule):
    """Facts in a central storage, one JSON object per host: {"time": UNIX TIME, "value": FACTS}."""

    def __init__(self, *args, **kwargs):
        self._cache = {}  # the unexpired facts of the storage, and the facts written since
        self._loaded = False
        self._store = None
        self._error = None
        self._label = NAME
        self._prefix = ''
        self._timeout = 0.0
        try:
            super().__init__(*args, **kwargs)
            uri, origin = self.get_option_and_origin('_uri')
            uri = (uri or '').strip()
            if not uri:
                raise AnsibleError(f'{NAME}: no storage: set fact_caching_connection (ANSIBLE_CACHE_PLUGIN_CONNECTION) to its URL')
            self._label = f'{NAME}: {label_of(uri)}'
            self._prefix = self.get_option('_prefix') or ''
            if '/' in self._prefix:
                raise StoreError(f'fact_caching_prefix {self._prefix!r}: no "/"; a directory goes into the URL')
            self._timeout = float(self.get_option('_timeout'))
            self._store = open_store(uri, self.get_option, origin)
        except StoreError as e:
            self._error = f'{self._label}: {e}'
        except Exception as e:
            # Ansible would take this for a broken plugin and go on with a cache in memory:
            # the error comes at the first use instead, and fails the run.
            self._error = f'{e}' if isinstance(e, AnsibleError) else f'{self._label}: {e}'

    def _do(self, method, *args):
        if self._error:
            raise AnsibleError(self._error)
        try:
            return getattr(self._store, method)(*args)
        except StoreError as e:
            raise AnsibleError(f'{self._label}: {e}') from None

    def _load(self):
        """Reads the facts of every host at the first use. The processes Ansible forks for tasks inherit
        them; each would read the facts of the hosts it templates again."""
        if self._loaded:
            return
        now = time.time()
        for name, data in self._do('read_all', self._prefix):
            key = key_of(name[len(self._prefix):])
            if key in self._cache:
                continue
            try:
                doc = decode(data)
                if not isinstance(doc, dict) or not isinstance(doc.get('time'), (int, float)) or 'value' not in doc:
                    raise ValueError('no time or value')
                value = facts_of(key, doc['value'])
            except (ValueError, TypeError) as e:
                if written(key):
                    display.warning(f'{self._label}: {name} is not a cache object ({e}); '
                                    f'the next facts of {host_of(key)} replace it')
                else:
                    display.warning(f'{self._label}: {name} is not a cache object ({e}) and is not read; remove it')
                continue
            if not self._timeout or now - doc['time'] <= self._timeout:
                self._cache[key] = value
        self._loaded = True
        display.vvvv(f'{self._label}: the facts of {len(self._cache)} hosts')

    def get(self, key):
        self._load()
        if key not in self._cache:
            raise KeyError(key)
        return self._cache[key]

    def set(self, key, value):
        try:
            data = encode({'time': time.time(), 'value': value})
        except (TypeError, ValueError) as e:
            raise AnsibleError(f'{self._label}: the facts of {host_of(key)} are not JSON: {e}') from None
        self._do('write', object_name(self._prefix, key), data)
        self._cache[key] = value

    def keys(self):
        self._load()
        return list(self._cache)

    def contains(self, key):
        self._load()
        return key in self._cache

    def delete(self, key):
        self._do('delete', [object_name(self._prefix, key)])
        self._cache.pop(key, None)

    def flush(self):
        self._do('delete', self._do('list', self._prefix))
        self._cache = {}
        self._loaded = True

    def copy(self):
        self._load()
        return dict(self._cache)
