# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

from __future__ import annotations


class ModuleDocFragment:

    # The options of a central storage (module_utils/storage.py): the section [ofzhur_storage] of
    # ansible.cfg and ANSIBLE_OFZHUR_STORAGE_*, never the variables of the storages' own clients.
    DOCUMENTATION = r"""
options:
  endpoint:
    description:
      - The address of an S3-compatible store for V(s3://), such as V(https://minio.example.com:9000).
      - Without it, AWS S3 in O(region).
    type: str
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_ENDPOINT
    ini:
      - key: endpoint
        section: ofzhur_storage
  region:
    description: The region for V(s3://); V(r2://) is always V(auto).
    type: str
    default: us-east-1
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_REGION
    ini:
      - key: region
        section: ofzhur_storage
  access_key:
    description: The access key ID for V(s3://) and V(r2://); O(access_key_file) wins over it.
    type: str
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_ACCESS_KEY
    ini:
      - key: access_key
        section: ofzhur_storage
  access_key_file:
    description: A file that holds O(access_key).
    type: path
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_ACCESS_KEY_FILE
    ini:
      - key: access_key_file
        section: ofzhur_storage
  secret_key:
    description: The secret access key for V(s3://) and V(r2://); O(secret_key_file) wins over it.
    type: str
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_SECRET_KEY
    ini:
      - key: secret_key
        section: ofzhur_storage
  secret_key_file:
    description: A file that holds O(secret_key).
    type: path
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_SECRET_KEY_FILE
    ini:
      - key: secret_key_file
        section: ofzhur_storage
  session_token:
    description: The session token of temporary AWS credentials; O(session_token_file) wins over it.
    type: str
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_SESSION_TOKEN
    ini:
      - key: session_token
        section: ofzhur_storage
  session_token_file:
    description: A file that holds O(session_token).
    type: path
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_SESSION_TOKEN_FILE
    ini:
      - key: session_token_file
        section: ofzhur_storage
  consul_token:
    description: The ACL token for V(consul://); O(consul_token_file) wins over it.
    type: str
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_CONSUL_TOKEN
    ini:
      - key: consul_token
        section: ofzhur_storage
  consul_token_file:
    description: A file that holds O(consul_token).
    type: path
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_CONSUL_TOKEN_FILE
    ini:
      - key: consul_token_file
        section: ofzhur_storage
  vault_token:
    description: The token for V(vault://), required; O(vault_token_file) wins over it.
    type: str
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN
    ini:
      - key: vault_token
        section: ofzhur_storage
  vault_token_file:
    description: A file that holds O(vault_token).
    type: path
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN_FILE
    ini:
      - key: vault_token_file
        section: ofzhur_storage
  vault_namespace:
    description: The Vault namespace (Vault Enterprise, HCP Vault).
    type: str
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_VAULT_NAMESPACE
    ini:
      - key: vault_namespace
        section: ofzhur_storage
  ca_file:
    description: CA certificates (PEM) to verify the storage's TLS certificate with, instead of the system's.
    type: path
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_CA_FILE
    ini:
      - key: ca_file
        section: ofzhur_storage
  ssh_args:
    description: Options of the ssh client for V(ssh://), such as V(-i ~/.ssh/fleet -o ControlMaster=auto).
    type: str
    default: ''
    env:
      - name: ANSIBLE_OFZHUR_STORAGE_SSH_ARGS
    ini:
      - key: ssh_args
        section: ofzhur_storage
notes:
  - The options of the storage are read from the section C([ofzhur_storage]) of C(ansible.cfg) and from
    C(ANSIBLE_OFZHUR_STORAGE_*), never from the variables of the storages' own clients (C(AWS_*),
    C(CONSUL_HTTP_TOKEN), C(VAULT_TOKEN)). A relative path in C(ansible.cfg) is relative to it.
  - Credentials never go into the URL. A query string, a password or a user (but ssh's) in it is refused.
"""
