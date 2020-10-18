import base64
import os
from typing import Dict, Optional, Tuple

import __main__
import keyring
import requests
from ansible.executor import task_executor
from ansible.executor.process import worker
from ansible.executor.task_executor import TaskExecutor as _TaskExecutor
from ansible.plugins.vars import BaseVarsPlugin
from ansible.utils.display import Display
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from requests import HTTPError

Credential = Dict[str, str]

display = Display()


class PKCS7Encoder(object):
    def __init__(self, k=16):
        assert (k <= 256)
        assert (k > 1)
        self.__klen = k

    ## @param text The padded text for which the padding is to be removed.
    # @exception ValueError Raised when the input padding is missing or corrupt.
    def decode(self, text):
        dectext = ''
        if (len(text) % self.__klen) != 0:
            raise Exception('text not %d align' % self.__klen)
        lastch = ord(text[-1])
        if lastch <= self.__klen and lastch != 0:
            trimlen = lastch
            textlen = len(text)
            for i in range(lastch):
                if ord(text[textlen - i - 1]) != lastch:
                    trimlen = 0
                    break
            if trimlen == 0:
                dectext = text
            else:
                dectext = text[:(textlen - trimlen)]
        else:
            dectext = text
        return dectext

    def get_bytes(self, text):
        outbytes = []
        for c in text:
            outbytes.append(ord(c))
        return outbytes

    def get_text(self, inbytes):
        s = ''
        for i in inbytes:
            s += chr((i % 256))
        return s

    def __encode_inner(self, text):
        '''
        Pad an input string according to PKCS#7
        if the real text is bits same ,just expand the text
        '''
        enctext = text
        leftlen = self.__klen - (len(text) % self.__klen)
        lastch = chr(leftlen)
        enctext += lastch * leftlen

        return enctext

    ## @param text The text to encode.
    def encode(self, text):
        return self.__encode_inner(text)


class Encrypter:
    """Encrypting and decrypting strings using AES"""

    def __init__(self, key):
        self.key = key
        self.pkcs7_encoder = PKCS7Encoder(16)

    def get_verifier(self, iv=None):
        """getting the verifier"""
        if iv is None:
            iv = get_random_bytes(16)
        aes = AES.new(self.key, AES.MODE_CBC, iv)

        base64_private_key = base64.b64encode(self.key).decode()
        base64_iv = base64.b64encode(iv).decode()
        padded_iv = self.pkcs7_encoder.encode(base64_iv)
        verifier = base64.b64encode(aes.encrypt(padded_iv.encode())).decode()
        return base64_private_key, base64_iv, verifier

    def encrypt(self, plain, iv: Optional[bytes] = None):
        """encryption"""
        if iv is not None:
            print()
        if iv is None:
            iv = get_random_bytes(16)
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        padded_plain = self.pkcs7_encoder.encode(plain)

        return base64.b64encode(aes.encrypt(padded_plain.encode())).decode()

    def decrypt(self, encrypted, iv=None):
        """decryption"""
        if iv is None:
            iv = get_random_bytes(16)
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = aes.decrypt(base64.b64decode(encrypted))

        return self.pkcs7_encoder.decode(decrypted.decode())

    @classmethod
    def generate_key(cls):
        """key generation"""
        return get_random_bytes(32)


class HttpClient:
    URL = 'http://localhost:19455'

    @classmethod
    def associate(cls, key, nonce, verifier):
        """Associate a client with KeepassHttp."""
        payload = {
            'RequestType': 'associate',
            'Key': key,
            'Nonce': nonce,
            'Verifier': verifier
        }
        r = requests.post(cls.URL, json=payload)
        data = r.json()

        error = data.get('Error')
        if error:
            raise HTTPError(error)
        r.raise_for_status()

        return data['Id']

    @classmethod
    def test_associate(cls, nonce, verifier, connection_id):
        """Test if client is Associated with KeepassHttp."""
        payload = {
            'Nonce': nonce,
            'Verifier': verifier,
            'RequestType': 'test-associate',
            'TriggerUnlock': 'false',
            'Id': connection_id
        }
        r = requests.post(cls.URL, json=payload)
        data = r.json()

        error = data.get('Error')
        if error:
            raise HTTPError(error)
        r.raise_for_status()

        return data['Success']

    @classmethod
    def get_logins(cls, connection_id, nonce, verifier, url):
        """getting logins through url"""
        payload = {
            'RequestType': 'get-logins',
            'SortSelection': 'true',
            'TriggerUnlock': 'false',
            'Id': connection_id,
            'Nonce': nonce,
            'Verifier': verifier,
            'Url': url,
            'SubmitUrl': url
        }
        r = requests.post(cls.URL, json=payload)
        data = r.json()

        error = data.get('Error')
        if error:
            raise HTTPError(error)
        r.raise_for_status()

        return data['Entries'], data['Nonce']


class Keepasshttplib:
    """Encrypting and decrypting strings using AES"""

    def __init__(self, keyring_id: Optional[str] = None):
        self.keyring_service_name = "keepasshttplib"
        if keyring_id:
            self.keyring_service_name += "-{}".format(keyring_id)

    def get_credentials(self, url: str) -> Optional[Credential]:
        key = self.get_key_from_keyring()
        if key is None:
            key = Encrypter.generate_key()
        connection_id = self.get_id_from_keyring()
        is_associated = False
        if connection_id is not None:
            is_associated = self.test_associate(key, connection_id)

        if not is_associated:
            print('running test associate')
            connection_id = self.associate(key)
            keyring.set_password(self.keyring_service_name, "connection_id", connection_id)
            keyring.set_password(self.keyring_service_name, "private_key", base64.b64encode(key).decode())
            is_associated = True

        if is_associated:
            return self.get_credentials_from_client(key, url, connection_id)
        else:
            return None

    def get_key_from_keyring(self):
        """getting key from Keyring"""
        private_key = keyring.get_password(self.keyring_service_name, "private_key")

        if private_key is not None:
            return base64.b64decode(private_key)
        else:
            return None

    def get_id_from_keyring(self):
        """getting identification from keyring"""
        return keyring.get_password(self.keyring_service_name, "connection_id")

    def test_associate(self, key, connection_id):
        """testing if associated"""
        enc = Encrypter(key)
        base64_private_key, nonce, verifier = enc.get_verifier()

        return HttpClient.test_associate(nonce, verifier, connection_id)

    def associate(self, key):
        """if associate"""
        enc = Encrypter(key)
        base64_private_key, nonce, verifier = enc.get_verifier()

        return HttpClient.associate(base64_private_key, nonce, verifier)

    def get_credentials_from_client(self, key, url, connection_id) -> Credential:
        """getting credentials from client"""
        enc = Encrypter(key)
        base64_private_key, nonce, verifier = enc.get_verifier()
        encrypted_url = enc.encrypt(url, base64.b64decode(nonce))
        encrypted_credentials, nonce = HttpClient.get_logins(connection_id, nonce, verifier, encrypted_url)
        iv = base64.b64decode(nonce)

        return {
            enc.decrypt(encrypted_credential['Login'], iv): enc.decrypt(encrypted_credential['Password'], iv)
            for encrypted_credential in encrypted_credentials
        }


class AnsibleKeepassError(Exception):
    body = 'Error in the Ansible Keepass plugin.'

    def __init__(self, msg=''):
        body = self.body
        if msg:
            body += ' {}'.format(msg)
        super().__init__(body)


class KeepassConnectionError(AnsibleKeepassError):
    body = 'Error on connection.'


class KeepassHTTPError(AnsibleKeepassError):
    body = ('The password for root could not be obtained using Keepass '
            'HTTP.')


class KeepassXCError(AnsibleKeepassError):
    body = ('The password for root could not be obtained using '
            'KeepassXC Browser.')


class KeepassBase:
    def __init__(self):
        self.cached_credentials = {}

    def get_cached_credential(self, host) -> Tuple[str, str]:
        return self._get_cached_credential(host.name)

    def _get_cached_credential(self, host_name: str) -> Tuple[str, str]:
        credential = self.cached_credentials.get(host_name, None)
        if credential is None:
            credential = self.get_credential(host_name)
            self.cached_credentials[host_name] = credential
        return credential

    def get_credential(self, host: str) -> Tuple[str, str]:
        raise NotImplementedError


class KeepassHTTP(KeepassBase):
    def __init__(self):
        super(KeepassHTTP, self).__init__()
        self.k = Keepasshttplib()

    def get_credential(self, host_name: str) -> Tuple[str, str]:
        try:
            auth = self.k.get_credentials('ansible://{}'.format(host_name))
        except Exception as e:
            raise KeepassHTTPError(
                'Error obtaining host name {}: {}'.format(host_name, e)
            )
        if auth:
            return auth[0], auth[1]


def get_host_names(host):
    return [host.name] + [group.name for group in host.groups]


def get_keepass_class():
    keepass_class = os.environ.get('KEEPASS_CLASS')
    return {
        'KeepassHTTP': KeepassHTTP,
    }.get(keepass_class, KeepassHTTP)


def get_or_create_conn(cls):
    if not getattr(__main__, '_keepass', None):
        __main__._keepass = cls()
    return __main__._keepass


class TaskExecutor(_TaskExecutor):
    def __init__(self, host, task, job_vars, play_context, *args,
                 **kwargs):
        become = task.become or play_context.become
        if become and not job_vars.get('ansible_become_pass'):
            password = None
            cls = get_keepass_class()
            try:
                kp = get_or_create_conn(cls)
                password = kp.get_cached_credential(host)
            except AnsibleKeepassError as e:
                display.error(e)
            if password is None:
                display.warning(
                    'The password could not be obtained using '
                    '{}. Hosts tried: '.format(cls.__name__) +
                    '{}. '.format(', '.join(get_host_names(host))) +
                    'Maybe the password is not in the database or does '
                    'not have the url.'
                )
            elif password not in [None, None]:
                job_vars['ansible_become_pass'] = password
        super(TaskExecutor, self).__init__(host, task, job_vars,
                                           play_context, *args, **kwargs)


setattr(task_executor, 'TaskExecutor', TaskExecutor)
setattr(worker, 'TaskExecutor', TaskExecutor)


class VarsModule(BaseVarsPlugin):
    """
    Loads variables for groups and/or hosts
    """

    def get_vars(self, loader, path, entities):
        super(VarsModule, self).get_vars(loader, path, entities)
        return {}

    def get_host_vars(self, *args, **kwargs):
        return {}

    def get_group_vars(self, *args, **kwargs):
        return {}
