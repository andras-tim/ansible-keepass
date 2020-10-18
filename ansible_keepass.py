import os

import __main__
import requests
from ansible.executor import task_executor
from ansible.executor.process import worker
from ansible.executor.task_executor import TaskExecutor as _TaskExecutor
from ansible.plugins.vars import BaseVarsPlugin
from ansible.utils.display import Display
from keepasshttplib import encrypter, keepasshttplib

display = Display()


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
        self.cached_passwords = {}

    def get_cached_password(self, host):
        hosts = get_host_names(host)
        for host_name in hosts:
            return self._get_cached_password(host_name)

    def _get_cached_password(self, host_name):
        password = self.cached_passwords.get(host_name, None)
        if password is None:
            password = self.get_password(host_name)
            self.cached_passwords[host_name] = password
        return password

    def get_password(self, host):
        raise NotImplementedError


class KeepassHTTP(KeepassBase):
    def __init__(self):
        super(KeepassHTTP, self).__init__()
        self.k = keepasshttplib.Keepasshttplib()

    def get_password(self, host_name):
        if not self.test_connection():
            raise KeepassHTTPError('Keepass is closed!')
        try:
            auth = self.k.get_credentials('ssh://{}'.format(host_name))
        except Exception as e:
            raise KeepassHTTPError(
                'Error obtaining host name {}: {}'.format(host_name, e)
            )
        if auth:
            return auth[1]

    def test_connection(self):
        key = self.k.get_key_from_keyring()
        if key is None:
            key = encrypter.generate_key()
        id_ = self.k.get_id_from_keyring()
        try:
            return self.k.test_associate(key, id_)
        except requests.exceptions.ConnectionError as e:
            raise KeepassHTTPError('Connection Error: {}'.format(e))


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
                password = kp.get_cached_password(host)
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
