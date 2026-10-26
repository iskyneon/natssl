"""Match the Go CLI's canonical subjects and certificate filenames."""
import ipaddress
import re

from ansible.errors import AnsibleFilterError


def canonical_subject(value):
    value = str(value).strip().lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    dns = value[2:] if value.startswith('*.') else value
    labels = dns.split('.')
    if ('.' not in value or len(dns) > 253 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)):
        raise AnsibleFilterError('Certificate subject must be an IP address or dotted DNS name')
    return value


def certificate_name(value):
    return canonical_subject(value).replace('*', '_').replace(':', '_')


class FilterModule:
    def filters(self):
        return {'natssl_subject': canonical_subject, 'natssl_cert_name': certificate_name}
