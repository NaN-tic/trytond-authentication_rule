
import ipaddress
from trytond.model import (sequence_ordered, ModelSQL, ModelView, MatchMixin,
    fields)
from trytond.exceptions import UserError
from trytond.i18n import gettext


class AuthenticationRule(sequence_ordered(), ModelSQL, ModelView, MatchMixin):
    'Authentication Rule'
    __name__ = 'authentication.rule'

    name = fields.Char('Name')
    user = fields.Many2One('res.user', 'User')
    group = fields.Many2One('res.group', 'Group')
    ip_address = fields.Char('IP Address or Network', help='IPv4 or IPv6 IP '
        'address or network. Valid values include: 192.168.0.26 or '
        '192.168.0.0/24')
    action = fields.Selection([
            ('allow', 'Allow'),
            ('deny', 'Deny'),
            ], 'Action', required=True)
    client = fields.Char('Client')

    @classmethod
    def validate(cls, rules):
        for rule in rules:
            rule.check_ip()

    def check_ip(self):
        if not self.ip_address:
            return
        try:
            if '/' in self.ip_address:
                ipaddress.ip_network(self.ip_address)
            else:
                ipaddress.ip_address(self.ip_address)
        except ValueError:
            raise UserError(gettext('authentication_rule.invalid_ip_address',
                    ip=self.ip_address,
                    rule=self.rec_name))

    def get_ip_network(self):
        if not self.ip_address:
            return
        if '/' in self.ip_address:
            return ipaddress.ip_network(self.ip_address)

    def get_ip_address(self):
        if not self.ip_address:
            return
        if '/' not in self.ip_address:
            return ipaddress.ip_address(self.ip_address)

    def match(self, pattern):

        if 'groups' in pattern:
            pattern = pattern.copy()
            groups = pattern.pop('groups')
            if self.group and self.group.id not in groups:
                return False
        if 'ip_address' in pattern:
            pattern = pattern.copy()
            ip_address = ipaddress.ip_address(pattern.pop('ip_address'))
            if (self.get_ip_network()
                    and ip_address not in self.get_ip_network()):
                return False
            if (self.get_ip_address() and ip_address != self.get_ip_address()):
                return False
        return super().match(pattern)
