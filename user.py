from trytond.pool import Pool, PoolMeta
from trytond.transaction import Transaction
import ipaddress


def is_user_id_allowed(user_id, parameters):
    pool = Pool()
    Rule = pool.get('authentication.rule')
    User = pool.get('res.user')
    pattern = {}
    context = Transaction().context
    if user_id:
        user = User(user_id)
        pattern['user'] = user.id
        pattern['groups'] = [x.id for x in user.groups]
    remote_addr = context.get('_request', {}).get('remote_addr')
    if remote_addr:
        pattern['ip_address'] = ipaddress.ip_address(remote_addr)
    if 'client' in parameters:
        pattern['client'] = parameters['client']
    for rule in Rule.search([]):
        if rule.match(pattern):
            return rule.action == 'allow'
    return True


class User(metaclass=PoolMeta):
    __name__ = 'res.user'

    @classmethod
    def _login_password(cls, login, parameters):
        user_id = super()._login_password(login, parameters)
        if user_id and is_user_id_allowed(user_id, parameters):
            return user_id

