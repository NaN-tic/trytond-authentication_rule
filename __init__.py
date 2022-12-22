# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.pool import Pool
from . import user
from .import rule


def register():
    Pool.register(
        user.User,
        rule.AuthenticationRule,
        module='authentication_rule', type_='model')