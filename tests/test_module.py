# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.tests.test_tryton import ModuleTestCase, with_transaction
from trytond.pool import Pool

# The following two helpers are defined in hyton/sugar
# Copied python translation here to avoid depending on hyton and hy

def save(model):
    model.save()
    return model


def pool_create(model_name, *args, **kargs):
    return save(Pool().get(model_name)(*args, **kargs))


class AutheticationRuleTestCase(ModuleTestCase):
    'Test Authentication Rule module'
    module = 'authentication_rule'

    @with_transaction()
    def test_match(self):
        group1 = pool_create('res.group', name='group_test1')
        user = pool_create('res.user',
                           name='test',
                           login='test',
                           password='viva1!match',
                           groups=[group1])
        group2 = pool_create('res.group', name='group_test2')
        rule_group2 = pool_create('authentication.rule',
                                  name='test1',
                                  group=group2,
                                  action='allow')
        rule_user1 = pool_create('authentication.rule',
                                 name='test1',
                                 user=user,
                                 action='allow')

        rule_u1_and_g2 = pool_create('authentication.rule',
                                     name='test1',
                                     user=user,
                                     group=group2,
                                     action='allow')

        rule_empty_match_all = pool_create('authentication.rule',
                                     name='test1',
                                     action='allow')

        rule_ip_address = pool_create('authentication.rule',
                                  name='test1',
                                  ip_address='192.162.1.0/24',
                                  action='allow')
        rule_client = pool_create('authentication.rule',
                                  name='test1',
                                  client='test',
                                  action='allow')

        self.assertTrue(rule_group2.match({'user': user.id,
                                           'groups': [group2.id]}))

        self.assertTrue(rule_user1.match({'user': user.id,
                                          'groups': [group2.id]}))
        self.assertTrue(rule_user1.match({'user': user.id,
                                          'groups': [group2.id],
                                          'client': None}))

        self.assertTrue(rule_u1_and_g2.match({'user': user.id,
                                              'groups': [group2.id]}))
        self.assertFalse(rule_u1_and_g2.match({'user': -1,
                                               'groups': [group2.id]}))
        self.assertFalse(rule_u1_and_g2.match({'user': user.id,
                                               'groups': [group1.id]}))
        # empty rule no user no group no ip always match.
        self.assertTrue(rule_empty_match_all.match({'user': -1,
                                                    'groups': []}))
        self.assertFalse(rule_ip_address.match({'ip_address': '192.162.2.3'}))
        self.assertTrue(rule_ip_address.match({'ip_address': '192.162.1.3'}))
        self.assertTrue(rule_client.match({'client': 'test'}))
        self.assertFalse(rule_client.match({'client': 'testDenail'}))
        self.assertTrue(rule_client.match({}))
        self.assertFalse(rule_client.match({'client': None}))

del ModuleTestCase
