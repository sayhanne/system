import ldap
import getpass

def ldap_initialize(remote, port, user, password):
    try:
        server = 'ldap://' + remote #+ ':' + port
        l = ldap.initialize(server)
        l.protocol_version = ldap.VERSION3
        l.set_option(ldap.OPT_REFERRALS, 0)
        l.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        l.set_option(ldap.OPT_NETWORK_TIMEOUT, 20.0)
        bind = l.simple_bind_s(user, password)
        print("Successfully bound to %s.\n" %server)
    except ldap.LDAPError as e:
        print(str(e))


def main():
    user = input('Enter user@domain:')
    password = getpass.getpass('Enter password:')
    ldap_initialize(remote='192.168.1.48', port='636', user=user, password=password)

main()
