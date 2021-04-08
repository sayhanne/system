import ldap
import ldap.modlist as modlist
import getpass
def ldap_initialize(remote, port, user, password):
    global conn
    server = 'ldap://' + remote  # not secure connection
    conn = ldap.initialize(uri=server)
    try:
        conn.protocol_version = ldap.VERSION3
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        bind = conn.simple_bind_s(user, password)
        print("Successfully bound to %s.\n" %server)
    except ldap.LDAPError as e:
        print(str(e))

def create_user(name, surname, phone_number):
    global conn
    base_dn = 'CN=Users,DC=hnn,DC=local'
    user_dn = 'CN=' + name + ' ' + surname + ',' + base_dn 
    full_name = name + ' ' + surname
    try:
        user_attrs = {}
        user_attrs['objectclass'] = [b'top', b'person', b'organizationalPerson', b'user']
        user_attrs['cn'] = full_name.encode("utf-8")
        user_attrs['givenName'] = name.encode("utf-8")
        user_attrs['sn'] = surname.encode("utf-8")
        user_attrs['displayName'] = full_name.encode("utf-8")
        user_attrs['telephoneNumber'] = phone_number.encode("utf-8")
        user_ldif = modlist.addModlist(user_attrs)
        conn.add_s(user_dn, user_ldif)
        print('New user added succesfully!')
    except ldap.LDAPError as e:
        print(str(e))

def main():
    ldap_initialize(remote='192.168.1.60', port='636', user='administrator@hnn.local', password='ramY8.')
    name = input('Enter name:')
    surname = input('Enter surname:')
    phone_number = input('Enter phone number:')
    create_user(name=name, surname=surname, phone_number=phone_number)

main()
