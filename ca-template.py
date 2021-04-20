import ldap
import ldap.modlist as modlist
import base64

conn = None
base = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=hnn,DC=local'

def ldap_initialize(remote, port, user, password):
    global conn
    server = ""
    if port == 636:
        server = 'ldaps://' + remote + ':636'  # secure connection
    elif port == 389:
        server = 'ldap://' + remote  # not secure connection
    conn = ldap.initialize(uri=server)
    try:
        conn.protocol_version = ldap.VERSION3
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        bind = conn.simple_bind_s(user, password)
        print("Successfully bound to %s.\n" % server)
    except ldap.LDAPError as e:
        print(str(e))


def get_template(name):
    criteria = '(cn='+ name +')'
    result = conn.search_s(base, ldap.SCOPE_SUBTREE, criteria)
    print(result)

def create_template(name):
    template_dn = 'CN=' + name + ',' + base
    default_csps=[b'2,Microsoft Base Cryptographic Provider v1.0', b'1,Microsoft Enhanced Cryptographic Provider v1.0']
    try:
        template_attr = {}
        template_attr['objectclass'] = [b'top', b'pKICertificateTemplate']
        template_attr['cn'] = name.encode("utf-8")
        template_attr['displayName'] = name.encode("utf-8")
        template_attr['pKIDefaultCSPs'] = default_csps
        template_ldif = modlist.addModlist(template_attr)
        conn.add_s(template_dn, template_ldif)
        print('New template added succesfully!')
    except ldap.LDAPError as e:
        print(str(e))

def ssl_ad_sync():
    criteria = '(cn=Machine)'
    attributes = ['pKIKeyUsage', 'pKIExtendedKeyUsage', 'pKIMaxIssuingDepth']
    result = conn.search_s(base, ldap.SCOPE_SUBTREE, criteria, attributes)
    attribute_dict = result[0][1]
    key_hex = attribute_dict['pKIKeyUsage'][0]
    # print(key_hex)
    flags = list(bytearray(key_hex))
    subset_sum([1,2,4,8,16,32,64,128,32768],flags[0])

def subset_sum(numbers, target, partial=[]):
    s = sum(partial)

    # check if the partial sum is equals to target
    if s == target: 
        print("sum(%s)=%s" % (partial, target))
    if s >= target:
        return  # if we reach the number then end

    for i in range(len(numbers)):
        n = numbers[i]
        remaining = numbers[i+1:]
        subset_sum(remaining, target, partial + [n])

def main():
    ldap_initialize(remote='192.168.1.60', port=636, user='administrator@hnn.local', password='ramY8.')
    ssl_ad_sync()
    conn.unbind()


main()
