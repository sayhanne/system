import ldap
import ldap.modlist as modlist

conn = None
base = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=hnn,DC=local'
ext_keyDict = {}
ext_keyDict.update({'1.3.6.1.5.5.7.3.1':'serverAuth'})	#	SSL/TLS Web Server Authentication.
ext_keyDict.update({'1.3.6.1.5.5.7.3.2':'clientAuth'})	#	SSL/TLS Web Client Authentication.
ext_keyDict.update({'1.3.6.1.5.5.7.3.3':'codeSigning'})	#	Code signing.
ext_keyDict.update({'1.3.6.1.5.5.7.3.4':'emailProtection'})	#	E-mail Protection (S/MIME).
ext_keyDict.update({'1.3.6.1.5.5.7.3.5':'ipsecEndSystem'})	#	IP security end system
ext_keyDict.update({'1.3.6.1.5.5.7.3.6':'timeStamping'})	#	IP security tunnel termination
ext_keyDict.update({'1.3.6.1.5.5.7.3.7':'timeStamping'})	#	IP security user
ext_keyDict.update({'1.3.6.1.5.5.7.3.8':'timeStamping'})	#	Trusted Timestamping
ext_keyDict.update({'1.3.6.1.5.5.7.3.9':'OCSPstamping'})	#	OCSPstamping
ext_keyDict.update({'1.3.6.1.4.1.311.2.1.21':'msCodeInd'})	# 	Microsoft Individual Code Signing (authenticode)
ext_keyDict.update({'1.3.6.1.4.1.311.2.1.22':'msCodeCom'})	#	Microsoft Commercial Code Signing (authenticode)
ext_keyDict.update({'1.3.6.1.4.1.311.10.3.1':'msCTLSign'})	#	Microsoft Trust List Signing
ext_keyDict.update({'1.3.6.1.4.1.311.10.3.3':'msSGC'})	#	Microsoft Server Gated Crypto
ext_keyDict.update({'1.3.6.1.4.1.311.10.3.4':'msEFS'})	#	Microsoft Encrypted File System
ext_keyDict.update({'2.16.840.1.113730.4.1':'nsSGC'})	# 	Netscape Server Gated Crypto

key_dict = {
    128:'digitalSignature', 
    64:'nonRepudiation', 
    32:'keyEncipherment',
    16:'dataEncipherment', 
    8:'keyAgreement', 
    4:'keyCertSign', 
    2:'cRLSign', 
    1:'encipherOnly',
    32768:'decipherOnly'
}


def ldap_initialize(remote, port, user, password):
    global conn
    server = ""
    if port == 636:
        server = 'ldaps://' + remote + ':636'  # secure connection
    elif port == 389:
        server = 'ldap://' + remote  # not secure connection
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    conn = ldap.initialize(uri=server)
    try:
        conn.protocol_version = ldap.VERSION3
        conn.set_option(ldap.OPT_REFERRALS, 0)
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


def create_section(name):
    return


def parse_template(name):
    global key_flags
    criteria = '(cn=' + name + ')'
    attributes = ['pKIKeyUsage', 'pKIExtendedKeyUsage', 'pKIMaxIssuingDepth']
    result = conn.search_s(base, ldap.SCOPE_SUBTREE, criteria, attributes)
    attribute_dict = result[0][1]
    key_hex = attribute_dict['pKIKeyUsage'][0]  # hexadecimal value of the key usage flags sum
    flags_sum = list(bytearray(key_hex))
    subset_sum([1,2,4,8,16,32,64,128,32768],flags_sum[0])  # Possible key usage flags

    ca_check = attribute_dict['pKIMaxIssuingDepth'][0].decode('utf-8')
    keys=''
    ext_keys = ''
    for i in range(len(attribute_dict['pKIExtendedKeyUsage'])):
        key = attribute_dict['pKIExtendedKeyUsage'][i].decode('utf-8')
        ext_keys += ext_keyDict[key] + ', '
    
    for x in key_flags:
        keys += key_dict[x] + ', '

    ext_keys = ext_keys[:-2]  # remove unnecessary part
    keys = keys[:-2]

    sect_name = '[ ' + name + ' ]'
    bsc_cons = 'basicConstraints = CA:'  # CA MI DEĞİL Mİ PATH LEN ?
    key_usage = 'keyUsage = ' + keys
    extended_key_usage = 'extendedKeyUsage = ' + ext_keys


def subset_sum(numbers, target, partial=[]):
    global key_flags
    s = sum(partial)

    # check if the partial sum is equals to target
    if s == target:
        key_flags = partial  # Storing the key usage flags
        # print("sum(%s)=%s" % (partial, target))
    if s >= target:
        return  # if we reach the number then end

    for i in range(len(numbers)):
        n = numbers[i]
        remaining = numbers[i+1:]
        subset_sum(remaining, target, partial + [n])

def main():
    ldap_initialize(remote='192.168.1.60', port=636, user='administrator@hnn.local', password='ramY8.')
    parse_template('Machine')
    conn.unbind()


main()
