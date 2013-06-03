#!/usr/bin/python


import os
if os.name == 'nt':
    GOODSTART = ""
    GOODEND = ""
    BADSTART = "*"
    BADEND = "*"
    WARNINGSTART = '-'
    WARNINGEND = '-'
else:
    GOODSTART = "\033[0;32m"
    GOODEND = "\033[0m"
    BADSTART = "\033[0;31m"
    BADEND = "\033[0m"
    WARNINGSTART = '\033[0;33m'
    WARNINGEND = '\033[0m'

try:
    #TRACE checker--------------------
    import httplib
    import urlparse

    bad =[400,401,402,403,405,406,501] 

    def resolve_http_redirect(url, method, depth=0):
        if depth > 10:
            raise Exception("Redirected "+depth+" times, giving up.")
        o = urlparse.urlparse(url,allow_fragments=True)
        if(o.scheme == 'https'):
            conn = httplib.HTTPSConnection(o.netloc)
        else:
            conn = httplib.HTTPConnection(o.netloc)
        path = o.path
        if o.query:
            path +='?'+o.query
        conn.request(method, path)
        res = conn.getresponse()
        headers = dict(res.getheaders())
        if headers.has_key('location') and headers['location'] != url:
            print('redirect to '+headers['location'])
            try:
                return resolve_http_redirect(headers['location'], method, depth+1)
            except:
                print 'error following redirect'
                return url
        else:
            return url


    TRACE = False

    address = raw_input("server ip or domain? ")
    if('://' not in address):
        address = 'http://'+address
    url = resolve_http_redirect(address, 'TRACE')
    o = urlparse.urlparse(url,allow_fragments=True)
    if(o.scheme == 'https'):
        con = httplib.HTTPSConnection(o.netloc)
    else:
        con = httplib.HTTPConnection(o.netloc)
    con.request('TRACE',o.path)
    resp = con.getresponse()
    if(resp.status not in bad ):
        print BADSTART+ 'TRACE request responded with:'+BADEND
        print resp.read()
        TRACE = True
    else:
        print GOODSTART+'TRACE says '+resp.reason+GOODEND
        url = resolve_http_redirect(address, 'OPTIONS')
        o = urlparse.urlparse(url,allow_fragments=True)
        if(o.scheme == 'https'):
            con = httplib.HTTPSConnection(o.netloc)
        else:
            con = httplib.HTTPConnection(o.netloc)
        con.request('OPTIONS',o.path)
        resp = con.getresponse()
        if(resp.status in bad ):
            print GOODSTART+'and OPTIONS says '+resp.reason+GOODEND
        elif(resp.status != 200):
            print GOODSTART+'checking OPTIONS failed'+GOODEND
        else:
            print
            print WARNINGSTART+'These are the reported OPTIONS'+WARNINGEND
            print str(resp.status)+' '+resp.reason
            print resp.msg
    netloc = o.netloc
except Exception, e:
    print e
    netloc = address


#SSL eyes processes --------------------
import subprocess
import xml.etree.ElementTree as et

def checkCert(certinfo):
    try:
        return certinfo[0].attrib['hasMatchingHostname'] == 'True', certinfo[0].attrib['isTrustedByMozillaCAStore'] == 'True'
    except Exception, e:
        print WARNINGSTART+'cert check '+str(e)
        print 'failed to insecure'+WARNINGEND
        return False,False
        
def renegotiation(reneg):
    try:
        return reneg[0].attrib['canBeClientInitiated'] == 'True', reneg[0].attrib['isSecure'] == 'True'
    except Exception, e:
        print WARNINGSTART+'renegotiation '+str(e)
        print 'failed to insecure'+WARNINGEND
        return True, False
        
def resumption(resum):
    try:
        return resum[0].attrib['isSupported'] == 'True', resum[1].attrib['isSupported'] == 'True'
    except Exception, e:
        print WARNINGSTART+'Resumption: '+str(e)
        print 'failed to insecure'+WARNINGEND
        return False,False

def cipher_check(ciphers, used):
    try:
        fin = {}
        suites = {}
        for suite in used:
            try:
                test = (len(suite[2]) != 0)
                suites[suite.attrib['title'].split()[0]] = test
                for cipher in suite[2]:
                    fin[cipher.attrib['name']] = ciphers[cipher.attrib['name']]
            except:
                suites[suite.attrib['exception'].split()[2]] = "False"
        return fin, suites
    except Exception, e:
        print WARNINGSTART+'ciphers '+str(e)
        print 'some information may have been lost'+WARNINGEND
        try:
            return fin, suites
        except:
            return [], []

tags = ['HIGH', 'MEDIUM', 'LOW', 'aNULL', 'EXP', 'MD5']
ciphers = {}
if os.name == 'nt':
    f = open('ciphers')
    ciphers = eval(f.read())
    f.close()
    subprocess.check_output(['python','windows/sslyze.py','--regular',netloc, '--xml_out=out.xml'])
    
else:
    try:
        for tag in tags:
            osslciphers = subprocess.check_output(['openssl','ciphers',tag]).split(':')
            for cipher in osslciphers:
                cipher = cipher.strip()
                ciphers[cipher] = tag
        f = open('ciphers','w')
        f.write(str(ciphers))
        f.close()
    except:
        print('openssl is not working, reverting to backup')
        f = open('ciphers')
        ciphers = eval(f.read())
        f.close()
    subprocess.check_output(['python','not/sslyze.py','--regular',netloc, '--xml_out=out.xml'])

findings = et.parse('out.xml').getroot()[0][0]
certinfo = findings[0]
compress = findings[1]
reneg = findings[2]
resum = findings[3]
ciphersUsed = findings[4:]

def TrueFalseColor(value):
    if value == "False":
        return BADSTART+value+BADEND
    return GOODSTART+value+GOODEND

def TrueFalseColorInverse(value):
    if value == "False":
        return GOODSTART+value+GOODEND
    return BADSTART+value+BADEND

def StrengthColor(value):
    if value == 'HIGH':
        return GOODSTART+value+GOODEND
    if value == 'MEDIUM':
        return WARNINGSTART+value+WARNINGEND
    return BADSTART+value+BADEND

certHost, certTrust = checkCert(certinfo)
renegStatus, renegSecure = renegotiation(reneg)
resumSessionID, resumTLS = resumption(resum)
checkedCiphers, checkedSuites = cipher_check(ciphers,ciphersUsed)
print
print 'CERT'
print 'trusted           '+TrueFalseColor(str(certTrust))
print 'for correct host  '+TrueFalseColor(str(certHost))
print
print 'Ciphers used'
for cipher in checkedCiphers:
    print StrengthColor(checkedCiphers[cipher])+'\t'+cipher
print
print 'Suites'
for suite in checkedSuites:
    if suite in ["SSLV2","SSLv2"]:
        print suite+'\t'+TrueFalseColorInverse(str(checkedSuites[suite]))
    else:
        print suite+'\t'+TrueFalseColor(str(checkedSuites[suite]))
print 

if(renegStatus):
    print 'renegotiation:             '+WARNINGSTART+str(renegStatus)+WARNINGEND
    print 'renegotiation secure:      '+TrueFalseColor(str(renegSecure))
else:
    print 'renegotiation:             '+GOODSTART+str(renegStatus)+GOODEND
print 'resuming with Session IDs: '+str(resumSessionID)
print 'resuming with TLS:         '+str(resumTLS)

os.remove('out.xml')


raw_input('press enter to finish')



