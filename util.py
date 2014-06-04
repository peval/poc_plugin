# encoding=utf8
import urlparse
import json
import urllib
import urllib2
import httplib
import cookielib
import socket
import sys
import re
import zlib
import decodepage
import md5 as _md5
import struct


# BPScanner配置为最高优先
try:
    sys.path.append("..")
    from param_config import PARAM_CONFIG
except ImportError:
    class PARAM_CONFIG:
        EXCLUDE = '{}'
        TIMEOUT = 20
        THRESHOLD_ENABLED = False
        THRESHOLD_LIST = ""
        PROXY = ""

# 由于_fileobject不能直接使用，因此模拟实现一个Url重定向后的Reponse类
class _RedirectResponse:
    def __init__(self):
        self.headers = {}
        self.status = 0
        self.code = 0
        self.body = None
        self.url = None

    def getcode(self):
        return self.code

    def read(self):
        return self.body

    def info(self):
        return self.headers

    def geturl(self):
        return self.url

# 用来实现在第一个重定向后停止下来，并返回相应的信息
class UnredirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        #response = urllib2.HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, headers)
        response = _RedirectResponse()
        response.code = code
        response.headers = headers
        response.url = headers.get("location", "")
        response.body = fp.read()
        fp.close()
        return response

    def http_error_302(self, req, fp, code, msg, headers):
        #response = urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)
        response = _RedirectResponse()
        response.code = code
        response.headers = headers
        response.url = headers.get("location", "")
        response.body = fp.read()
        fp.close()
        return response

HTTP_STATUS_OK = 0
HTTP_STATUS_FAILD = 1
HTTP_STATUS_TIMEOUT = 2
HTTP_STATUS_REQUEST_ERROR = 3
HTTP_STATUS_RESPONSE_ERROR = 4
HTTP_STATUS_UNKNOWN_SCHEME = 5
HTTP_STATUS_INVALID_PARAM = 6
HTTP_STATUS_INVALID_ADDRESS = 7

def sendHttpRequest(uri,
    headers=None,
    method="GET", 
    data=None,
    urlEncode=True,
    redirect=True, 
    timeout=1):
    timeout = timeout if timeout < PARAM_CONFIG.TIMEOUT else PARAM_CONFIG.TIMEOUT
    socket.setdefaulttimeout(timeout)

    if PARAM_CONFIG.PROXY:
        proxyList = PARAM_CONFIG.PROXY.strip().split(",")
        proxyDict = {}
        for proxy in proxyList:
            urlElements = urlparse.urlparse(proxy)
            if urlElements.scheme and urlElements.netloc:
                proxyDict.update({urlElements.scheme: urlElements.netloc})
        proxyHandler = urllib2.ProxyHandler(proxyDict)
    else:
        proxyHandler = urllib2.ProxyHandler({})
    proxyHandler = urllib2.ProxyHandler({})

    if redirect:
        redirectHandler = urllib2.HTTPRedirectHandler
    else:
        redirectHandler = UnredirectHandler

    request = urllib2.Request(uri)

    if headers:
        if type(headers) == type({}):
            for k,v in headers.iteritems():
                request.add_header(k, v)
        else:
            return 0, None, None, None, HTTP_STATUS_INVALID_PARAM

    if data:
        if urlEncode:
            try:
                urlEncodedData = urllib.urlencode(data)
            except e:
                return 0, None, None, None, HTTP_STATUS_INVALID_PARAM
            request.add_data(urlEncodedData)

    if method.upper() != "GET" and method.upper() != "POST" :
        request.get_method = lambda: method.upper()

    cookieJar = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPHandler, 
        proxyHandler, 
        redirectHandler, 
        #urllib2.HTTPDefaultErrorHandler,
        urllib2.HTTPCookieProcessor(cookieJar))

    response = None
    error = HTTP_STATUS_FAILD
    try:
        response = opener.open(request)
    except urllib2.HTTPError, e:
        print "urllib2.HTTPError:%s" % (e.reason)
        if -1 != e.reason.find("11004"):
            error = HTTP_STATUS_INVALID_ADDRESS
            return 0, None, None, None, error

        return e.getcode(), e.info(), e.read(), e.geturl(), 0
    except urllib2.URLError, e:
        print "urllib2.URLError:%s" % (e.reason)
        if isinstance(e.reason, socket.timeout):
            error = HTTP_STATUS_TIMEOUT
        return 0, None, None, None, error
    except httplib.BadStatusLine, e:
        print "httplib.BadStatusLine:"
        return 0, None, None, None, HTTP_STATUS_RESPONSE_ERROR
    except socket.error, e:
        (errno, strerror) = e
        print "socket.error:%d %s" % (errno, strerror)
        return 0, None, None, None, error
    except:
        print "Exception:"
        (ErrorType, ErrorValue, ErrorTB) = sys.exc_info()
        print ErrorType
        print ErrorValue
        print ErrorTB
        return 0, None, None, None, error
    else:
        return response.getcode(), response.info(), response.read(), response.geturl(), 0

def getHostByUrl(url):
    urlElements = urlparse.urlparse(url)
    return urlElements.netloc

def fillPayload(url, param, payload, isAppend=True):
    urlElements = urlparse.urlparse(url)
    if not urlElements.query:
        return None

    payloadQuery = ""
    pairList = urlparse.parse_qsl(urlElements.query, True)

    for pair in pairList:
        key = pair[0]
        value = pair[1]
        if param == key:
            if isAppend:
                value += payload
            else:
                value = payload
        if payloadQuery:
            payloadQuery += "&"
        payloadQuery += "%s=%s" % (key, value)

    #print "payloadQuery:%s" % (payloadQuery)
    payloadUrl = urlparse.urlunparse((urlElements.scheme, 
        urlElements.netloc, 
        urlElements.path,
        urlElements.params,
        payloadQuery,
        urlElements.fragment))

    if payloadUrl == url:
        return None
    else:
        return payloadUrl

def isUri(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:\S+:\S@)?://' # name:password@
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return regex.match(url)

def isIPAddress(ip):
    try:
        print socket.inet_aton(ip)
    except:
        return False
    return True

def htmlDecode(header, body):
    content_encoding = header.get('Content-Encoding','')
    if not content_encoding:
        content_encoding = header.get('content-encoding','')
    
    if content_encoding.lower() == 'gzip':
        body = zlib.decompress(body,16+zlib.MAX_WBITS)
    charset = decodepage.getCharset(header, body)
    body = decodepage.getUnicodePage(body, charset)
    return header, body

def urlEncode(content):
    return urllib2.urlencode(content)

def md5(message):
    if type(message) != type(""):
        return None

    m = _md5.new()
    m.update(message)
    return m.hexdigest()


if __name__ == "__main__":
    '''
    print md5("7")
    # isIPAddress test
    if isIPAddress("1.1.1.1"):
        print "isIPAddress True"
    else:
        print "isIPAddress False"
    # isUri test
    if isUri("https://lianguan:liangquan@www.baidu.com:8080/index.php?#123456"):
        print "isUri True"
    else:
        print "isUri False"
    # fillPayload test
    u = fillPayload("http://www.baidu.com:8080/index.php?a=1&b=2&c&#123456", "a", "' and '1'='1", True)
    if not u:
        print "invalid url"
    else:
        print u
    '''

    # sendHttpRequest test
    code, headers, body, location, error = sendHttpRequest("http://mango.lub4r.cc/2/upload/forum.php",
        {"Cookie": "test=1 2 3", "Content-Length": 123},
        data={"name": "zhaodaichong", "password": "123456", "test": "x y z ?"},
        method="PUT",
        urlEncode=False,
        redirect=False)

    if error:
        print "error:%d, code:%d" % (error, code)
    else:
        print "error:%d, code:%d, location:%s" % (error, code, location)
        print "headers:"
        print headers
        if body:
            print "body (512bytes tr\uncated):%s" % (body[:512])