#!/usr/bin/python
# encoding=utf-8

"""检测网页编码

[使用]
1、作为模块导入

import decodepage
decodepage.getCharset(headers,html)
decodepage.getUnicodePage(html,charset)

参数说明：
headers：目标URL的http头部信息
html：目标URL的html内容


2、可以直接运行

python decodepage.py http://www.baidu.com 看效果。

[原理]
1、检测http头部是否包含编码
2、上面如果失败，则检测html中的meta是否包含编码
3、上面都失败就使用chardet，但是这里不会拿全部的html去chardet，因为效率会很低，这次会取前几行去判断，提高效率。
"""

import re
import sys
import codecs
#import chardet

# 忽略js里的meta，例如这个页面：http://www.xx007.com/inc/print.js
# meta_re = re.compile(r"""<meta[a-zA-Z\-="\s/;]+charset\s*=\s*['"]?\s*([^"'>\s]+)\s*['"]?""",re.I)

def checkCharEncoding(encoding):
    if encoding:
        encoding = encoding.lower()
    else:
        return encoding

    # http://www.destructor.de/charsets/index.htm
    translate = { 'windows-874': 'iso-8859-11', 'en_us': 'utf8', 'macintosh': 'iso-8859-1',\
                  'euc_tw': 'big5_tw', 'th': 'tis-620','zh-cn': 'gbk','gb_2312-80':'gb2312',\
                  'iso-latin-1':'iso-8859-1','windows-31j':'shift_jis','x-sjis':'shift_jis',\
                  'none': 'null','no':'null','0ff':'null'}

    for delimiter in (';', ',', '('):
        if delimiter in encoding:
            encoding = encoding[:encoding.find(delimiter)].strip()

    # 常见的一些错误写法纠正
    if '8858' in encoding:
        encoding = encoding.replace('8858', '8859') # iso-8858 -> iso-8859
    elif '8559' in encoding:
        encoding = encoding.replace('8559', '8859') # iso-8559 -> iso-8859
    elif '5889' in encoding:
        encoding = encoding.replace('5889', '8859') # iso-5889 -> iso-8859
    elif '2313' in encoding:
        encoding = encoding.replace('2313', '2312') # gb2313 -> gb2312
    elif '2132' in encoding:
        encoding = encoding.replace('2132', '2312') # gb2132 -> gb2312
    elif '2321' in encoding:
        encoding = encoding.replace('2321', '2312') # gb2321 -> gb2312
    elif 'gb-2312' in encoding:
        encoding = encoding.replace('gb-2312', 'gb2312') # gb-2321 -> gb2312
    elif 'gbk2312' in encoding:
        encoding = encoding.replace('gbk2312', 'gbk') # gbk2312 -> gbk
    elif 'gbs2312' in encoding:
        encoding = encoding.replace('gbs2312', 'gb2312') # gbs2312 -> gb2312
    elif '.gb2312' in encoding:
        encoding = encoding.replace('.gb2312', 'gb2312') # .gb2312 -> gb2312
    elif '.gbk' in encoding:
        encoding = encoding.replace('.gbk', 'gbk') # .gbk -> gbk
    elif 'uft-8' in encoding:
        encoding = encoding.replace('uft-8', 'utf-8') # uft-8 -> utf-8
    elif 'x-euc' in encoding:
        encoding = encoding.replace('x-euc', 'euc') # x-euc-kr -> euc-kr

    # 调整为正确的编码方式
    if encoding.startswith('8859'):
        encoding = 'iso-%s' % encoding
    elif encoding.startswith('cp-'):
        encoding = 'cp%s' % encoding[3:]
    elif encoding.startswith('euc-'):
        encoding = 'euc_%s' % encoding[4:]
    elif encoding.startswith('windows') and not encoding.startswith('windows-'):
        encoding = 'windows-%s' % encoding[7:]
    elif encoding.find('iso-88') > 0:
        encoding = encoding[encoding.find('iso-88'):]
    elif encoding.startswith('is0-'):
        encoding = 'iso%s' % encoding[4:]
    elif encoding.find('ascii') > 0:
        encoding = 'ascii'

    # http://philip.html5.org/data/charsets-2.html
    if encoding in translate:
        encoding = translate[encoding]
    if encoding in ('null', '{$'):   # charset={$charset$} in templates files,eg:dedecms
        return None

    # http://www.iana.org/assignments/character-sets
    # http://docs.python.org/library/codecs.html
    try:
        codecs.lookup(encoding)
    except LookupError:
        warnMsg = "unknown web page charset '%s'. " % encoding
        #echo_csrf(warnMsg)
        encoding = None

    return encoding

def detectCharEncoding(html):
    retVal = ''
    if html:
        lines = html.split('\n')
        for i in [10, 50, 100]:
            retVal = chardet.detect('\n'.join(lines[:i]))['encoding']
            if retVal and retVal.lower() != 'ascii':
                break
    return retVal

def getCharset(headers, html):
    charset,contentType,httpCharset, metaCharset = None, None, None, None
    meta_re = re.compile(r'<meta[a-zA-Z\-="\s/;]+charset="?([^">]+)',re.DOTALL | re.IGNORECASE)

    if headers and headers.has_key('content-type'):
        contentType = headers['content-type']
        if contentType and (contentType.find('charset=') != -1):
            httpCharset = checkCharEncoding(contentType.split('charset=')[-1])

    if html:
        match= meta_re.search(html)
        if match:
            metaCharset = checkCharEncoding(match.group(1))

    if ((httpCharset or metaCharset) and not all([httpCharset, metaCharset]))\
       or (httpCharset == metaCharset and all([httpCharset, metaCharset])):
        charset = httpCharset or metaCharset
    else:
        charset = None

    if contentType:
        charset = charset or checkCharEncoding(detectCharEncoding(html))

    #html = getUnicode(html, charset)
    return charset

def getUnicode(value, encoding=None, system=False):
    """
    Return the unicode representation of the supplied value:

    >>> getUnicode(u'test')
    u'test'
    >>> getUnicode('test')
    u'test'
    >>> getUnicode(1)
    u'1'
    """
    UNICODE_ENCODING = "utf8"

    if not system:
        if isinstance(value, unicode):
            return value
        elif isinstance(value, basestring):
            return unicode(value, encoding or UNICODE_ENCODING, errors="replace")
        else:
            return unicode(value) # encoding ignored for non-basestring instances
    else:
        try:
            return getUnicode(value, sys.getfilesystemencoding() or sys.stdin.encoding)
        except:
            return getUnicode(value, UNICODE_ENCODING)


def getUnicodePage(html,charset):
    if html and charset:
        html = getUnicode(html, charset)
    return html

if __name__ == '__main__':
    import urllib2
    import socket
    # http://www.baidu.com
    # http://anquan.baidu.com
    # http://charset.7jp.net/sjis.html
    socket.setdefaulttimeout(8)

    try:
        url = sys.argv[1]
    except:
        #echo_csrf('Usage: python decodepage.py http://www.knownsec.com/')
        sys.exit(0)

    req = urllib2.Request(url)
    req.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)')
    r = urllib2.urlopen(req)
    headers = r.headers.dict
    html = r.read()
    r.close()
    charset = getCharset(headers,html)
    #echo_csrf('[*] checking:%s' %url)
    #echo_csrf('[+] target charset:%s' %charset)
    #echo_csrf('[*] decode to unicode:\n')
    #echo_csrf(getUnicodePage(html,charset))

