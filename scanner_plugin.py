# encoding=utf8

from optparse import OptionParser
import json
import sys

class LEVEL:
    CRITICAL = 3
    WARNING = 2
    LOW = 1


class ScannerPluginError(Exception):
   def __init__(self, value):
      self.value = "ScannerPluginError: " + value


class ScannerPlugin(object):
    def __init__(self):
        self.__delimiter = "standard_output_boundary"  # 标准输出的定界符
        self.__scanResultList = []
        self.__description = {}
        self.__isInternal = True

        self._addDescription({"load_type":"internal", "mode":"audit"})  # 默认情况下，插件都是内部调用且audit模式
        self.describe()  # 加载插件作者对插件的描述
        name = self.__description.get("name")
        if name:
            nameElements = name.strip().split(" ")
            if len(nameElements) > 3:
        
                self._addDescription({"app_name": nameElements[0]})
                self._addDescription({"version_scope": nameElements[1]})
                module_path = nameElements[2] if nameElements[2] else "/"
                self._addDescription({"module_path": module_path})
                self._addDescription({"vulnerability": nameElements[3]})

        print self.__description
        if not self.__check():
            raise ScannerPluginError("incomplete structure of code")  # 代码结构不完整
            return

        if self.__description["load_type"] == "external":
            self.__isInternal = False

        if self.__isInternal:
            # 内部模式init完成
            return

        # 外部模式init
        optionParser = OptionParser()  
        optionParser.add_option("--initialize", dest="isCallInitialize", action="store_true", default=False, metavar=None, help="whether call initialize function")
        optionParser.add_option("--get-describe",  dest="isCallGetDescribe", action="store_true", metavar=None, default=False, help="whether call getDescription function to obtain information about plugin")
        optionParser.add_option("--delimiter",  dest="delimiter", metavar=None, default="standard_output_boundary", help="delimiter use to separate data from stdout")
        optionParser.add_option("--fuzz", dest="context", metavar=None, default=None, type="string", help="context of scanning target in fuzz mode")
        optionParser.add_option("--audit", dest="target", metavar=None, default=None, type="string", help="scanning target in audit mode")
        optionParser.add_option("--uninitialize",  dest="isCallUninitialize", action="store_true", metavar=None, default=False, help="whether call uninitialize function")

        (options, args) = optionParser.parse_args()

        if options.delimiter:
            self.__delimiter = options.delimiter

        if options.isCallGetDescribe:
            self.getDescription()
            return

        if options.isCallInitialize:
            self.initialize()

        if self.__description["mode"] == "audit" and options.target != None:
            try:
                self.audit(options.target)
            except:
                print "Exception: in audit function"
        elif self.__description["mode"] == "fuzz" and options.context != None:
            try:
                context = json.loads(options.context)
            except (ValueError, KeyError, TypeError):
                print "invalid context: "
                print options.context
                return
            try:
                self.fuzz(context)
            except:
                print "Exception: in fuzz function"

        self.returnScanResult()
        if options.isCallUninitialize:
            self.uninitialize()

    def getDescription(self, jsonEncode=False):  # jsonEncode param is only effective when self.__isInternal is True (internal mode)
        if self.__isInternal:
            if jsonEncode:
                return json.dumps(self.__description)
            else:
                return self.__description
        else:
            sys.stdout.write(self.__delimiter + json.dumps(self.__description) + self.__delimiter)

    def initialize(self, id):
        self._addDescription({"id": id})

    def describe(self):
        self._addDescription({"load_type":"internal", "mode":"audit"}) 

    def fingerprint(self, target):
        return True

    def audit(self, target):
        self._addScanResult({"method": "POST",
        "post_data": "x=1&y=2&z=3",
        "url": target, 
        "vul_key": "key"})

    def fuzz(self, context):
        self._addScanResult({"method": context["method"],
        "post_data": context["data"],
        "url": context["url"], 
        "vul_key": context["param"]})

    def uninitialize(self):
        self.__scanResultList = []
        pass

    def _addDescription(self, describe):
        if type(describe) == type({}):
            if not self.__description:
                self.__description = describe
            else:
                self.__description.update(describe)
        else:
            print "Invalid describe format"

    def _addScanResult(self, scanResult):

        buildInParameters = {"type": self.__description["name"],
        "id": self.__description["id"],
        "app_name": self.__description.get("app_name", ""),
        "version_scope": self.__description.get("version_scope", ""),
        "status": 1, 
        "vulnerability": "baidu_poc", #self.__description.get("vulnerability", ""),
        "level": self.__description["level"]} #  根据插件作者对poc的描述来构建一部分扫描结果信息，尽可能减轻插件开发者工作量。

        if type(scanResult) == type({}):
            scanResult.update(buildInParameters)
            self.__scanResultList.append(scanResult)
        elif type(scanResult) == type([]):
            for item in scanResult:
                item.update(buildInParameters)
                self.__scanResultList.append(item)
            #self.__scanResultList.extend(scanResult)

    def __check(self):
        keys = self.__description.keys()
        values = self.__description.values()

        if set(keys) < set(("load_type", "mode", "name", "type", "target", "version", "scope", "level")):
            return False

        if not all(values):
            return False

        if not hasattr(self, "fingerprint") or not callable(self.fingerprint):
            return False

        if not hasattr(self, "describe") or not callable(self.describe):
            return False

        if self.__description["mode"] == "audit":
            if not hasattr(self, "audit") or not callable(self.audit):
                return False

        if self.__description["mode"] == "fuzz":
            if not hasattr(self, "fuzz") or not callable(self.fuzz):
                return False

        return True

    def returnScanResult(self, jsonEncode=False): # jsonEncode param is only effective when self.__isInternal is True (internal mode)
        if self.__isInternal:
            if jsonEncode:
                return json.dumps(self.__scanResultList)
            else:
                return self.__scanResultList
        else:
            sys.stdout.write(self.__delimiter + json.dumps(self.__scanResultList) + self.__delimiter)



