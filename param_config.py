# encoding=utf8
__metaclass__  = type

class PARAM_CONFIG:
	TASK_ID = ''
	MONITOR = "127.0.0.1:11117"
	URL = ""
	URL_FILE = ""
	RESULT_FILE = ""
	PLUGINS_PATH = "./plugins"
	PLUGINS_TOTAL = 0
	FUZZ_PLUGINS_TOTAL = 0
	AUDIT_PLUGINS_TOTAL = 0
	#PLUGINS = "xss,flash_xss,sql,php_cmd,struts_cmd,file_upload,file_include,intra_proxy,url_location,http_only,fastcgi_parse,csrf,demo_plugin"
	PLUGINS = "xss,sql,csrf,file_include,php_cmd,fastcgi_parse,url_location"
	#EXCLUDE = '{"www.baidu.com": ["sql", "file_include"], \
	#"tieba.baidu.com": ["xss", "sql", "csrf", "file_include", "php_cmd", "fast_cgi_parse", "url_location"]}'
	EXCLUDE = '{}'

	TIMEOUT = 20
	MODE = 5
	FAST = True
	SPEED = 200
	MAX_THREADS = 40
	RULE = "baidu-inner"
	THRESHOLD_ENABLED = False
	THRESHOLD_LIST = ""
	REALTIME_RESULT_ENABLED = False
	REALTIME_RESULT_URL = None
	XSS_TIMEOUT = 40
	THREAD_TIMEOUT = 300
	LOG_PATH = ""
	INTERACTIVE_MODE = False
	PING_ADDRESS = "8.8.8.8"
	PING_ENABLED = False
	#PROXY = "http://tc-spider01.tc.baidu.com:8080,https://tc-spider01.tc.baidu.com:8888"
	PROXY = 'http://127.0.0.1:8080'

	DELIMITER = "scan_result_boundary"
	EXIT_CODE_DELIMITER = "exit_code_boundary"
	PLATFORM = "Windows"

	class HTTP_HEADER:
		COOKIE = ""
		COOKIES_FILE = ""	
		USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"
		REFERER = ""
		HEADERS = ""
		HOST_BIND = ""

	class INTERPRETER:
		PHP = "D:\Development\php-5.2.12-Win32\php.exe"
		PYTHON = "C:\Python27\python.exe"
		PERL = "D:\Development\Perl\bin\perl.exe"
		DLL_STUB = None
		COM_STUB = None
		CSHARP_STUB = None
		SO_STUB = None
		RULE_ENGINE = "rule_exec"

	class POSTFIX:
		PHP = ".php"
		PYTHON = ".py"
		PERL = ".pl"
		DLL_STUB = ".dll"
		COM_STUB = ".dll"
		CSHARP_STUB = ".dll"
		SO_STUB = ".so,.a"
		RULE = ".xml"




