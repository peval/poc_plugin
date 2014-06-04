poc_plugin
==========

1.依赖包安装：
chardet-2.2.1.tar

具体POC 插件分为两种模式：audit与fuzz模式

编写插件时分别参考：
demo_audit_plugin.py
demo_fuzz_plugin.py

插件中漏洞类型取以下几个值，如file_upload：
        (0,'sql_injection'),
        (1,'code_execution'),
        (2,'cmd_execution'),
        (3,'file_inclusion'),
        (4,'file_upload'),
        (5,'csrf'),
        (6,'xss'),
        (7,'intra_proxy'),
        (8,'url_location'),
        (9,'fastcgi_parser'),
        (10,'info_disclosure'),
        (11,'access_control'),
        (12,'configure_error'),
        (13,'design_fault'),
        (14,'backdoor'),
        (15,'weak_password'),
        (16,'dos'),
        (17,'overflow'),
