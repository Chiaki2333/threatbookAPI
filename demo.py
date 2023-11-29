#!/usr/bin/python
# -*- coding: UTF-8 -*-
'''
此处为微步在线api的v3版本的接口封装库的演示脚本。
微步在线云API使用文档：https://x.threatbook.com/v5/apiDocs
Github: https://github.com/Chiaki2333/threatbookAPI
'''

from threatbookAPI import *

if __name__ == "__main__" :
    # 微步在线API Key，登录自己微步获取 https://x.threatbook.com/v5/myApi
    # 同时在微步上绑定访问IP，微步在线仅接受符合IP来源的API请求。
    apikey = ""

    # 代理设置，如无代理置空即可。
    proxies = {
        'http': '',
        'https': ''
    }

    '''
    proxies = {
        'http': 'http://127.0.0.1:8083',
        'https': 'http://127.0.0.1:8083'
    }
    '''
    
    # IP分析
    flag = ip_query(apikey, "117.50.162.53", lang="zh", proxies=proxies)
    print(flag)
    # IP信誉
    flag = scene_ip_reputation(apikey, "117.50.162.53", lang="zh", proxies=proxies)
    print(flag)
    # 域名分析
    flag = domain_query(apikey, "baidu.com", lang="zh", proxies=proxies)
    print(flag)
    # 失陷检测
    flag = scene_dns(apikey, "117.50.162.53", lang="zh", proxies=proxies)
    print(flag)
    # 提交文件分析
    flag = file_upload(apikey, "artifact.exe", proxies=proxies)
    print(flag)
    # 文件信誉报告
    flag = file_report(apikey, "73005a914518706cc67b927c6be89435aa7504fb653e03d5eae17e77501be925", proxies=proxies)
    print(flag)
    # 文件反病毒引擎检测报告
    flag = file_report_multiengines(apikey, "73005a914518706cc67b927c6be89435aa7504fb653e03d5eae17e77501be925", proxies=proxies)
    print(flag)
    # 提交URL分析
    flag = url_scan(apikey, "baidu.com", proxies=proxies)
    print(flag)
    # URL信誉报告
    flag = url_report(apikey, "baidu.com", proxies=proxies)
    print(flag)
    # IP高级查询
    flag = ip_adv_query(apikey, "117.50.162.53", lang="zh", proxies=proxies)
    print(flag)
    # 域名高级查询
    flag = domain_adv_query(apikey, "baidu.com", lang="zh", proxies=proxies)
    print(flag)
    # 子域名查询
    flag = domain_sub_domains(apikey, "baidu.com", lang="zh", proxies=proxies)
    print(flag)
    # 域名上下文
    flag = scene_domain_context(apikey, "baidu.com", lang="zh", proxies=proxies)
    print(flag)
    