#!/usr/bin/python
# -*- coding: UTF-8 -*-
'''
此处为微步在线api的v3版本的接口封装。
微步在线云API使用文档：https://x.threatbook.com/v5/apiDocs
'''

import sys
import os
import requests

####### 基础接口 #######

# IP分析
def ip_query(apikey, resource, exclude="asn,ports,cas,rdns_list,intelligences,judgments,tags_classes,samples,update_time,sum_cur_domains,scene", lang="en", proxies=""):
    url = "https://api.threatbook.cn/v3/ip/query"

    query = {
      "apikey":apikey,
      "resource":resource,
      "exclude":exclude,
      "lang":lang
    }

    response = requests.request("POST", url, params=query, proxies=proxies)

    return(response.json())

# IP信誉
def scene_ip_reputation(apikey, resource, lang="en", proxies=""):
    url = "https://api.threatbook.cn/v3/scene/ip_reputation"

    query = {
      "apikey":apikey,
      "resource":resource,
      "lang":lang
    }

    response = requests.request("POST", url, params=query, proxies=proxies)

    return(response.json())


# 域名分析
def domain_query(apikey, resource, exclude="cur_ips,cur_whois,cas,intelligences,judgments,tags_classes,categories,sum_sub_domains,sum_cur_ips", lang="en", proxies=""):
    url = "https://api.threatbook.cn/v3/domain/query"

    query = {
      "apikey":apikey,
      "resource":resource,
      "exclude":exclude,
      "lang":lang
    }

    response = requests.request("POST", url, params=query, proxies=proxies)

    return(response.json())

# 失陷检测
def scene_dns(apikey, resource, lang="en", proxies=""): 
    url = "https://api.threatbook.cn/v3/scene/dns"

    query = {
      "apikey":apikey,
      "resource":resource,
      "lang":lang
    }

    response = requests.request("POST", url, params=query, proxies=proxies)

    return(response.json())

# 提交文件分析
def file_upload(apikey, file, sandbox_type="", run_time=60, proxies=""):
    url = 'https://api.threatbook.cn/v3/file/upload';
    fields = {
        'apikey': apikey,
        'sandbox_type': sandbox_type,
        #Windows
        #win7_sp1_enx64_office2013
        #win7_sp1_enx86_office2013
        #win7_sp1_enx86_office2010
        #win7_sp1_enx86_office2007
        #win7_sp1_enx86_office2003
        #win10_1903_enx64_office2016
        #Linux
        #ubuntu_1704_x64
        #centos_7_x64
        #Kylin
        #kylin_desktop_v10
        'run_time': run_time    # 沙箱运行时间，默认60s，根据需求控制在300s以内
    }
    files = {
      'file' : (os.path.basename(file), open(file, 'rb'))
    }
    response = requests.post(url, data=fields, files=files, proxies=proxies)
    return(response.json())

# 文件信誉报告
def file_report(apikey, sha256, sandbox_type="", query_fields="summary,network,signature,static,dropped,pstree,multiengines,strings", proxies=""):
    url = 'https://api.threatbook.cn/v3/file/report'
    params = {
        'apikey': apikey,
        'sandbox_type': sandbox_type,
        #Windows
        #win7_sp1_enx64_office2013
        #win7_sp1_enx86_office2013
        #win7_sp1_enx86_office2010
        #win7_sp1_enx86_office2007
        #win7_sp1_enx86_office2003
        #win10_1903_enx64_office2016
        #Linux
        #ubuntu_1704_x64
        #centos_7_x64
        #Kylin
        #kylin_desktop_v10
        'sha256': sha256    # 文件的 sha256 值，用于获取分析报告。为方便查询报告，sha256 可以替换成 md5 或 sha1。
    }
    response = requests.post(url, params=params, proxies=proxies)
    return(response.json())

# 文件反病毒引擎检测报告
def file_report_multiengines(apikey, sha256, proxies=""):
    url = 'https://api.threatbook.cn/v3/file/report/multiengines'
    params = {
        'apikey': apikey,
        'sha256': sha256
    }
    response = requests.post(url, params=params, proxies=proxies)
    return(response.json())

# 提交URL分析
def url_scan(apikey, url, proxies=""):
    url = "https://api.threatbook.cn/v3/url/scan"
    data = {
      "apikey": apikey,
      "url": url
    }
    response = requests.post(url, data=data, proxies=proxies)
    return(response.json())

# URL信誉报告
def url_report(apikey, url, proxies=""):
    url = "https://api.threatbook.cn/v3/url/report"
    params = {
      "apikey": apikey,
      "url": url
    }
    response = requests.post(url, params=params, proxies=proxies)
    return(response.json())

####### 高级接口 #######

# IP高级查询
def ip_adv_query(apikey, resource, exclude="asn,cur_domains,history_domains", lang="en", proxies=""):
    url = "https://api.threatbook.cn/v3/ip/adv_query"

    query = {
      "apikey":apikey,
      "resource":resource,
      "exclude":exclude,
      "lang":lang
    }

    response = requests.request("POST", url, params=query, proxies=proxies)

    return(response.json())

# 域名高级查询
def domain_adv_query(apikey, resource, exclude="history_ips,history_whoises", lang="en", proxies=""):
    url = "https://api.threatbook.cn/v3/domain/adv_query"

    query = {
      "apikey":apikey,
      "resource":resource,
      "exclude":exclude,
      "lang":lang
    }

    response = requests.request("POST", url, params=query, proxies=proxies)

    return(response.json())

# 子域名查询
def domain_sub_domains(apikey, resource, lang="en", proxies=""):
    url = "https://api.threatbook.cn/v3/domain/sub_domains"

    query = {
      "apikey":apikey,
      "resource":resource,
      "lang":lang
    }

    response = requests.request("POST", url, params=query, proxies=proxies)

    return(response.json())

# 域名上下文
def scene_domain_context(apikey, resource, lang="en", proxies=""):
    url = "https://api.threatbook.cn/v3/scene/domain_context"

    query = {
      "apikey":apikey,
      "resource":resource,
      "lang":lang
    }

    response = requests.request("GET", url, params=query, proxies=proxies)

    return(response.json())



#测试代码：
'''
apikey = ""
proxies = {
    'http': '',
    'https': ''
}
#flag = ip_query(apikey, "117.50.162.53", lang="zh", proxies=proxies)
#flag = scene_ip_reputation(apikey, "117.50.162.53", lang="zh", proxies=proxies)
#flag = domain_query(apikey, "baidu.com", lang="zh", proxies=proxies)
#flag = scene_dns(apikey, "117.50.162.53", lang="zh", proxies="")
#flag = file_upload(apikey, "artifact.exe", proxies=proxies)
#flag = file_report(apikey, "73005a914518706cc67b927c6be89435aa7504fb653e03d5eae17e77501be925", proxies=proxies)
#flag = file_report_multiengines(apikey, "73005a914518706cc67b927c6be89435aa7504fb653e03d5eae17e77501be925", proxies=proxies)
#flag = url_scan(apikey, "baidu.com", proxies=proxies)
#flag = url_report(apikey, "baidu.com", proxies=proxies)
#flag = ip_adv_query(apikey, "117.50.162.53", lang="zh", proxies=proxies)
#flag = domain_adv_query(apikey, "baidu.com", lang="zh", proxies=proxies)
#flag = domain_sub_domains(apikey, "baidu.com", lang="zh", proxies=proxies)
#flag = scene_domain_context(apikey, "baidu.com", lang="zh", proxies=proxies)
#print(flag)
'''