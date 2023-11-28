#!/usr/bin/python
# -*- coding: UTF-8 -*-
'''
此处为微步在线api的v3版本的接口封装库的初始化脚本，放置你的微步apikey和代理。
微步在线云API使用文档：https://x.threatbook.com/v5/apiDocs
Github: https://github.com/Chiaki2333/threatbookAPI
'''

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
