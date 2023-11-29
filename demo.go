package main

/*
此处为微步在线api的v3版本的接口封装库。
微步在线云API使用文档：https://x.threatbook.com/v5/apiDocs
Github: https://github.com/Chiaki2333/threatbookAPI
*/

import (
	"fmt"
	"threatbookAPI"
)

func main() {
	/*
	微步在线API Key，登录自己微步获取 https://x.threatbook.com/v5/myApi
	同时在微步上绑定访问IP，微步在线仅接受符合IP来源的API请求。
	*/
	apikey := ""
	flag := ""
	
	// TEST
	
	/******基础接口******/
	// IP分析
	flag = threatbookAPI.Ip_query(apikey, "127.0.0.1", "", "zh")
	fmt.Println(flag)
	// IP信誉
	flag = threatbookAPI.Scene_ip_reputation(apikey, "127.0.0.1", "zh")
	fmt.Println(flag)
	// 域名分析
	flag = threatbookAPI.Domain_query(apikey, "baidu.com", "", "zh")
	fmt.Println(flag)
	// 失陷检测
	flag = threatbookAPI.Scene_dns(apikey, "127.0.0.1", "zh")
	fmt.Println(flag)
	// 提交文件分析
	flag = threatbookAPI.File_upload(apikey, "artifact.exe", "", 60)
	fmt.Println(flag)
	// 文件信誉报告
	flag = threatbookAPI.File_report(apikey, "73005a914518706cc67b927c6be89435aa7504fb653e03d5eae17e77501be925", "", "")
	fmt.Println(flag)
	// 文件反病毒引擎检测报告
	flag = threatbookAPI.File_report_multiengines(apikey, "73005a914518706cc67b927c6be89435aa7504fb653e03d5eae17e77501be925")
	fmt.Println(flag)
	// 提交URL分析
	flag = threatbookAPI.Url_scan(apikey, "baidu.com")
	fmt.Println(flag)
	// URL信誉报告
	flag = threatbookAPI.Url_report(apikey, "baidu.com")
	fmt.Println(flag)
	/******高级接口******/
	// IP高级查询
	flag = threatbookAPI.Ip_adv_query(apikey, "127.0.0.1", "", "zh")
	fmt.Println(flag)
	// 域名高级查询
	flag = threatbookAPI.Domain_adv_query(apikey, "baidu.com", "", "zh")
	fmt.Println(flag)
	// 子域名查询
	flag = threatbookAPI.Domain_sub_domains(apikey, "baidu.com", "zh")
	fmt.Println(flag)
	// 域名上下文
	flag = threatbookAPI.Scene_domain_context(apikey, "baidu.com", "zh")
	fmt.Println(flag)
}

