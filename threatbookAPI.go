package threatbookAPI

/*
此处为微步在线api的v3版本的接口封装库。
微步在线云API使用文档：https://x.threatbook.com/v5/apiDocs
Github: https://github.com/Chiaki2333/threatbookAPI
*/
//此Golang版本的还没做测试，可能存在bug。

import (
  "io/ioutil"
  "net/http"
  "mime/multipart"
  "bytes"
  "os"
  "io"
)

/******基础接口******/

// IP分析
func Ip_query(apikey string, resource string, exclude string, lang string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("resource", resource)
  writer.WriteField("exclude", exclude)
  //asn,ports,cas,rdns_list,intelligences,judgments,tags_classes,samples,update_time,sum_cur_domains,scene
  writer.WriteField("lang", lang)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/ip/query", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// IP信誉
func Scene_ip_reputation(apikey string, resource string, lang string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("resource", resource)
  writer.WriteField("lang", lang)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/scene/ip_reputation", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// 域名分析
func Domain_query(apikey string, resource string, exclude string, lang string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("resource", resource)
  writer.WriteField("exclude", exclude)
  // cur_ips,cur_whois,cas,intelligences,judgments,tags_classes,categories,sum_sub_domains,sum_cur_ips
  writer.WriteField("lang", lang)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/domain/query", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// 失陷检测
func Scene_dns(apikey string, resource string, lang string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("resource", resource)
  writer.WriteField("lang", lang)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/scene/dns", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}


// 提交文件分析
func FileUpload(apikey string, file string, sandbox_type string, run_time int) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("sandbox_type", sandbox_type)
  /*
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
  */
  writer.WriteField("apikey", apikey)
  writer.WriteField("run_time", string(run_time))	//沙箱运行时间，默认60s，根据需求控制在300s以内
  filename := file
  fw, _ := writer.CreateFormFile("file", filename)
  f, _ := os.Open(filename)
  _, err := io.Copy(fw, f)
  if err != nil {
    //fmt.Println("error when append file", err.Error())
    return err.Error()
  }

  writer.Close()

  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/file/upload", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// 文件信誉报告
func File_report(apikey string, sha256 string, sandbox_type string, query_fields string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("sha256", sha256)
  writer.WriteField("sandbox_type", sandbox_type)
  /*
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
		*/
  writer.WriteField("query_fields", query_fields)
  // summary,network,signature,static,dropped,pstree,multiengines,strings
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/file/report", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// 文件反病毒引擎检测报告
func File_report_multiengines(apikey string, sha256 string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("sha256", sha256)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/file/report/multiengines", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// 提交URL分析
func Url_scan(apikey string, url string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("url", url)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/url/scan", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// URL信誉报告
func Url_report(apikey string, url string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("url", url)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/url/report", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

/******高级接口******/

// IP高级查询
func Ip_adv_query(apikey string, resource string, exclude string, lang string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("resource", resource)
  writer.WriteField("exclude", exclude)
  // asn,cur_domains,history_domains
  writer.WriteField("lang", lang)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/ip/adv_query", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// 子域名查询
func Domain_sub_domains(apikey string, resource string, lang string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("resource", resource)
  writer.WriteField("lang", lang)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/domain/sub_domains", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}

// 域名上下文
func Scene_domain_context(apikey string, resource string, lang string) string {
  body := &bytes.Buffer{}
  writer := multipart.NewWriter(body)
  writer.WriteField("apikey", apikey)
  writer.WriteField("resource", resource)
  writer.WriteField("lang", lang)
  writer.Close()
  
  // Create client
  client := &http.Client{}

  // Create request
  req, err := http.NewRequest("POST", "https://api.threatbook.cn/v3/scene/domain_context", body)

  // Headers
  req.Header.Add("Content-Type", writer.FormDataContentType())

  // Fetch Request
  resp, err := client.Do(req)
  //fmt.Println("ok")

  if err != nil {
    //fmt.Println("Failure : ", err)
	return err.Error()
  }

  // Read Response Body
  respBody, _ := ioutil.ReadAll(resp.Body)

  // Display Results
  //fmt.Println("response Status : ", resp.Status)
  //fmt.Println("response Headers : ", resp.Header)
  //fmt.Println("response Body : ", string(respBody))
  return string(respBody)
}
