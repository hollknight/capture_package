package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Info struct {
	Ip          string `json:"ip"`
	Pro         string `json:"pro"`
	ProCode     string `json:"proCode"`
	City        string `json:"city"`
	CityCode    string `json:"cityCode"`
	Region      string `json:"region"`
	RegionCode  string `json:"regionCode"`
	Addr        string `json:"addr"`
	RegionNames string `json:"regionNames"`
	Err         string `json:"err"`
}

func IP2Add(ip string) (string, error) {
	url := fmt.Sprintf("http://whois.pconline.com.cn/ipJson.jsp?ip=%s&json=true", ip)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	data, err = GBK2UTF8(data)
	//fmt.Println(data)
	info := new(Info)
	err = json.Unmarshal(data, info)
	if err != nil {
		return "", err
	}

	return info.Pro, err
}
