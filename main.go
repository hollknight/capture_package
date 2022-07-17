package main

import (
	"capture_package/util"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

type ipInfo struct {
	address    string
	srcFlowNum int
	dstFlowNum int
}

func main() {
	localIPAddress, err := getLocalIPAddress()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Print("请输入抓包数量：")
	num := 0
	fmt.Scan(&num)
	resMap := capturePackage("wlo1", localIPAddress, 1024, false, 30*time.Second, num)

	fmt.Println("-------------------------------------------------")
	for ip, info := range resMap {
		fmt.Printf("ip 地址：%s\nip 归属地：%s\n发送网络包次数：%d\n接收网络包次数：%d\n\n", ip, info.address, info.srcFlowNum, info.dstFlowNum)
	}
}

// 监听模式下抓包
func capturePackage(device, localIP string, snapshotLen int32, promiscuous bool, timeout time.Duration, maxNum int) map[string]*ipInfo {
	// 打开某一网络设备
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("开始抓包")

	flowMap := make(map[string]*ipInfo)
	flowMap[localIP] = &ipInfo{
		address:    "本机局域网ip",
		srcFlowNum: 0,
		dstFlowNum: 0,
	}

	num := 0
	for packet := range packetSource.Packets() {
		srcIP, dstIP, err := getIPs(packet)
		if err != nil {
			fmt.Println(err)
		}

		// 查询 ip 信息网站域名对应 ip 地址，直接跳过
		if srcIP == "115.223.7.10" || dstIP == "115.223.7.10" {
			continue
		}

		srcPro, err := util.IP2Add(srcIP)
		dstPro, err := util.IP2Add(dstIP)
		if srcPro == "" {
			if srcIP == localIP {
				srcPro = "本机"
			} else {
				srcPro = "无法分析归属地"
			}
		}
		if dstPro == "" {
			if dstIP == localIP {
				dstPro = "本机"
			} else {
				dstPro = "无法分析归属地"
			}
		}

		if srcPro == "无法分析归属地" && dstPro == "无法分析归属地" {
			fmt.Println(srcPro + "\t->\t" + dstPro + "\t||\t" + srcIP + "\t->    " + dstIP)
		} else if srcPro == "无法分析归属地" {
			fmt.Println(srcPro + "\t->\t" + dstPro + "\t\t||\t" + srcIP + "\t->    " + dstIP)
		} else if dstPro == "无法分析归属地" {
			fmt.Println(srcPro + "\t\t->\t" + dstPro + "\t||\t" + srcIP + "\t->    " + dstIP)
		} else {
			fmt.Println(srcPro + "\t\t->\t" + dstPro + "\t\t||\t" + srcIP + "\t->    " + dstIP)
		}

		if _, ok := flowMap[srcIP]; ok {
			(*flowMap[srcIP]).srcFlowNum++
		} else {
			flowMap[srcIP] = &ipInfo{
				address:    srcPro,
				srcFlowNum: 1,
				dstFlowNum: 0,
			}
		}
		if _, ok := flowMap[dstIP]; ok {
			(*flowMap[dstIP]).dstFlowNum++
		} else {
			flowMap[dstIP] = &ipInfo{
				address:    dstPro,
				srcFlowNum: 0,
				dstFlowNum: 1,
			}
		}

		num++
		if num >= maxNum {
			break
		}
	}

	return flowMap
}

// 获取 ip 数据包
func getIPs(packet gopacket.Packet) (string, string, error) {
	// 判断数据包是否为IP数据包，可解析出源ip、目的ip、协议号等
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP

		return ip.SrcIP.String(), ip.DstIP.String(), nil
	}

	// Check for errors
	// 判断layer是否存在错误
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return "", "", errors.New("layer存在错误")
}

// 获取本机 ip 地址
func getLocalIPAddress() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", errors.New("获取本地ip失败")
}
