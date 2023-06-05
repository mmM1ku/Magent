package hostinfo

import (
	"github.com/elastic/go-sysinfo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"net/netip"
	"os/exec"
	"sec_agent/internal/logger"
	"strings"
)

// Host 该结构体存储如下信息：
//
// * hostName 主机名
//
// * osInfo 系统类型及版本号，如macOS 12.4
//
// * architecture 系统架构，如amd64
//
// * kernelVersion 内核版本
//
// * ipAddr ip地址切片，只过滤内网ip(10.*)
type Host struct {
	HostName   string
	OsPlatform string
	OsName     string
	//OsVersion     string
	MajVersion    int
	MinVersion    int
	Architecture  string
	KernelVersion string
	IpAddr        []string
}

var Info, _ = Task()

func (h *Host) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddString("hostName", h.HostName)
	encoder.AddString("osPlatform", h.OsPlatform)
	encoder.AddString("osName", h.OsName)
	encoder.AddInt("majorVersion", h.MajVersion)
	encoder.AddInt("minorVersion", h.MinVersion)
	encoder.AddString("arch", h.Architecture)
	encoder.AddString("kernel", h.KernelVersion)
	encoder.AddString("ip", h.IpAddr[0])
	return nil
}

func HostInfo() (*Host, error) {
	info := new(Host)
	host, err := sysinfo.Host()
	if err != nil {
		return nil, err
	}
	info.HostName = host.Info().Hostname
	info.OsPlatform = host.Info().OS.Platform
	info.Architecture = host.Info().Architecture
	info.OsName = host.Info().OS.Name
	//info.OsVersion = host.Info().OS.Version
	info.MajVersion = host.Info().OS.Major
	info.MinVersion = host.Info().OS.Minor
	info.KernelVersion = host.Info().KernelVersion
	ips := host.Info().IPs
	//改用1.18新版匹配ip cidr的方式匹配
	network, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		//return nil, err
	}
	//应使用出网ip作为agent ip
	//使用ip route get 10.8.8.8作为出网测试
	cmd := "ip route get 10.8.8.8 | head -1 | gawk '{ print $7 }'"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		//如果该命令执行出错，则使用lib库去获取本机ip
		//遍历所有10.*的内网地址,不再使用正则匹配方式
		for _, ip := range ips {
			realip := strings.Split(ip, "/")[0]
			parseip, err := netip.ParseAddr(realip)
			if err != nil {
				continue
			}
			if network.Contains(parseip) {
				info.IpAddr = append(info.IpAddr, realip)
			}
		}
		return info, nil
	}
	//去除空格和换行符
	ipstr := strings.Replace(string(out), "\n", "", -1)
	ipstr = strings.Replace(ipstr, " ", "", -1)
	parseip, err := netip.ParseAddr(ipstr)
	//如果ip不是一个合法的ip
	if err != nil {
		for _, ip := range ips {
			realip := strings.Split(ip, "/")[0]
			parseip, err := netip.ParseAddr(realip)
			if err != nil {
				continue
			}
			if network.Contains(parseip) {
				info.IpAddr = append(info.IpAddr, realip)
			}
		}
		return info, nil
	}
	//如果该出网地址是10.*的内网地址，
	if network.Contains(parseip) {
		info.IpAddr = append(info.IpAddr, ipstr)
	}
	return info, nil
}

func Task() (*Host, error) {
	//主机通用信息
	hostInfo, err := HostInfo()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	//log.Printf("hostname: %s, os: %s:%v.%v, arch: %s, kernel: %s, ip: %v\n", hostInfo.HostName, hostInfo.OsPlatform, hostInfo.MajVersion, hostInfo.MinVersion, hostInfo.Architecture, hostInfo.KernelVersion, hostInfo.IpAddr)
	logger.Logger.Info("sysinfo", zap.String("infoType", "hostinfo"), zap.Object("info", hostInfo))
	return hostInfo, nil
}
