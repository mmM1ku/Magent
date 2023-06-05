package asset

import (
	"sec_agent/internal/asset/croninfo"
	"sec_agent/internal/asset/netinfo"
	"sec_agent/internal/asset/pkginfo"
	"sec_agent/internal/asset/processinfo"
	"sec_agent/internal/asset/systemdinfo"
	"sec_agent/internal/asset/userinfo"
)

func AllTask(ip, osPlatform string) {
	//用户信息
	userinfo.Task(ip)
	//进程信息
	processinfo.Task(ip)
	//网络信息
	netinfo.Task(ip)
	//cron信息
	croninfo.Task(ip)
	//service信息
	systemdinfo.Task(ip)
	//pkg信息
	pkginfo.Task(ip, osPlatform)
}
