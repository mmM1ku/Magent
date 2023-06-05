package utils

import (
	"github.com/robfig/cron/v3"
	"sec_agent/internal/asset/croninfo"
	"sec_agent/internal/asset/netinfo"
	"sec_agent/internal/asset/pkginfo"
	"sec_agent/internal/asset/processinfo"
	"sec_agent/internal/asset/systemdinfo"
	"sec_agent/internal/asset/userinfo"
)

func CronInit(ip, osPlatform string) {
	c := cron.New()
	//每小时任务
	c.AddFunc("0 */6 * * *", func() {
		processinfo.Task(ip)
		netinfo.Task(ip)
	})
	//每12小时任务
	c.AddFunc("0 */12 * * *", func() {
		userinfo.Task(ip)
		croninfo.Task(ip)
		systemdinfo.Task(ip)
		pkginfo.Task(ip, osPlatform)
	})
	c.Start()
}
