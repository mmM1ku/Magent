package main

import (
	"sec_agent/internal/asset/hostinfo"
	"sec_agent/internal/audit_event"
	"sec_agent/internal/inits"
	"sec_agent/internal/proc_event"
	"sec_agent/internal/utils"
	"sec_agent/pkg/etcd"
)

func main() {
	//inits 初始化
	inits.InitAgent()
	//运行audit模块
	go audit_event.Client.AuditEvents()
	//运行proc模块
	go proc_event.ProcEvents(hostinfo.Info.IpAddr[0])
	//运行计划任务
	go utils.CronInit(hostinfo.Info.IpAddr[0], hostinfo.Info.OsPlatform)
	//运行etcd模块
	etcd.Cli.AgentTask()
}
