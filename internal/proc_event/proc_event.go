package proc_event

import (
	"github.com/elastic/go-sysinfo"
	"go.uber.org/zap"
	"os/user"
	"sec_agent/configs"
	"sec_agent/internal/logger"
	"sec_agent/internal/utils"
	"strconv"
	"strings"
	"time"
)

func ProcEvents(ip string) {
	//延迟启动proc事件模块，避免同时通过netlink发送消息而冲突
	time.Sleep(10 * time.Second)
	//创建uid:user Map
	//userMap := make(map[string]string, 20)
	var name string
	//proc_event comm会报错，暂时去除
	cn, err := DialPCNWithEvents([]EventType{ProcEventExec, ProcEventFork})
	if err != nil {
		logger.Logger.Error("proc events dail failed", zap.String("error", err.Error()))
	}
	defer cn.ClosePCN()
	for {
		data, err := cn.ReadPCN()
		if err != nil {
			logger.Logger.Error("read netlink msg failed", zap.String("error", err.Error()))
		}
		// 注意：pid->proc存在空指针的问题，可能导致panic
		for _, ev := range data {
			//fmt.Printf("ev: %v\n", ev)
			if ev.WhatString == "Exec" {
				proc, _ := sysinfo.Process(int(ev.EventData.(Exec).ProcessPid))
				if proc == nil {
					continue
				}
				pinfo, _ := proc.Info()
				if pinfo.Name == "" {
					continue
				}
				//过滤进程
				if utils.ProcFilter(pinfo.Exe, utils.ExecFilter) {
					continue
				}
				//过滤参数
				if utils.ArgFilter(pinfo.Exe, strings.Join(pinfo.Args, ","), utils.ArgsFilter) {
					continue
				}
				pid := pinfo.PID
				uid := utils.GetLoginUID(strconv.Itoa(pid))
				if uid == "" {
					name = ""
				} else {
					mapUser, ok := utils.UserMap[uid]
					if ok {
						name = mapUser
					} else {
						username, err := user.LookupId(uid)
						if err != nil {
							name = utils.GetUser(uid)
							utils.UserMap[uid] = name
						} else {
							name = username.Username
							utils.UserMap[uid] = name
						}
					}
				}
				if pinfo.Exe != "" && len(pinfo.Args) != 0 {
					argStr := strings.Join(pinfo.Args, " ")
					logger.Logger.Info("procevent", zap.String("agentVersion", configs.AgentVersion), zap.String("loaderVersion", configs.LoaderVersion), zap.String("localIp", ip), zap.String("eventType", ev.WhatString), zap.String("startTime", pinfo.StartTime.String()), zap.Uint32("pid", ev.EventData.(Exec).ProcessPid), zap.Uint32("tgid", ev.EventData.(Exec).ProcessTgid), zap.String("user", name), zap.String("uid", uid), zap.String("procName", pinfo.Name), zap.String("exec", pinfo.Exe), zap.String("args", argStr), zap.String("cwd", pinfo.CWD))
				}
			}
			if ev.WhatString == "Fork" {
				proc, _ := sysinfo.Process(int(ev.EventData.(Fork).ChildPid))
				if proc == nil {
					continue
				}
				pinfo, _ := proc.Info()
				if pinfo.Name == "" {
					continue
				}
				//过滤进程
				if utils.ProcFilter(pinfo.Exe, utils.ExecFilter) {
					continue
				}
				//过滤参数
				if utils.ArgFilter(pinfo.Exe, strings.Join(pinfo.Args, ","), utils.ArgsFilter) {
					continue
				}
				pid := pinfo.PID
				uid := utils.GetLoginUID(strconv.Itoa(pid))
				if uid == "" {
					name = ""
				} else {
					mapUser, ok := utils.UserMap[uid]
					if ok {
						name = mapUser
					} else {
						username, err := user.LookupId(uid)
						if err != nil {
							name = utils.GetUser(uid)
							utils.UserMap[uid] = name
						} else {
							name = username.Username
							utils.UserMap[uid] = name
						}
					}
				}
				if pinfo.Exe != "" && len(pinfo.Args) != 0 {
					argStr := strings.Join(pinfo.Args, " ")
					logger.Logger.Info("procevent", zap.String("agentVersion", configs.AgentVersion), zap.String("loaderVersion", configs.LoaderVersion), zap.String("localIp", ip), zap.String("eventType", ev.WhatString), zap.String("startTime", pinfo.StartTime.String()), zap.Uint32("pid", ev.EventData.(Fork).ChildPid), zap.Uint32("tgid", ev.EventData.(Fork).ChildTgid), zap.Uint32("ppid", ev.EventData.(Fork).ParentPid), zap.Uint32("ptgid", ev.EventData.(Fork).ParentTgid), zap.String("user", name), zap.String("uid", uid), zap.String("procName", pinfo.Name), zap.String("exec", pinfo.Exe), zap.String("args", argStr), zap.String("cwd", pinfo.CWD))
				}
			}
		}
	}
}
