//go:build linux

package audit_event

import (
	"fmt"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"go.uber.org/zap"
	"os"
	"sec_agent/configs"
	"sec_agent/internal/logger"
	"sec_agent/internal/utils"
	"strconv"
	"strings"
	"time"
)

type AuditMsg struct {
	Type      string `json:"type"`
	Exe       string `json:"exe,omitempty"`
	Pid       string `json:"pid,omitempty"`
	PPid      string `json:"ppid,omitempty"`
	Uid       string `json:"uid,omitempty"`
	User      string `json:"user,omitempty"`
	Family    string `json:"family,omitempty"`
	Addr      string `json:"addr,omitempty"`
	Port      string `json:"port,omitempty"`
	Comm      string `json:"comm,omitempty"`
	Tty       string `json:"tty,omitempty"`
	Logintime string `json:"logintime,omitempty"`
	Account   string `json:"account,omitempty"`
	Result    string `json:"result,omitempty"`
}

func read(amsg *AuditMsg, client *libaudit.AuditClient, ip string) error {
	//delete all rules
	n, _ := client.DeleteRules()
	logger.Logger.Debug("Delete " + strconv.Itoa(n) + " rules")
	//status
	status, err := client.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get audit status: %w", err)
	}
	if status.Enabled == 0 {
		logger.Logger.Debug("enabling auditing in the kernel")
		if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
			return fmt.Errorf("failed to set enabled=true: %w", err)
		}
	}

	if status.RateLimit != uint32(0) {
		//log.Printf("setting rate limit in kernel to %v", 0)
		logger.Logger.Debug("setting rate limit in kernel to 0")
		if err = client.SetRateLimit(uint32(0), libaudit.NoWait); err != nil {
			return fmt.Errorf("failed to set rate limit to unlimited: %w", err)
		}
	}

	if status.BacklogLimit != uint32(8192) {
		//log.Printf("setting backlog limit in kernel to %v", 8192)
		logger.Logger.Debug("setting backlog limit in kernel to 8192")
		if err = client.SetBacklogLimit(uint32(8192), libaudit.NoWait); err != nil {
			return fmt.Errorf("failed to set backlog limit: %w", err)
		}
	}
	//log.Printf("sending message to kernel registering our PID (%v) as the audit daemon", os.Getpid())
	logger.Logger.Debug("sending message to kernel registering our PID (" + strconv.Itoa(os.Getpid()) + ") as the audit daemon")
	if err = client.SetPID(libaudit.NoWait); err != nil {
		return fmt.Errorf("failed to set audit PID: %w", err)
	}

	//build rules
	//-a always,exclude -F msgtype=EOE
	r0, _ := flags.Parse("-a always,exclude -F msgtype=EOE")
	//-a always,exclude -F msgtype=AVC
	r1, _ := flags.Parse("-a always,exclude -F msgtype=AVC")
	r2, _ := flags.Parse("-a always,exclude -F msgtype=CWD")
	r3, _ := flags.Parse("-a always,exclude -F msgtype=PATH")
	// -a always,exit -F arch=b64 -S connect -F a2!=110 -F a2!=42 -F a2!=45
	r4, _ := flags.Parse("-a always,exit -F arch=b64 -S connect -F a2!=110 -F a2!=42 -F a2!=45")
	wireFormat0, err := rule.Build(r0)
	if err != nil {
		return err
	}
	wireFormat1, err := rule.Build(r1)
	if err != nil {
		return err
	}
	wireFormat2, err := rule.Build(r2)
	if err != nil {
		return err
	}
	wireFormat3, err := rule.Build(r3)
	if err != nil {
		return err
	}
	wireFormat4, err := rule.Build(r4)
	if err != nil {
		return err
	}
	//add rules
	_ = client.AddRule(wireFormat0)
	_ = client.AddRule(wireFormat1)
	_ = client.AddRule(wireFormat2)
	_ = client.AddRule(wireFormat3)
	_ = client.AddRule(wireFormat4)
	//log.Println("add rules finished")
	logger.Logger.Debug("add rules finished")
	return receive(amsg, client, ip)
}

func receive(amsg *AuditMsg, client *libaudit.AuditClient, ip string) error {
	var seq, ses, addr string
	msgSlice := make([]map[string]interface{}, 0)
	loginSlice := make([]map[string]interface{}, 0)
	for {
		rawEvent, err := client.Receive(false)
		msgEvent := rawEvent
		if err != nil {
			return fmt.Errorf("receive failed: %w", err)
		}
		//audit type号在合适范围
		if msgEvent.Type < auparse.AUDIT_USER_AUTH ||
			msgEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}
		msgLine := `type=` + msgEvent.Type.String() + ` msg=` + string(msgEvent.Data) + "\n"
		msg, err := auparse.ParseLogLine(msgLine)
		if err != nil {
			return err
		}
		evtMap := msg.ToMapStr()
		//若family为空，则跳过
		if evtMap["record_type"].(string) == "SOCKADDR" {
			_, ok := evtMap["family"]
			if !ok {
				continue
			}
		}
		//SOCKADDR事件，如果family为unix、0，则跳过
		if evtMap["record_type"].(string) == "SOCKADDR" && (evtMap["family"].(string) == "unix" || evtMap["family"].(string) == "0" || evtMap["family"].(string) == "ipv6" || evtMap["family"].(string) == "" || evtMap["addr"] == "127.0.0.1") {
			continue
		}
		//fmt.Println(evtMap)
		//login事件
		if evtMap["record_type"].(string) == "CRED_ACQ" && evtMap["result"].(string) == "success" && evtMap["ses"].(string) != "unset" {
			ses = evtMap["ses"].(string)
			addr = evtMap["addr"].(string)
			loginSlice = append(loginSlice, evtMap)
			continue
		} else if evtMap["record_type"].(string) == "USER_LOGIN" && evtMap["result"].(string) == "success" && evtMap["ses"].(string) == ses && evtMap["addr"].(string) == addr {
			loginSlice = append(loginSlice, evtMap)
			for _, evtm := range loginSlice {
				if evtm["record_type"].(string) == "CRED_ACQ" {
					amsg.Type = "login"
					amsg.Logintime = time.Now().Format("2006-01-02 15:04:05")
					amsg.Account = evtm["acct"].(string)
					amsg.Addr = evtm["addr"].(string)
					amsg.Result = evtm["result"].(string)
				} else if evtm["record_type"].(string) == "USER_LOGIN" {
					amsg.Tty = strings.Trim(evtm["terminal"].(string), "/dev/")
				}
			}
			logger.Logger.Info("auditevent", zap.String("agentVersion", configs.AgentVersion), zap.String("loaderVersion", configs.LoaderVersion), zap.String("localIp", ip), zap.String("eventType", amsg.Type), zap.String("account", amsg.Account), zap.String("time", amsg.Logintime), zap.String("remoteIp", amsg.Addr), zap.String("result", amsg.Result), zap.String("tty", amsg.Tty))
			amsg = new(AuditMsg)
			loginSlice = make([]map[string]interface{}, 0)
			ses = ""
			addr = ""
			continue
		}
		//connect syscall事件合并
		if evtMap["sequence"].(string) == seq {
			//继续添加
			msgSlice = append(msgSlice, evtMap)
		} else {
			seq = evtMap["sequence"].(string)
			if len(msgSlice) > 0 && strings.Contains(fmt.Sprint(msgSlice), "record_type:SYSCALL") && strings.Contains(fmt.Sprint(msgSlice), "record_type:SOCKADDR") && strings.Contains(fmt.Sprint(msgSlice), "record_type:PROCTITLE") {
				//if strings.Contains(fmt.Sprint(msgSlice), "record_type:SYSCALL") {
				for _, evtm := range msgSlice {
					if evtm["record_type"].(string) == "SYSCALL" {
						//添加过滤exe
						if utils.ProcFilter(evtm["exe"].(string), utils.ExecFilter) {
							break
						}
						amsg.Type = "Connect"
						amsg.Uid = evtm["uid"].(string)
						//user
						user, ok := utils.UserMap[evtm["uid"].(string)]
						if ok {
							amsg.User = user
						} else {
							user = utils.GetUser(evtm["uid"].(string))
							amsg.User = user
							utils.UserMap[evtm["uid"].(string)] = user
						}
						amsg.Exe = evtm["exe"].(string)
						amsg.Pid = evtm["pid"].(string)
						amsg.PPid = evtm["ppid"].(string)
						amsg.Tty = evtm["tty"].(string)
					} else if evtm["record_type"] == "SOCKADDR" {
						amsg.Family = evtm["family"].(string)
						if _, ok := evtm["addr"].(string); ok {
							amsg.Addr = evtm["addr"].(string)
						} else {
							amsg.Addr = ""
						}
						if _, ok := evtm["port"].(string); ok {
							amsg.Port = evtm["port"].(string)
						} else {
							amsg.Port = ""
						}
					} else if evtm["record_type"] == "PROCTITLE" {
						if amsg.Exe != "" {
							if utils.ArgFilter(amsg.Exe, evtm["proctitle"].(string), utils.ArgsFilter) {
								break
							}
						}
						amsg.Comm = evtm["proctitle"].(string)
					}
				}
				//日志过滤
				if amsg.Exe != "" && amsg.Comm != "" {
					logger.Logger.Info("auditevent", zap.String("agentVersion", configs.AgentVersion), zap.String("loaderVersion", configs.LoaderVersion), zap.String("localIp", ip), zap.String("eventType", amsg.Type), zap.String("uid", amsg.Uid), zap.String("user", amsg.User), zap.String("exec", amsg.Exe), zap.String("pid", amsg.Pid), zap.String("ppid", amsg.PPid), zap.String("tty", amsg.Tty), zap.String("family", amsg.Family), zap.String("remoteIp", amsg.Addr), zap.String("port", amsg.Port), zap.String("fullcommand", amsg.Comm))
				}

				amsg = new(AuditMsg)
				msgSlice = make([]map[string]interface{}, 0)
				//?
				msgSlice = append(msgSlice, evtMap)
			} else {
				amsg = new(AuditMsg)
				msgSlice = make([]map[string]interface{}, 0)

				msgSlice = append(msgSlice, evtMap)
			}
		}
	}
}
