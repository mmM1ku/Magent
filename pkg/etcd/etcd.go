package etcd

import (
	"embed"
	"fmt"
	"github.com/tidwall/gjson"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"math/rand"
	"net/netip"
	"os"
	"os/exec"
	"sec_agent/configs"
	"sec_agent/internal/asset/hostinfo"
	"sec_agent/internal/audit_event"
	"sec_agent/internal/logger"
	"sec_agent/internal/risk"
	"sec_agent/internal/utils"
	"strconv"
	"strings"
	"sync"
	"time"
)

type EtcdConfig struct {
	LoaderVersion string
	AgentVersion  string
	FalcoVersion  string
	Group         string
	AgentSwitch   bool
	FalcoSwitch   bool
	AgentFile     string
	ConfVersion   string
	ChildProcess  exec.Cmd
	ProcessStatus bool
	EtcdIp        []string
	ServerInfo    *hostinfo.Host
	Timeout       time.Duration
	ServerIP      string
	OsPlatform    string
	Client        *clientv3.Client
	Audit         *audit_event.Audit
	LeaseID       clientv3.LeaseID
}

var Cli = EtcdNew(configs.LoaderVersion, configs.AgentVersion, configs.FalcoVersion, configs.EtcdCluster, hostinfo.Info, configs.EtcdTimeout, audit_event.Client)

func EtcdNew(loaderVersion, agentVersion, falcoVersion string, etcdip []string, serverinfo *hostinfo.Host, timeout time.Duration, audit *audit_event.Audit) *EtcdConfig {
	cli, _ := clientv3.New(clientv3.Config{
		Endpoints:   etcdip,
		DialTimeout: timeout,
		Username:    "", //etcd用户名
		Password:    "", //etcd密码
	})
	return &EtcdConfig{
		LoaderVersion: loaderVersion,
		AgentVersion:  agentVersion,
		FalcoVersion:  falcoVersion,
		Group:         "default",
		EtcdIp:        etcdip,
		ServerInfo:    serverinfo,
		Timeout:       timeout,
		ServerIP:      serverinfo.IpAddr[0],
		OsPlatform:    serverinfo.OsPlatform,
		Audit:         audit,
		Client:        cli,
	}
}

func (e *EtcdConfig) CloseClient() error {
	return e.Client.Close()
}

func (e *EtcdConfig) GetLoaderConf() {
	kv := clientv3.NewKV(e.Client)
	resp, err := kv.Get(context.TODO(), "/secagent/loader/conf/container")
	if err != nil {
		logger.Logger.Error("get loader module conf error", zap.String("error", err.Error()))
	}
	//判断key是否存在
	if resp.Count > 0 {
		conf := resp.Kvs[0].Value
		containerList := gjson.GetBytes(conf, "container.iplist")
		confVersion := gjson.GetBytes(conf, "container.confVersion")
		if len(containerList.Array()) > 0 {
			containerList.ForEach(func(key, value gjson.Result) bool {
				if value.String() == e.ServerIP {
					e.Group = "container"
					e.AgentSwitch = false
					e.FalcoSwitch = true
					e.ConfVersion = confVersion.String()
					//todo 下载conf到本地
				}
				return true
			})
		} else {
			e.AgentSwitch = true
			e.FalcoSwitch = false
			e.ConfVersion = confVersion.String()
		}
	} else {
		e.AgentSwitch = true
		e.FalcoSwitch = false
	}
}

func (e *EtcdConfig) RegisLoader() error {
	//申请新租约
	lease := clientv3.NewLease(e.Client)
	leaseGran, err := lease.Grant(context.TODO(), 20)
	if err != nil {
		logger.Logger.Error("grant lease error", zap.String("error", err.Error()))
		return err
	}
	//获取租约id
	e.LeaseID = leaseGran.ID
	//创建新kv
	kv := clientv3.NewKV(e.Client)
	//无论之前是否注册，loader启动后，都会写入最新的loader信息和状态信息
	//写入loader信息
	regtime := time.Now().Format("2006-01-02 15:04:05")
	info := `{"hostName":"` + e.ServerInfo.HostName + `","ip":"` + e.ServerIP + `","group":"` + e.Group + `","regTime":"` + regtime + `","loaderVersion":"` + e.LoaderVersion + `","agentVersion":"` + e.AgentVersion + `","falcoVersion":"` + e.FalcoVersion + `"}`
	infoResp, err := kv.Put(context.TODO(), "/secagent/loader/infos/"+e.ServerIP, info)
	logger.Logger.Debug("hostinfo写入成功", zap.Int64("Resp Revision", infoResp.Header.Revision))
	//写入status
	status := `{"loaderStatus": "online", "agentStatus": "` + strconv.FormatBool(e.ProcessStatus) + `"}`
	statusResp, err := kv.Put(context.TODO(), "/secagent/loader/status/"+e.ServerIP, status, clientv3.WithLease(e.LeaseID))
	if err != nil {
		logger.Logger.Error("put status error", zap.String("error", err.Error()))
		return err
	}
	logger.Logger.Debug("status写入成功", zap.Int64("Resp Revision", statusResp.Header.Revision))
	return nil
}

func (e *EtcdConfig) KeepAlive() error {
	lease := clientv3.NewLease(e.Client)
	keepRespChan, err := lease.KeepAlive(context.TODO(), e.LeaseID)
	if err != nil {
		logger.Logger.Error("lease keepalive error", zap.String("ip", e.ServerIP), zap.String("error", err.Error()))
		return err
	}
	for {
		select {
		case keepResp := <-keepRespChan:
			if keepResp == nil {
				err := fmt.Errorf("租约已关闭")
				logger.Logger.Error(err.Error(), zap.String("ip", e.ServerIP))
				return err
			} else {
				time.Sleep(500 * time.Millisecond)
			}
		}

	}
}

func (e *EtcdConfig) LoaderMonitor() {
	var wg sync.WaitGroup
	wg.Add(3)
	kv := clientv3.NewKV(e.Client)
	watcher := clientv3.NewWatcher(e.Client)
	//loader conf 监控
	//1.container配置监控
	//key:/secagent/loader/conf/container
	go func() {
		getResp, err := kv.Get(context.TODO(), "/secagent/loader/conf/container")
		if err != nil {
			logger.Logger.Error("get container conf error", zap.String("error", err.Error()))
		}
		watchStartRevision := getResp.Header.Revision + 1
		watchChan := watcher.Watch(context.TODO(), "/secagent/loader/conf/container", clientv3.WithRev(watchStartRevision))
		for watchResp := range watchChan {
			for _, event := range watchResp.Events {
				switch event.Type {
				case mvccpb.PUT:
					newJson := event.Kv.Value
					fmt.Println(string(newJson))
					if e.Group != "container" {
						ipList := gjson.GetBytes(newJson, "container.iplist")
						if len(ipList.Array()) > 0 {
							ipList.ForEach(func(key, value gjson.Result) bool {
								if value.String() == e.ServerIP {
									e.Group = "container"
									e.AgentSwitch = false
									e.FalcoSwitch = true
								}
								return true
							})
						}
					}
					if e.Group == "container" {
						confVersion := gjson.GetBytes(newJson, "container.confVersion")
						if confVersion.String() != e.ConfVersion {
							e.ConfVersion = confVersion.String()
							//todo 解析confURL并下载新配置文件
						}
					}
				}
			}
		}
		wg.Done()
	}()
	//2.处理进程启停
	//key:/secagent/loader/conf/manage
	go func() {
		getResp, err := kv.Get(context.TODO(), "/secagent/loader/conf/manage")
		if err != nil {
			logger.Logger.Error("get manage conf error", zap.String("error", err.Error()))
		}
		watchStartRevision := getResp.Header.Revision + 1
		watchChan := watcher.Watch(context.TODO(), "/secagent/loader/conf/manage", clientv3.WithRev(watchStartRevision))
		for watchResp := range watchChan {
			for _, event := range watchResp.Events {
				switch event.Type {
				case mvccpb.PUT:
					newJson := event.Kv.Value
					fmt.Println(string(newJson))
					kind := gjson.GetBytes(newJson, "kind")
					target := gjson.GetBytes(newJson, "target")
					//kind类型：1.ip 2.list 3.cidr 4.group 5.all
					if kind.String() == "ip" {
						if e.ServerIP == target.String() {
							action := gjson.GetBytes(newJson, "action")
							fmt.Println(action.String())
							if action.String() == "on" {
								fmt.Println(e.Group)
								if e.Group == "default" {
									fmt.Println(strconv.FormatBool(e.ProcessStatus))
									if !e.ProcessStatus {
										e.ChildProcess = utils.ChildProcessStart(e.AgentFile)
										logger.Logger.Debug("remote start child process", zap.Int("pid", e.ChildProcess.Process.Pid))
										e.AgentSwitch = true
									}
								} else {
									//todo
									e.FalcoSwitch = true
								}
							} else if action.String() == "off" {
								fmt.Println("action off")
								logger.Logger.Debug("remote stop child process", zap.Int("pid", e.ChildProcess.Process.Pid))
								utils.ChildProcessStop(e.ChildProcess)
								if e.Group == "default" {
									e.AgentSwitch = false
								} else {
									e.FalcoSwitch = false
								}
							}
						}
					} else if kind.String() == "list" {
						ips := strings.Split(target.String(), ",")
						if utils.SliceFind(ips, e.ServerIP) {
							action := gjson.GetBytes(newJson, "action")
							fmt.Println(action.String())
							if action.String() == "on" {
								fmt.Println(e.Group)
								if e.Group == "default" {
									fmt.Println(strconv.FormatBool(e.ProcessStatus))
									if !e.ProcessStatus {
										e.ChildProcess = utils.ChildProcessStart(e.AgentFile)
										logger.Logger.Debug("remote start child process", zap.Int("pid", e.ChildProcess.Process.Pid))
										e.AgentSwitch = true
									}
								} else {
									//todo
									e.FalcoSwitch = true
								}
							} else if action.String() == "off" {
								fmt.Println("action off")
								logger.Logger.Debug("remote stop child process", zap.Int("pid", e.ChildProcess.Process.Pid))
								utils.ChildProcessStop(e.ChildProcess)
								if e.Group == "default" {
									e.AgentSwitch = false
								} else {
									e.FalcoSwitch = false
								}
							}
						}
					} else if kind.String() == "cidr" {
						network, _ := netip.ParsePrefix(target.String())
						ip, _ := netip.ParseAddr(e.ServerIP)
						if network.Contains(ip) {
							action := gjson.GetBytes(newJson, "action")
							if action.String() == "on" {
								if e.Group == "default" {
									if !e.ProcessStatus {
										e.ChildProcess = utils.ChildProcessStart(e.AgentFile)
										logger.Logger.Debug("remote start child process", zap.Int("pid", e.ChildProcess.Process.Pid))
										e.AgentSwitch = true
									}
								} else {
									//todo
									e.FalcoSwitch = true
								}
							} else if action.String() == "off" {
								logger.Logger.Debug("remote stop child process", zap.Int("pid", e.ChildProcess.Process.Pid))
								utils.ChildProcessStop(e.ChildProcess)
								if e.Group == "default" {
									e.AgentSwitch = false
								} else {
									e.FalcoSwitch = false
								}
							}
						}
					} else if kind.String() == "group" {
						if e.Group == target.String() {
							action := gjson.GetBytes(newJson, "action")
							if action.String() == "on" {
								if e.Group == "default" {
									if !e.ProcessStatus {
										e.ChildProcess = utils.ChildProcessStart(e.AgentFile)
										logger.Logger.Debug("remote start child process", zap.Int("pid", e.ChildProcess.Process.Pid))
										e.AgentSwitch = true
									}
								} else {
									//todo
									e.FalcoSwitch = true
								}
							} else if action.String() == "off" {
								logger.Logger.Debug("remote stop child process", zap.Int("pid", e.ChildProcess.Process.Pid))
								utils.ChildProcessStop(e.ChildProcess)
								if e.Group == "default" {
									e.AgentSwitch = false
								} else {
									e.FalcoSwitch = false
								}
							}
						}
					} else if kind.String() == "all" {
						action := gjson.GetBytes(newJson, "action")
						if action.String() == "on" {
							if e.Group == "default" {
								if !e.ProcessStatus {
									e.ChildProcess = utils.ChildProcessStart(e.AgentFile)
									logger.Logger.Debug("remote start child process", zap.Int("pid", e.ChildProcess.Process.Pid))
									e.AgentSwitch = true
								}
							} else {
								//todo
								e.FalcoSwitch = true
							}
						} else if action.String() == "off" {
							logger.Logger.Debug("remote stop child process", zap.Int("pid", e.ChildProcess.Process.Pid))
							utils.ChildProcessStop(e.ChildProcess)
							if e.Group == "default" {
								e.AgentSwitch = false
							} else {
								e.FalcoSwitch = false
							}
						}
					}
				}
			}
		}
		wg.Done()
	}()
	//3.update
	go func() {
		getResp, err := kv.Get(context.TODO(), "/secagent/loader/conf/update")
		if err != nil {
			logger.Logger.Error("get update conf error", zap.String("error", err.Error()))
		}
		watchStartRevision := getResp.Header.Revision + 1
		watchChan := watcher.Watch(context.TODO(), "/secagent/loader/conf/update", clientv3.WithRev(watchStartRevision))
		for watchResp := range watchChan {
			for _, event := range watchResp.Events {
				switch event.Type {
				case mvccpb.PUT:
					newJson := event.Kv.Value
					fmt.Println(string(newJson))
					kind := gjson.GetBytes(newJson, "kind")
					target := gjson.GetBytes(newJson, "target")
					//kind类型：1.ip 2.list 3.cidr 4.group 5.all
					if kind.String() == "ip" {
						if e.ServerIP == target.String() {
							url := gjson.GetBytes(newJson, "url")
							hash := gjson.GetBytes(newJson, "hash")
							version := gjson.GetBytes(newJson, "version")
							if version.String() != configs.LoaderVersion {
								e.update(url.String(), version.String(), hash.String())
							}
						}
					} else if kind.String() == "list" {
						ips := strings.Split(target.String(), ",")
						if utils.SliceFind(ips, e.ServerIP) {
							url := gjson.GetBytes(newJson, "url")
							hash := gjson.GetBytes(newJson, "hash")
							version := gjson.GetBytes(newJson, "version")
							if version.String() != configs.LoaderVersion {
								e.update(url.String(), version.String(), hash.String())
							}
						}
					} else if kind.String() == "cidr" {
						network, _ := netip.ParsePrefix(target.String())
						ip, _ := netip.ParseAddr(e.ServerIP)
						if network.Contains(ip) {
							url := gjson.GetBytes(newJson, "url")
							hash := gjson.GetBytes(newJson, "hash")
							version := gjson.GetBytes(newJson, "version")
							if version.String() != configs.LoaderVersion {
								e.update(url.String(), version.String(), hash.String())
							}
						}
					} else if kind.String() == "group" {
						if e.Group == target.String() {
							url := gjson.GetBytes(newJson, "url")
							hash := gjson.GetBytes(newJson, "hash")
							version := gjson.GetBytes(newJson, "version")
							if version.String() != configs.LoaderVersion {
								e.update(url.String(), version.String(), hash.String())
							}
						}
					} else if kind.String() == "all" {
						url := gjson.GetBytes(newJson, "url")
						hash := gjson.GetBytes(newJson, "hash")
						version := gjson.GetBytes(newJson, "version")
						if version.String() != configs.LoaderVersion {
							e.update(url.String(), version.String(), hash.String())
						}
					}
				}
			}
		}
		wg.Done()
	}()
	wg.Wait()
}

func (e *EtcdConfig) AgentMonitor() {
	kv := clientv3.NewKV(e.Client)
	watcher := clientv3.NewWatcher(e.Client)
	//先获取agent filter配置
	//key:/secagent/agent/filter
	getResp, err := kv.Get(context.TODO(), "/secagent/agent/filter")
	if err != nil {
		logger.Logger.Error("get agent filter error", zap.String("error", err.Error()))
	}
	if getResp.Count > 0 {
		value := getResp.Kvs[0].Value
		execFilter := gjson.GetBytes(value, "execFilter")
		argsFilter := gjson.GetBytes(value, "argsFilter")
		if len(execFilter.Array()) > 0 {
			for _, item := range execFilter.Array() {
				utils.ExecFilter[item.String()] = struct{}{}
			}
		}
		logger.Logger.Debug("get execFilter conf success", zap.Any("execFilter", utils.ExecFilter))
		if len(execFilter.Array()) > 0 {
			for _, item := range argsFilter.Array() {
				utils.ArgsFilter[item.Get("exec").String()] = append(utils.ArgsFilter[item.Get("exec").String()], item.Get("args").String())
			}
		}
		logger.Logger.Debug("get argsFilter conf success", zap.Any("argsFilter", utils.ArgsFilter))
	}
	//监控agent tasks配置
	watchStartRevision := getResp.Header.Revision + 1
	watchChan := watcher.Watch(context.TODO(), "/secagent/agent/filter", clientv3.WithRev(watchStartRevision))
	for watchResp := range watchChan {
		for _, event := range watchResp.Events {
			switch event.Type {
			case mvccpb.PUT:
				newJson := event.Kv.Value
				utils.ExecFilter = make(map[string]struct{}, 100)
				utils.ArgsFilter = make(map[string][]string, 100)
				execFilter := gjson.GetBytes(newJson, "execFilter")
				argsFilter := gjson.GetBytes(newJson, "argsFilter")
				if len(execFilter.Array()) > 0 {
					for _, item := range execFilter.Array() {
						utils.ExecFilter[item.String()] = struct{}{}
					}
				}
				logger.Logger.Debug("update execFilter conf success", zap.Any("execFilter", utils.ExecFilter))
				if len(argsFilter.Array()) > 0 {
					for _, item := range argsFilter.Array() {
						utils.ArgsFilter[item.Get("exec").String()] = append(utils.ArgsFilter[item.Get("exec").String()], item.Get("args").String())
					}
				}
				logger.Logger.Debug("update argsFilter conf success", zap.Any("argsFilter", utils.ArgsFilter))
			}
		}
	}
}

func (e *EtcdConfig) LoaderTask(f embed.FS) {
	var wg sync.WaitGroup
	wg.Add(5)
	//获取loader配置
	e.GetLoaderConf()
	//注册loader
	e.RegisLoader()
	//写入文件
	if e.Group == "default" {
		e.WriteAgentFile(f)
		e.ChildProcess = utils.ChildProcessStart(e.AgentFile)
		logger.Logger.Debug("start child process", zap.Int("pid", e.ChildProcess.Process.Pid))
		//e.ProcessStatus = true
	} else if e.Group == "container" {
		//todo
	}
	//loader保活
	go func() {
		time.Sleep(5 * time.Second)
		err := e.KeepAlive()
		if err != nil {
		LOOP:
			err = e.RegisLoader()
			if err != nil {
				goto LOOP
			}
			err = e.KeepAlive()
			if err != nil {
				goto LOOP
			}
		}
		defer wg.Done()
	}()
	//loader monitor
	go func() {
		e.LoaderMonitor()
		defer wg.Done()
	}()
	//wait子进程，解决僵尸进程问题
	go func() {
		e.waitProcess()
		defer wg.Done()
	}()
	//检查子进程状态
	go func() {
		e.checkProcess()
		defer wg.Done()
	}()
	go func() {
		e.childProcManage()
		defer wg.Done()
	}()
	wg.Wait()
}

func (e *EtcdConfig) AgentTask() {
	//watch
	e.AgentMonitor()
}

func (e *EtcdConfig) risk(task string) {
	if task == "ssh" {
		logger.Logger.Debug("下发ssh弱密码检测任务")
		risk.WeakPassScan(e.ServerIP)
	}
}

// todo 下发更新任务后，如果版本号没有变化，则忽略
func (e *EtcdConfig) update(url, version, hash string) {
	//避免同时下载，需要添加随机时间的延后 0-1h
	//rand.Intn是伪随机数,需要rand.seed附加一个动态的值
	rand.Seed(time.Now().UnixNano())
	n := rand.Intn(3600)
	time.Sleep(time.Duration(n) * time.Second)
	//download file
	fileName, err := utils.Update_download(url, version)
	if err != nil {
		logger.Logger.Error("download update file error.")
	}
	if fileName != "" {
		path := "/opt/secagent/" + fileName
		//check hash
		check, err := utils.CheckSum_sha256(path)
		if err != nil {
			logger.Logger.Error("check file hash error.")
		}
		//如果hash匹配，则进行升级
		if check == hash {
			// 检查子进程状态，运行中则关停
			// 关停后执行文件更新
			if e.ProcessStatus {
				utils.ChildProcessStop(e.ChildProcess)
			}
			utils.Update_run(path)
		} else {
			// hash不一致，重新执行下载动作
			logger.Logger.Error("hash checksum is wrong")
			e.update(url, version, hash)
		}
	}
}

func (e *EtcdConfig) newLease() {
	//申请新租约
	lease := clientv3.NewLease(e.Client)
	leaseGran, err := lease.Grant(context.TODO(), 10)
	if err != nil {
		logger.Logger.Error("grant newlease error", zap.String("error", err.Error()))
	}
	//获取租约id
	e.LeaseID = leaseGran.ID
	//创建新kv
	kv := clientv3.NewKV(e.Client)
	//写入status
	status := `{"loaderStatus": "online", "agentStatus": "` + strconv.FormatBool(e.ProcessStatus) + `"}`
	statusResp, err := kv.Put(context.TODO(), "/secagent/loader/status/"+e.ServerIP, status, clientv3.WithLease(e.LeaseID))
	if err != nil {
		logger.Logger.Error("put status error", zap.String("error", err.Error()))
	}
	logger.Logger.Debug("status写入成功", zap.Int64("Resp Revision", statusResp.Header.Revision))
}

func (e *EtcdConfig) WriteAgentFile(f embed.FS) {
	fileName := "/opt/secagent/secagent-" + e.AgentVersion + "-linux"
	if e.Group == "default" {
		data, _ := f.ReadFile("build/secagent")
		_ = os.WriteFile(fileName, data, 0755)
	}
	e.AgentFile = fileName
}

func (e *EtcdConfig) InstallFalco() {

}

func (e *EtcdConfig) checkProcess() {
	for {
		time.Sleep(10 * time.Second)
		if utils.CheckPid(e.ChildProcess.Process.Pid) {
			if e.ProcessStatus != true {
				err := e.revokeID()
				if err != nil {
					fmt.Println(err)
				}
			}
			e.ProcessStatus = true
		} else {
			if e.ProcessStatus != false {
				err := e.revokeID()
				if err != nil {
					fmt.Println(err)
				}
			}
			e.ProcessStatus = false
		}
	}
}

func (e *EtcdConfig) revokeID() error {
	lease := clientv3.NewLease(e.Client)
	_, err := lease.Revoke(context.TODO(), e.LeaseID)
	if err != nil {
		return err
	}
	return nil
}

func (e *EtcdConfig) waitProcess() {
	for {
		time.Sleep(2 * time.Second)
		if err := e.ChildProcess.Wait(); err != nil {
			fmt.Printf("Child process %d exit with err: %v\n", e.ChildProcess.Process.Pid, err)
		}
	}
}

func (e *EtcdConfig) childProcManage() {
	for {
		time.Sleep(120 * time.Second)
		if e.Group == "default" {
			if e.AgentSwitch && e.ProcessStatus == false {
				e.ChildProcess = utils.ChildProcessStart(e.AgentFile)
			}
		}
	}
}
