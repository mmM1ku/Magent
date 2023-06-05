package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/containerd/cgroups"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/shirou/gopsutil/process"
	"go.uber.org/zap"
	"os"
	"os/exec"
	"regexp"
	"sec_agent/internal/logger"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	Logger  = logger.InitLogger()
	UserMap map[string]string
	// ExecFilter 进程过滤清单, 类型map[string]struct{}, 进程名记录在key中
	ExecFilter = make(map[string]struct{}, 200)
	// ArgsFilter 参数过滤清单, 类型map[string]string, 进程名记录在key，参数记录在value，与进程强关联
	ArgsFilter = make(map[string][]string, 200)
)

// GetUser 通过uid获取用户名
func GetUser(uid string) string {
	cmd := exec.Command("id", "-nu", uid)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err)
	}
	out = bytes.Trim(out, "\n")
	if strings.Contains(string(out), "no such user") {
		out = []byte("unknown")
	}
	return string(out)
}

// GetLoginUID 获取进程对应用户uid
func GetLoginUID(pid string) string {
	cmd := exec.Command("cat", "/proc/"+pid+"/loginuid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	out = bytes.Trim(out, "\n")
	return string(out)
}

func SliceFind(s []string, str string) bool {
	var result = false
	for _, ss := range s {
		if ss == str {
			result = true
			return result
		}
	}
	return result
}

func Cgroup() {
	var path = "/sys/fs/cgroup/cpu/agent"
	//创建agent cgroup文件夹
	//_ = os.MkdirAll("/sys/fs/cgroup/cpu/agent", os.ModePerm)
	var cgroupV2 = false
	if cgroups.Mode() == cgroups.Unified {
		cgroupV2 = true
	}
	quota := int64(5000)
	//period := uint64(200000)
	if !cgroupV2 {
		//如果存在
		if exists(path) {
			control, err := cgroups.Load(cgroups.V1, cgroups.StaticPath("/agent"))
			if err != nil {
				fmt.Println(err)
			}
			if err = control.Update(&specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Quota: &quota,
				},
			}); err != nil {
				fmt.Println(err)
			}
			defer control.Delete()
			pid := os.Getpid()
			if err := control.Add(cgroups.Process{Pid: pid}); err != nil {
				fmt.Println(err)
			}
		} else {
			control, err := cgroups.New(cgroups.V1, cgroups.StaticPath("/agent"), &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Quota: &quota,
					//Period: &period,
				},
			})
			if err != nil {
				fmt.Println(err)
			}
			defer control.Delete()
			pid := os.Getpid()
			if err := control.Add(cgroups.Process{Pid: pid}); err != nil {
				fmt.Println(err)
			}
		}
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func checkAudit() bool {
	//检查/sbin/auditd文件是否存在
	_, err := os.Stat("/sbin/auditd")
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func StopAudit() {
	//如果存在auditd，则判断auditd服务是否运行，存在则关闭
	if checkAudit() {
		//检查auditd服务状态
		cmd := exec.Command("service", "auditd", "status")
		out, err := cmd.CombinedOutput()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				//fmt.Printf("service finished with non-zero: %v\n", exitErr)
				logger.Logger.Error("service finished with non-zero.", zap.String("error", exitErr.String()))
			} else {
				//fmt.Printf("failed to run service: %v\n", err)
				logger.Logger.Error("failed to run service.", zap.String("error", err.Error()))
			}
		}
		//如果auditd服务运行中，则停止运行
		if strings.Contains(string(out), "Active: active") {
			//
			cmd2 := exec.Command("service", "auditd", "stop")
			out2, err := cmd2.CombinedOutput()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					//fmt.Printf("service finished with non-zero: %v\n", exitErr)
					logger.Logger.Error("service finished with non-zero.", zap.String("error", exitErr.String()))
				} else {
					//fmt.Printf("failed to run service: %v\n", err)
					logger.Logger.Error("failed to run service.", zap.String("error", err.Error()))
				}
			}
			//fmt.Printf("service stop finished: %v\n", string(out2))
			logger.Logger.Debug("service stop finished", zap.String("debug-info", string(out2)))
		} else {
			//fmt.Println("auditd service is not running.")
			logger.Logger.Debug("auditd service is not running.")
		}
	} else {
		//fmt.Println("auditd service is not installed.")
		logger.Logger.Debug("auditd service is not installed.")
	}
}

// CheckRoot 检测是否root
func CheckRoot() {
	if os.Geteuid() != 0 {
		Logger.Error("Please run the agent with root privileges!")
		os.Exit(1)
	}
}

func CheckRun() {
	// 杀掉非当前pid的secloader进程
	pid := os.Getpid()
	cmd1 := exec.Command("sh", "-c", "ps aux|grep secloader|grep -v "+strconv.Itoa(pid)+"|grep -v grep|awk '{print $2}'")
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		Logger.Error("get current sec agent proc failed")
	}
	if string(out1) == "" {
		//不存在，直接启动
		return
	} else {
		//存在，杀进程
		cmd2 := exec.Command("sh", "-c", "kill -9 "+string(out1))
		err := cmd2.Run()
		if err != nil {
			Logger.Error("kill current secloader proc failed", zap.String("error", err.Error()))
		}
	}
}

func CheckAgentRun() {
	reg := `secagent\-\d\.\d\.\d\-linux`
	processes, err := process.Processes()
	if err != nil {
		Logger.Error("get process list error", zap.String("msg", err.Error()))
	}
	for _, p := range processes {
		n, err := p.Name()
		if err != nil {
			Logger.Error("get process name error", zap.String("msg", err.Error()))
		}
		match, _ := regexp.MatchString(reg, n)
		if match {
			er := p.Kill()
			if er != nil {
				Logger.Error("kill agent process failed", zap.String("msg", er.Error()), zap.String("pid", strconv.Itoa(int(p.Pid))))
			} else {
				Logger.Debug("kill agent process successfully")
			}
		}
	}
}

func CheckSum_sha256(path string) (string, error) {
	hasher := sha256.New()
	f, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hasher.Write(f)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func DelOtherLoader(version string) {
	cmd := exec.Command("sh", "-c", "ls /opt/secagent/|grep 'secloader'|grep -v "+version)
	out, err := cmd.CombinedOutput()
	fileName := string(out)
	//注意排除\n和\r,shell返回结果带换行符
	fileName = strings.Trim(fileName, "\n")
	fileName = strings.Trim(fileName, "\r")
	if err != nil {
		//fmt.Println(err)
		Logger.Error("list other running sec agent proc failed")
	}
	//判断是否存在
	if string(out) != "" {
		path, _ := exec.LookPath("/opt/secagent/" + fileName)
		err = os.Remove(path)
		if err != nil {
			Logger.Error("remove other agent file failed", zap.String("error", err.Error()))
		}
	}
}

// DelOtherAgent todo
func DelOtherAgent() {

}

func ProcFilter(pName string, filter map[string]struct{}) bool {
	for proc := range filter {
		if strings.Contains(pName, proc) {
			return true
		} else {
			continue
		}
	}
	return false
}

func ArgFilter(exec, args string, filter map[string][]string) bool {
	list, ok := filter[exec]
	if ok {
		for _, item := range list {
			if strings.Contains(args, item) {
				return true
			} else {
				continue
			}
		}
	} else {
		return false
	}
	return false
}

func ChildProcessStart(fileName string) exec.Cmd {
	cmd := exec.Cmd{
		Path: fileName,
		Args: []string{},
		//Dir:  "/opt/secagent",
	}
	if err := cmd.Start(); err != nil {
		logger.Logger.Error("start "+fileName+"error", zap.String("error", err.Error()))
	}
	fmt.Printf("Child process started successfully, pid: %v\n", cmd.Process.Pid)
	return cmd
}

func ChildProcessStop(cmd exec.Cmd) {
	time.Sleep(15 * time.Second)
	err := cmd.Process.Kill()
	if err != nil {
		fmt.Printf("child process kill error: %v\n", err)
	}
	fmt.Println("child process stoped successfully")
}

func CheckPid(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		fmt.Printf("Process %d is dead!\n", pid)
		return false
	} else {
		fmt.Printf("Process %d is alive!\n", pid)
		return true
	}
}
