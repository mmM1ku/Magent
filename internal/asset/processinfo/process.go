package processinfo

import (
	"github.com/elastic/go-sysinfo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sec_agent/internal/logger"
)

type Process struct {
	ProcName      string
	ProcId        int
	ProcExe       string
	ProcPid       int
	ProcPName     string
	ProcPExe      string
	ProcStartTime string
}

func (p *Process) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddString("procName", p.ProcName)
	encoder.AddInt("pid", p.ProcId)
	encoder.AddString("Exec", p.ProcExe)
	encoder.AddInt("p_pid", p.ProcPid)
	encoder.AddString("p_pName", p.ProcPName)
	encoder.AddString("p_Exec", p.ProcPExe)
	encoder.AddString("startTime", p.ProcStartTime)
	return nil
}

func ProcessInfo() ([]*Process, error) {
	pros := make([]*Process, 0, 500)
	processes, err := sysinfo.Processes()
	if err != nil {
		return nil, err
	}
	for _, process := range processes {
		procInfo, err := process.Info()
		if err != nil {
			continue
		}
		proc := new(Process)
		proc.ProcName = procInfo.Name
		proc.ProcId = procInfo.PID
		proc.ProcExe = procInfo.Exe
		proc.ProcPid = procInfo.PPID
		if proc.ProcPid > 0 {
			proc.ProcPName, proc.ProcPExe = procPInfo(proc.ProcPid)
		} else {
			proc.ProcPName, proc.ProcPExe = "", ""
		}
		proc.ProcStartTime = procInfo.StartTime.Format("2006-01-02 15:04:05")
		pros = append(pros, proc)
	}
	return pros, nil
}

func procPInfo(pid int) (string, string) {
	proc, err := sysinfo.Process(pid)
	if err != nil {
		logger.Logger.Error("get proc error", zap.String("error", err.Error()))
	}
	pInfo, err := proc.Info()
	if err != nil {
		logger.Logger.Error("get proc info error", zap.String("error", err.Error()))
	}
	return pInfo.Name, pInfo.Exe
}

func Task(ip string) {
	//进程信息
	pros, err := ProcessInfo()
	if err != nil {
		//log.Println(err)
		logger.Logger.Error("run proc task error", zap.String("error", err.Error()))
	}
	for _, proc := range pros {
		//log.Printf("proc name: %s, pid: %v, execve: %s starttime: %s -> p_name:%s, p_pid: %v, p_execve: %s\n", proc.ProcName, proc.ProcId, proc.ProcExe, proc.ProcStartTime, proc.ProcPName, proc.ProcPid, proc.ProcPExe)
		logger.Logger.Info("sysinfo", zap.String("ip", ip), zap.String("infoType", "procinfo"), zap.Object("info", proc))
	}
}
