package netinfo

import (
	"github.com/dean2021/goss"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sec_agent/internal/logger"
)

type AddrPort struct {
	Addr string `json:"addr"`
	Port string `json:"port"`
}

type UserEnt struct {
	Inode uint32 `json:"inode"`
	FD    int    `json:"fd"`
	Pid   int    `json:"pid"`
	PName string `json:"p_name"`
	PPid  int    `json:"p_pid"`
	PGid  int    `json:"p_gid"`
}

type Net struct {
	//Type    string
	Proto   string
	Local   *AddrPort
	Foreign *AddrPort
	State   string
	Inode   uint32
	Process *UserEnt
}

func (a *AddrPort) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddString("addr", a.Addr)
	encoder.AddString("port", a.Port)
	return nil
}

func (u *UserEnt) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddUint32("inode", u.Inode)
	encoder.AddInt("fd", u.FD)
	encoder.AddInt("pid", u.Pid)
	encoder.AddString("p_name", u.PName)
	encoder.AddInt("p_pid", u.PPid)
	encoder.AddInt("p_gid", u.PGid)
	return nil
}

func (n *Net) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	//encoder.AddString("type", n.Type)
	encoder.AddString("protocol", n.Proto)
	encoder.AddObject("local", n.Local)
	encoder.AddObject("foreign", n.Foreign)
	//zap.Inline(n.Local).AddTo(encoder)
	//zap.Inline(n.Foreign).AddTo(encoder)
	encoder.AddString("state", n.State)
	encoder.AddUint32("inode", n.Inode)
	encoder.AddObject("process", n.Process)
	//zap.Inline(n.Process).AddTo(encoder)
	return nil
}

func NetInfo() ([]*Net, error) {
	nets := make([]*Net, 0, 1000)
	connections, err := goss.Connections(goss.AF_INET, "all")
	if err != nil {
		return nil, err
	}
	for _, conn := range connections {
		//此处规避state为time-wait状态时，process结构体为nil的情况
		/*if conn.State == "TIME-WAIT" {
			continue
		}*/
		net := new(Net)
		//net.Type = "netinfo"
		net.Proto = conn.Proto
		net.Local = &AddrPort{
			Addr: conn.Local.Addr,
			Port: conn.Local.Port,
		}
		net.Foreign = &AddrPort{
			Addr: conn.Foreign.Addr,
			Port: conn.Foreign.Port,
		}
		net.State = conn.State
		net.Inode = conn.Inode
		if conn.Process == (*goss.UserEnt)(nil) {
			net.Process = new(UserEnt)
			/*net.Process.PName = "nil"
			net.Process.Pid = 0*/
		} else {
			net.Process = &UserEnt{
				Inode: conn.Process.Inode,
				FD:    conn.Process.FD,
				Pid:   conn.Process.Pid,
				PName: conn.Process.PName,
				PPid:  conn.Process.PPid,
				PGid:  conn.Process.PGid,
			}
		}
		nets = append(nets, net)
	}
	return nets, nil
}

func Task(ip string) {
	//网络信息 注意：goss.UserEnt可能为空结构体
	nets, err := NetInfo()
	if err != nil {
		logger.Logger.Error("run net task error", zap.String("error", err.Error()))
	}
	for _, net := range nets {
		//log.Printf("protol: %s, state: %s, process_name: %s,process_id: %v, local: %v:%v -> foreign: %v:%v\n", net.Proto, net.State, net.Process.PName, net.Process.Pid, net.Local.Addr, net.Local.Port, net.Foreign.Addr, net.Foreign.Port)
		logger.Logger.Info("sysinfo", zap.String("ip", ip), zap.String("infoType", "netinfo"), zap.Object("info", net))
	}
}
