package croninfo

import (
	"bufio"
	"fmt"
	"github.com/adhocore/gronx"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io/fs"
	"os"
	"path/filepath"
	"sec_agent/internal/logger"
	"strings"
)

type Cron struct {
	Path    string `json:"path"`
	CronExp string `json:"cronExp"`
	User    string `json:"user"`
	Cmd     string `json:"cmd"`
}

func (c *Cron) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddString("path", c.Path)
	encoder.AddString("cronExp", c.CronExp)
	encoder.AddString("user", c.User)
	encoder.AddString("cmd", c.Cmd)
	return nil
}

func CronInfo() ([]*Cron, error) {
	cronslice1, err := commCronInfo()
	if err != nil {
		return nil, err
	}
	cronslice2, err := cycleCronInfo()
	if err != nil {
		return nil, err
	}
	cronslice3, err := userCronInfo()
	if err != nil {
		return nil, err
	}
	cronslice := append(cronslice1, cronslice2...)
	cronslice = append(cronslice, cronslice3...)
	return cronslice, nil
}

// commCronInfo
//
// 解析/etc/crontab和/etc/cron.d/目录下的文件
func commCronInfo() ([]*Cron, error) {
	crons := make([]*Cron, 0)
	var filedirs = []string{"/etc/crontab"}
	err := filepath.Walk("/etc/cron.d/", func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			filedirs = append(filedirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	gron := gronx.New()
	for _, filedir := range filedirs {
		file, err := os.Open(filedir)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		buf := bufio.NewScanner(file)
		for {
			if !buf.Scan() {
				break
			}
			line := strings.ReplaceAll(buf.Text(), "\t", " ")
			if strings.HasPrefix(line, "#") {
				continue
			} else {
				cronslice := strings.Split(line, " ")
				if len(cronslice) > 1 {
					exp := strings.Join(cronslice[:5], " ")
					if gron.IsValid(exp) {
						cron := new(Cron)
						cron.CronExp = exp
						cron.User = cronslice[5]
						cron.Cmd = strings.Join(cronslice[6:], " ")
						cron.Path = filedir
						crons = append(crons, cron)
					}
				}
			}
		}
	}
	return crons, nil
}

// userCronInfo
//
// 主要解析/var/spool/cron和/var/spool/cron/crontabs下文件
func userCronInfo() ([]*Cron, error) {
	var dirs = []string{
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
	}
	crons := make([]*Cron, 0)
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		} else {
			err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
				if !info.IsDir() {
					file, err := os.Open(path)
					if err != nil {
						return err
					}
					defer file.Close()
					buf := bufio.NewScanner(file)
					for {
						if !buf.Scan() {
							break
						}
						line := buf.Text()
						if strings.HasPrefix(line, "#") {
							continue
						} else {
							croninfo := new(Cron)
							cronslice := strings.Split(line, " ")
							if len(cronslice) > 1 {
								croninfo.User = info.Name()
								croninfo.Path = path
								croninfo.CronExp = strings.Join(cronslice[:5], " ")
								croninfo.Cmd = strings.Join(cronslice[5:], " ")
								crons = append(crons, croninfo)
							} else {
								continue
							}
						}
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	return crons, nil
}

// cycleCronInfo
//
// 主要解析/etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly
func cycleCronInfo() ([]*Cron, error) {
	var dirs = []string{
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	}
	crons := make([]*Cron, 0, 100)
	for _, dir := range dirs {
		err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if !info.IsDir() {
				if !strings.Contains(info.Name(), ".") {
					cron := new(Cron)
					cron.Path = strings.Trim(path, info.Name())
					cron.CronExp = strings.Split(path, "/")[2]
					cron.User = "root"
					cron.Cmd = info.Name()
					crons = append(crons, cron)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return crons, nil
}

func Task(ip string) {
	//cron
	fmt.Printf("\n")
	crons, err := CronInfo()
	if err != nil {
		logger.Logger.Error("run cron task error", zap.String("error", err.Error()))
	}
	for _, cron := range crons {
		logger.Logger.Info("sysinfo", zap.String("ip", ip), zap.String("infoType", "croninfo"), zap.Object("info", cron))
	}
}
