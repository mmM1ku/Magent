package userinfo

import (
	"bufio"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"sec_agent/internal/logger"
	"strings"
)

type User struct {
	UserName  string
	Uid       string
	Gid       string
	HomeDir   string
	ShellType string
}

func (u *User) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddString("user", u.UserName)
	encoder.AddString("uid", u.Uid)
	encoder.AddString("gid", u.Gid)
	encoder.AddString("home", u.HomeDir)
	encoder.AddString("shellType", u.ShellType)
	return nil
}

func UserInfo() ([]*User, error) {
	//userinfo := new(User)
	users := make([]*User, 0, 50)
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
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
			userSlice := strings.Split(line, ":")
			if len(userSlice) != 7 {
				continue
			}
			userinfo := new(User)
			userinfo.UserName = userSlice[0]
			userinfo.Uid = userSlice[2]
			userinfo.Gid = userSlice[3]
			userinfo.HomeDir = userSlice[5]
			userinfo.ShellType = userSlice[6]
			users = append(users, userinfo)
		}
	}
	return users, nil
}

func Task(ip string) {
	//用户信息
	users, err := UserInfo()
	if err != nil {
		logger.Logger.Error("run userinfo task error", zap.String("error", err.Error()))
	}
	for _, userInfo := range users {
		logger.Logger.Info("sysinfo", zap.String("ip", ip), zap.String("infoType", "userinfo"), zap.Object("info", userInfo))
	}
}
