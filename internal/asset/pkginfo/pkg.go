package pkginfo

import (
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os/exec"
	"sec_agent/internal/logger"
	"strings"
)

func PkgInfo(osName string) ([]*Pkg, error) {
	if osName == "centos" {
		return rpmList()
	} else if osName == "ubuntu" || osName == "debian" {
		return dpkgList()
	}
	return nil, fmt.Errorf("os platform err")
}

type Pkg struct {
	//Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PkgType string `json:"pkgType"`
}

func (p *Pkg) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	//encoder.AddString("type", p.Type)
	encoder.AddString("name", p.Name)
	encoder.AddString("version", p.Version)
	encoder.AddString("pkgType", p.PkgType)
	return nil
}

func rpmList() ([]*Pkg, error) {
	cmd := exec.Command("rpm", "-qa", "--qf", "\\{ \"name\": \"%{NAME}\", \"version\": \"%{VERSION}\", \"pkgType\": \"rpm\"\\},")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	jsonstr := strings.TrimRight(string(output), ",")
	jsonstr = "[" + jsonstr + "]"
	pkgs := make([]*Pkg, 0)
	if err := json.Unmarshal([]byte(jsonstr), &pkgs); err != nil {
		return nil, err
	}
	return pkgs, nil
}

func dpkgList() ([]*Pkg, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f={ \"name\": \"${Package}\", \"version\": \"${Version}\", \"pkgType\": \"dpkg\"},")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	jsonstr := strings.TrimRight(string(output), ",")
	jsonstr = "[" + jsonstr + "]"
	pkgs := make([]*Pkg, 0)
	if err := json.Unmarshal([]byte(jsonstr), &pkgs); err != nil {
		return nil, err
	}
	return pkgs, nil
}

func Task(ip, osPlatform string) {
	//pkg
	pkgs, err := PkgInfo(osPlatform)
	if err != nil {
		logger.Logger.Error("run pkg task error", zap.String("error", err.Error()))
	}
	for _, pkg := range pkgs {
		//log.Printf("pkg name: %s, version: %s, pkgType: %s\n", pkg.Name, pkg.Version, pkg.PkgType)
		logger.Logger.Info("sysinfo", zap.String("ip", ip), zap.String("infoType", "pkginfo"), zap.Object("info", pkg))
	}
}
