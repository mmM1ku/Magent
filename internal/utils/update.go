package utils

import (
	"go.uber.org/zap"
	"io"
	"net/http"
	"os"
	"os/exec"
)

// Update_download 下载新版本客户端文件
func Update_download(url, version string) (string, error) {
	//下载agent更新文件
	fileName := "secloader-" + version + "-linux"
	file, err := os.OpenFile("/opt/secagent/"+fileName, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0755)
	if err != nil {
		Logger.Error("create file error", zap.String("error", err.Error()))
		return "", err
	}
	defer file.Close()

	resp, err := http.Get(url)
	if err != nil {
		Logger.Error("request file err", zap.String("error", err.Error()))
		return "", err
	}
	defer resp.Body.Close()
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		Logger.Error("download file err", zap.String("error", err.Error()))
		return "", err
	}
	return fileName, nil
}

// Update_run 使用命令执行新版本agent
func Update_run(path string) {
	cmd := exec.Command("sh", "-c", path+" >/dev/null 2>&1 &")
	err := cmd.Start()
	if err != nil {
		Logger.Error("run update agent file error", zap.String("error", err.Error()))
	}
}
