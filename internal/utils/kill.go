package utils

import (
	"os"
	"os/signal"
	"syscall"
)

func Kill() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	s := <-c
	Logger.Debug("接收信号" + s.String())
	os.Exit(1)
}
