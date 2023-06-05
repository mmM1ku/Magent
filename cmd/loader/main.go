package main

import (
	"embed"
	"sec_agent/internal/inits"
	"sec_agent/pkg/etcd"
)

//go:embed build/secagent
var f embed.FS

func main() {
	//loader 初始化
	inits.InitLoader()
	//loader etcd任务
	etcd.Cli.LoaderTask(f)
}
