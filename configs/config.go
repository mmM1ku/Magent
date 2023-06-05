package configs

import "time"

// EtcdCluster etcd集群地址
var EtcdCluster = []string{""}

const (
	// 版本号信息, 格式x.x.x
	LoaderVersion = ""
	AgentVersion  = ""
	FalcoVersion  = ""
	EtcdTimeout   = 5 * time.Second
)
