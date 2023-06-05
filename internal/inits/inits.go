package inits

import (
	"sec_agent/configs"
	"sec_agent/internal/utils"
)

func InitLoader() {
	//root检测
	utils.CheckRoot()
	//检测是否重复启动
	utils.CheckRun()
	//检测是否启动agent进程
	utils.CheckAgentRun()
	//删除非当前版本loader
	utils.DelOtherLoader(configs.LoaderVersion)
}

func InitAgent() {
	//cgourp加载
	utils.Cgroup()
	//userMap初始化
	utils.UserMap = make(map[string]string, 20)
	//判断是否存在auditd进程，存在的话关掉并禁用服务
	utils.StopAudit()
}
