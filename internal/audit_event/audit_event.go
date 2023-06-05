package audit_event

import (
	"github.com/elastic/go-libaudit/v2"
	"go.uber.org/zap"
	"io"
	"sec_agent/internal/asset/hostinfo"
	"sec_agent/internal/logger"
)

var Client = NewAudit(hostinfo.Info.IpAddr[0])

type Audit struct {
	ip     string
	Cli    *libaudit.AuditClient
	writer io.WriteCloser
}

func NewAudit(ip string) *Audit {
	return &Audit{
		ip: ip,
	}
}

func (a *Audit) AuditEvents() {
	var err error
	amsg := new(AuditMsg)
	logger.Logger.Debug("Starting audit syscall events")
	a.Cli, err = libaudit.NewAuditClient(a.writer)
	if err != nil {
		logger.Logger.Error("audit dial failed", zap.String("error", err.Error()))
	}
	defer a.Cli.Close()

	if err := read(amsg, a.Cli, a.ip); err != nil {
		logger.Logger.Error("read audit msg failed", zap.String("error", err.Error()))
	}
}

func (a *Audit) CloseAudit() {
	//a.writer.Close()
	err := a.Cli.Close()
	if err != nil {
		logger.Logger.Error("close audit client error", zap.String("error", err.Error()))
	}
}
