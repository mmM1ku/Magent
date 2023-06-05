package systemdinfo

import (
	"context"
	"github.com/coreos/go-systemd/v22/dbus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sec_agent/internal/logger"
	"strings"
)

type Unit struct {
	Name        string
	LoadState   string
	ActiveState string
	Description string
}

func (u *Unit) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	encoder.AddString("name", u.Name)
	encoder.AddString("loadState", u.LoadState)
	encoder.AddString("activeState", u.ActiveState)
	encoder.AddString("description", u.Description)
	return nil
}

func SystemdInfo() ([]*Unit, error) {
	services := make([]*Unit, 0)
	ctx := context.Background()
	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	units, err := conn.ListUnitsContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, unit := range units {
		service := new(Unit)
		if strings.Contains(unit.Name, ".service") {
			service.Name = unit.Name
			service.LoadState = unit.LoadState
			service.ActiveState = unit.ActiveState
			service.Description = unit.Description
			services = append(services, service)
		} else {
			continue
		}
	}
	return services, nil
}

func Task(ip string) {
	//systemd
	serivces, err := SystemdInfo()
	if err != nil {
		//log.Println(err)
		logger.Logger.Error("run systemd task error", zap.String("error", err.Error()))
	}
	for _, service := range serivces {
		//log.Printf("service name: %s, load state: %s, active state: %s\n", service.Name, service.LoadState, service.ActiveState)
		logger.Logger.Info("sysinfo", zap.String("ip", ip), zap.String("infoType", "serviceinfo"), zap.Object("info", service))
	}
}
