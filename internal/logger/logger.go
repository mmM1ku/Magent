package logger

import (
	"github.com/arthurkiller/rollingwriter"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger = InitLogger()

func getLogWriter() zapcore.WriteSyncer {
	//只有拥有者有读写权限；而属组用户和其他用户只有读权限
	//file, _ := os.OpenFile("/var/log/sec_agent.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 644)
	//启动带有日志切割功能的logger
	config := rollingwriter.Config{
		LogPath:            "/var/log",
		TimeTagFormat:      "20060102150405",
		FileName:           "sec_agent",
		MaxRemain:          7,
		RollingPolicy:      rollingwriter.TimeRolling,
		RollingTimePattern: "0 0 0 * * *", //每天0点0分0秒切割日志
		WriterMode:         "lock",
		Compress:           true,
	}
	writer, _ := rollingwriter.NewWriterFromConfig(&config)
	return zapcore.AddSync(writer)
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05")
	return zapcore.NewJSONEncoder(encoderConfig)
}

func InitLogger() *zap.Logger {
	encoder := getEncoder()
	writeSyncer := getLogWriter()
	//允许debug级别日志
	core := zapcore.NewCore(encoder, writeSyncer, zapcore.DebugLevel)

	commLogger := zap.New(core)
	defer commLogger.Sync()
	return commLogger
}
