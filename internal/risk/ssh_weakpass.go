package risk

import (
	"bufio"
	"fmt"
	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"go.uber.org/zap"
	"os"
	"sec_agent/internal/logger"
	"strconv"
	"strings"
	"time"
)

type Shadow struct {
	User      string
	UserStats bool
	Pass      string
	Secret    string
	WeakStats bool
	WeakPass  string
}

// shadow passwd
// $id$salt$encrypted
// id:
// 1:MD5
// 5:SHA-256
// 6:SHA-512
func passCrypt(pass, cryptstr string) (string, error) {
	if strings.HasPrefix(cryptstr, "$6") {
		cp := crypt.SHA512.New()
		ret, err := cp.Generate([]byte(pass), []byte(cryptstr))
		if err != nil {
			return "", err
		}
		return ret, nil
	} else if strings.HasPrefix(cryptstr, "$5") {
		cp := crypt.SHA256.New()
		ret, err := cp.Generate([]byte(pass), []byte(cryptstr))
		if err != nil {
			return "", err
		}
		return ret, nil
	} else if strings.HasPrefix(cryptstr, "$1") {
		cp := crypt.MD5.New()
		ret, err := cp.Generate([]byte(pass), []byte(cryptstr))
		if err != nil {
			return "", err
		}
		return ret, nil
	}
	return "", fmt.Errorf("不支持的加密算法")
}

func WeakPassScan(ip string) {
	file, err := os.Open("/etc/shadow")
	if err != nil {

	}
	defer file.Close()
	var shadows []*Shadow
	buf := bufio.NewScanner(file)
	for {
		if !buf.Scan() {
			break
		}
		line := buf.Text()
		shadowStruct := shadowParser(line)
		shadows = append(shadows, shadowStruct)
	}
	for _, info := range shadows {
		//如果用户有效
		if info.UserStats {
			//获取该用户密码字典
			//fmt.Println(info.User)
			passDic := genPassDic(info.User)
			//fmt.Println(passDic)
			info.WeakStats = false
			info.WeakPass = ""
			//进行密码匹配
			for _, pass := range passDic {
				res, err := passCrypt(pass, info.Secret)
				if err != nil {
					//log.Printf("用户:%s -> %v\n", info.User, err)
					logger.Logger.Error("ssh密码检测匹配失败", zap.String("error", err.Error()))
					continue
				}
				if res == info.Pass {
					info.WeakStats = true
					info.WeakPass = pass
					break
				}
			}
		} else {
			info.WeakStats = false
			info.WeakPass = ""
		}
	}
	i := 0
	for _, content := range shadows {
		if content.WeakStats {
			logger.Logger.Info("riskevent", zap.String("ip", ip), zap.String("eventType", "ssh-weakpass"), zap.String("user", content.User), zap.String("pass", content.WeakPass))
		} else {
			i += 1
			if i == len(shadows) {
				logger.Logger.Info("riskevent", zap.String("msg", "未发现ssh弱口令"))
			}
		}
	}
	logger.Logger.Debug("弱口令扫描完毕")
}

func shadowParser(line string) *Shadow {
	shadowSlice := strings.Split(line, ":")
	shadowStruct := new(Shadow)
	if strings.HasPrefix(shadowSlice[1], "$") {
		shadowStruct.User = shadowSlice[0]
		shadowStruct.UserStats = true
		shadowStruct.Pass = shadowSlice[1]
		cryptSlice := strings.Split(shadowSlice[1], "$")
		shadowStruct.Secret = "$" + cryptSlice[1] + "$" + cryptSlice[2]
	} else {
		shadowStruct.User = shadowSlice[0]
		shadowStruct.UserStats = false
		shadowStruct.Pass = ""
		shadowStruct.Secret = ""
	}
	return shadowStruct
}

func genPassDic(user string) []string {
	//动态生成密码字典
	year := time.Now().Year()
	var passDic = []string{"root", "123456", "1", "raspberry", "admin", "password", "raspberryraspberry993311", "123456789", "111111", "P@ssw0rd", "12345678", "12345", "anonymous@", "1qaz@WSX", "admin123", "test", "aisadmin", "123", "user", "123123", "1234", "1qaz!QAZ", "p@ssw0rd", "1qaz2wsx", "abc123", "1234567890", "Admin@123", "Aa123456", "1qaz@WSX3edc", "111", "root@123", "root123", "Passw0rd", "1q2w3e4r", "ABCabc123", "1qazXSW@", "ftp", "1qaz2wsx3edc", "1234567", "!QAZ2wsx", "admin@123", "Admin123", "Huawei@123", "ftpuser", "abc@123", "1qazxsw2", "0", "ubnt", "Abc123", "112233"}
	passDic = append(passDic, user)
	for i := year - 5; i <= year; i++ {
		passDic = append(passDic, user+"@"+strconv.Itoa(i))
	}
	return passDic
}
