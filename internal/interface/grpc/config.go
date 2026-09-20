package grpcservice

import (
	"fmt"
	"net"
)

type Config struct {
	Port      uint32
	AdminPort uint32
}

func (c Config) Validate() error {
	if c.Port == c.AdminPort {
		return fmt.Errorf("admin port must differ from port")
	}
	if c.Port == 0 || c.Port > 65535 || c.AdminPort == 0 || c.AdminPort > 65535 {
		return fmt.Errorf("ports must be between 1 and 65535")
	}
	for _, addr := range []string{address(c.Port), address(c.AdminPort)} {
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("invalid port: %s", err)
		}
		// nolint:all
		lis.Close()
	}
	return nil
}

func address(port uint32) string {
	return fmt.Sprintf(":%d", port)
}

func gatewayAddress(port uint32) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}
