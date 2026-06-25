package node

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
)

var instanceID string

func init() {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate instance ID", "error", err)
		instanceID = "unknown"
		return
	}
	instanceID = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func InstanceID() string {
	return instanceID
}

func NodeName(cfgNodeName string) string {
	if cfgNodeName != "" {
		return cfgNodeName
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
