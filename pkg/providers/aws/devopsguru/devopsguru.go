package devopsguru

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Devopsguru struct {
	NotificationChannels []NotificationChannel
}

type NotificationChannel struct {
	Metadata defsecTypes.Metadata
}
