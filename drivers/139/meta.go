package _139

import (
	"github.com/alist-org/alist/v3/internal/driver"
	"github.com/alist-org/alist/v3/internal/op"
)

type Addition struct {
	Username             string `json:"username" required:"false"`
	Password             string `json:"password" required:"false" type:"password"`
	DeviceProfile        string `json:"device_profile" required:"false" type:"text"`
	Authorization        string `json:"authorization" type:"text"`
	driver.RootID
	Type                 string `json:"type" type:"select" options:"personal_new,family,group,personal" default:"personal_new"`
	CloudID              string `json:"cloud_id"`
	CustomUploadPartSize int64  `json:"custom_upload_part_size" type:"number" default:"0" help:"0 for auto"`
	ReportRealSize       bool   `json:"report_real_size" type:"bool" default:"true" help:"Enable to report the real file size during upload"`
	UseLargeThumbnail    bool   `json:"use_large_thumbnail" type:"bool" default:"false" help:"Enable to use large thumbnail for images"`
}

var config = driver.Config{
	Name:             "139Yun",
	LocalSort:        true,
	ProxyRangeOption: true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		d := &Yun139{}
		d.ProxyRange = true
		return d
	})
}
