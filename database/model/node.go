package model

type Node struct {
	Id         int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	UserId     int    `json:"userId" form:"userId"`
	Name       string `json:"name" form:"name"`
	BaseURL    string `json:"baseUrl" form:"baseUrl"`
	Token      string `json:"token" form:"token"`
	Enable     bool   `json:"enable" form:"enable"`
	LastSyncAt int64  `json:"lastSyncAt" form:"lastSyncAt"`
	LastError  string `json:"lastError" form:"lastError"`
}
