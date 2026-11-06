package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"x-ui/database"
	"x-ui/database/model"
)

type NodeService struct{}

func (s *NodeService) List(userID int) ([]*model.Node, error) {
	var nodes []*model.Node
	err := database.GetDB().Where("user_id = ?", userID).Find(&nodes).Error
	return nodes, err
}

func (s *NodeService) Save(node *model.Node) error {
	if strings.TrimSpace(node.Name) == "" || strings.TrimSpace(node.BaseURL) == "" || strings.TrimSpace(node.Token) == "" {
		return fmt.Errorf("name, baseUrl and token are required")
	}
	node.BaseURL = strings.TrimRight(strings.TrimSpace(node.BaseURL), "/")
	return database.GetDB().Save(node).Error
}

func (s *NodeService) Delete(userID, id int) error {
	return database.GetDB().Where("user_id = ? AND id = ?", userID, id).Delete(&model.Node{}).Error
}

func (s *NodeService) Sync(userID, id int) error {
	var node model.Node
	if err := database.GetDB().Where("user_id = ? AND id = ?", userID, id).First(&node).Error; err != nil {
		return err
	}
	var inbounds []*model.Inbound
	if err := database.GetDB().Where("user_id = ?", userID).Find(&inbounds).Error; err != nil {
		return err
	}
	body, err := json.Marshal(inbounds)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, node.BaseURL+"/panel/api/nodes/push", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", node.Token)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("node returned HTTP %d", resp.StatusCode)
	}
	now := time.Now().UnixMilli()
	return database.GetDB().Model(&node).Updates(map[string]interface{}{"last_sync_at": now, "last_error": ""}).Error
}

func (s *NodeService) Push(token string, inbounds []*model.Inbound) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("missing node token")
	}
	var count int64
	if err := database.GetDB().Model(&model.Node{}).Where("token = ? AND enable = ?", token, true).Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("invalid node token")
	}
	db := database.GetDB()
	for _, inbound := range inbounds {
		if inbound == nil || inbound.Tag == "" {
			continue
		}
		var existing model.Inbound
		err := db.Where("tag = ?", inbound.Tag).First(&existing).Error
		if database.IsNotFound(err) {
			inbound.Id = 0
			if err := db.Create(inbound).Error; err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		inbound.Id = existing.Id
		inbound.UserId = existing.UserId
		if err := db.Save(inbound).Error; err != nil {
			return err
		}
	}
	return nil
}
