package controller

import (
	"net/http"
	"strconv"

	"x-ui/database/model"
	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
)

type NodeController struct {
	BaseController
	service service.NodeService
}

func NewNodeController(g *gin.RouterGroup) *NodeController {
	c := &NodeController{}
	g = g.Group("/nodes")
	g.Use(c.checkLogin)
	g.GET("/list", c.list)
	g.POST("/save", c.save)
	g.POST("/delete/:id", c.delete)
	g.POST("/sync/:id", c.sync)
	return c
}

func (c *NodeController) list(ctx *gin.Context) {
	nodes, err := c.service.List(session.GetLoginUser(ctx).Id)
	jsonObj(ctx, nodes, err)
}

func (c *NodeController) save(ctx *gin.Context) {
	node := &model.Node{}
	if err := ctx.ShouldBindJSON(node); err != nil {
		jsonMsg(ctx, "save node", err)
		return
	}
	node.UserId = session.GetLoginUser(ctx).Id
	err := c.service.Save(node)
	jsonMsgObj(ctx, "save node", node, err)
}

func (c *NodeController) delete(ctx *gin.Context) {
	id, err := strconv.Atoi(ctx.Param("id"))
	if err == nil {
		err = c.service.Delete(session.GetLoginUser(ctx).Id, id)
	}
	jsonMsg(ctx, "delete node", err)
}

func (c *NodeController) sync(ctx *gin.Context) {
	id, err := strconv.Atoi(ctx.Param("id"))
	if err == nil {
		err = c.service.Sync(session.GetLoginUser(ctx).Id, id)
	}
	jsonMsg(ctx, "sync node", err)
}

func RegisterNodePush(g *gin.RouterGroup, service service.NodeService) {
	g.POST("/nodes/push", func(ctx *gin.Context) {
		var inbounds []*model.Inbound
		if err := ctx.ShouldBindJSON(&inbounds); err != nil {
			jsonMsg(ctx, "push node", err)
			return
		}
		if err := service.Push(ctx.GetHeader("X-Node-Token"), inbounds); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"success": false, "msg": err.Error()})
			return
		}
		jsonMsg(ctx, "push node", nil)
	})
}
