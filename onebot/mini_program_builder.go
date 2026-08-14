package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	wxproto "github.com/yincongcyincong/weixin-macos/onebot/proto"
)

// MiniProgramInfo describes the public fields required by a type=33 mini-program card.
type MiniProgramInfo struct {
	Title       string
	Description string
	AppID       string
	Username    string
	PagePath    string
	ThumbURL    string
}

func BuildMiniProgramMsgProto(sender, receiver string, info *MiniProgramInfo) (string, error) {
	if info == nil || info.Title == "" || info.AppID == "" || info.Username == "" || info.PagePath == "" {
		return "", fmt.Errorf("mini-program card fields are incomplete")
	}
	now := time.Now().Unix()
	upgradeURL := "https://mp.weixin.qq.com/mp/waerrpage?appid=" + info.AppID + "&amp;type=upgrade&amp;upgradetype=3#wechat_redirect"
	xml := `<?xml version="1.0"?>` +
		`<appmsg appid="" sdkver="0">` +
		`<title>` + escapeXmlStr(info.Title) + `</title>` +
		`<des>` + escapeXmlStr(info.Description) + `</des>` +
		`<action>view</action><type>33</type><showtype>0</showtype>` +
		`<content></content><url>` + upgradeURL + `</url><lowurl></lowurl><forwardflag>0</forwardflag>` +
		`<appattach><totallen>0</totallen><attachid></attachid><fileext></fileext>` +
		`<cdnthumburl></cdnthumburl></appattach>` +
		`<extinfo></extinfo><sourceusername>` + escapeXmlStr(info.Username) + `</sourceusername>` +
		`<sourcedisplayname>领悟信息</sourcedisplayname>` +
		`<webviewshared><publisherId>wxapp_` + escapeXmlStr(info.AppID) + escapeXmlStr(info.PagePath) + `</publisherId></webviewshared>` +
		`<weappinfo><pagepath><![CDATA[` + cdataSafe(info.PagePath) + `]]></pagepath>` +
		`<username><![CDATA[` + cdataSafe(info.Username) + `]]></username>` +
		`<appid><![CDATA[` + cdataSafe(info.AppID) + `]]></appid><type>2</type>` +
		`<weappiconurl><![CDATA[` + cdataSafe(info.ThumbURL) + `]]></weappiconurl>` +
		`<pkginfo><type>2</type></pkginfo><appservicetype>0</appservicetype></weappinfo></appmsg>`

	version := NextVersion()
	appID := ""
	sdkVersion := uint32(0)
	msgType := uint32(33)
	clientMsgID := fmt.Sprintf("%s_%d_%d", receiver, now, rand.Intn(1000))
	msgSource := "<msgsource><alnode><fr>1</fr></alnode></msgsource>"
	req := &wxproto.SendAppMsgReq{
		BaseRequest: &wxproto.ReplyMsgHeader{
			Flag: []byte{0x00}, SessionId: &globalSessionId, ClientProof: globalClientProof,
			DeviceId: &globalDeviceId, Platform: proto.String("UnifiedPCMac 26 arm64"), Version: &version,
		},
		Msg: &wxproto.AppMsgBody{
			FromUserName: &sender, AppId: &appID, SdkVersion: &sdkVersion, ToUserName: &receiver,
			Type: &msgType, Content: &xml, CreateTime: &now, ClientMsgId: &clientMsgID, MsgSource: &msgSource,
		},
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal mini-program proto failed: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func cdataSafe(value string) string {
	return strings.ReplaceAll(value, "]]>", "]]]]><![CDATA[>")
}
