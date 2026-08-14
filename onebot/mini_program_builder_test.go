package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	wxproto "github.com/yincongcyincong/weixin-macos/onebot/proto"
)

func TestBuildMiniProgramMsgProtoUsesExperienceVersion(t *testing.T) {
	encoded, err := BuildMiniProgramMsgProto("wxid_sender", "filehelper", &MiniProgramInfo{
		Title:    "绑定领悟 PMS 身份",
		AppID:    "wx25a2d71ced501a1e",
		Username: "gh_196f05b79f4d@app",
		PagePath: "pages/openh5/index.html?url=%2FwxAssets%2Fhybrid%2FlwStudent%2Fpms-bind.html",
		ThumbURL: "http://wx.qlogo.cn/example/96",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	request := &wxproto.SendAppMsgReq{}
	if err := proto.Unmarshal(raw, request); err != nil {
		t.Fatal(err)
	}
	xml := request.GetMsg().GetContent()
	for _, expected := range []string{
		`<type>33</type>`,
		`<url>https://mp.weixin.qq.com/mp/waerrpage?appid=wx25a2d71ced501a1e&amp;type=upgrade&amp;upgradetype=3#wechat_redirect</url>`,
		`<weappinfo>`,
		`<type>2</type>`,
		`<pkginfo><type>2</type></pkginfo>`,
		`<weappiconurl><![CDATA[http://wx.qlogo.cn/example/96]]></weappiconurl>`,
	} {
		if !strings.Contains(xml, expected) {
			t.Fatalf("mini-program XML is missing %q: %s", expected, xml)
		}
	}
	if strings.Contains(xml, `<cdnthumburl>http://wx.qlogo.cn`) {
		t.Fatal("public app icon must not be used as a CDN thumbnail identifier")
	}
}
