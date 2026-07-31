package main

import (
	"encoding/json"
	"testing"

	wxproto "github.com/yincongcyincong/weixin-macos/onebot/proto"
)

func TestParseAtUsers(t *testing.T) {
	users := parseAtUsers(`<msgsource><atuserlist><![CDATA[wxid_one,wxid_two]]></atuserlist></msgsource>`)
	if len(users) != 2 || users[0] != "wxid_one" || users[1] != "wxid_two" {
		t.Fatalf("unexpected users: %#v", users)
	}
	if invalid := parseAtUsers(`<atuserlist><![CDATA[]]></atuserlist>`); len(invalid) != 0 {
		t.Fatalf("expected no users, got %#v", invalid)
	}
}

func TestApplyGroupMentionsUsesVisibleNicknameWithoutDuplicate(t *testing.T) {
	messages := []*Message{
		{Type: "text", Data: &SendRequestData{Text: "@Michael"}},
		{Type: "text", Data: &SendRequestData{Text: "朱，进销存同步有熠云的方案敲定了不"}},
	}

	result := applyGroupMentions(messages, "room@chatroom", []string{"wxid_rj3003trtaen11"})
	if len(result) != 2 {
		t.Fatalf("expected two segments without appended duplicate, got %d", len(result))
	}
	if result[0].Type != "at" || result[0].Data.QQ != "wxid_rj3003trtaen11" || result[0].Data.Nickname != "Michael" {
		t.Fatalf("unexpected mention: %#v", result[0])
	}
}

func TestBuildWechatMessageJSONPrivateDirection(t *testing.T) {
	previousWechatID := myWechatId
	myWechatId = "wxid_self"
	t.Cleanup(func() { myWechatId = previousWechatID })

	tests := []struct {
		name               string
		sender             string
		receiver           string
		wantConversationID string
		wantAuthorID       string
	}{
		{
			name:               "incoming message",
			sender:             "wxid_contact",
			receiver:           "wxid_self",
			wantConversationID: "wxid_contact",
			wantAuthorID:       "wxid_contact",
		},
		{
			name:               "outgoing desktop message",
			sender:             "wxid_self",
			receiver:           "wxid_contact",
			wantConversationID: "wxid_contact",
			wantAuthorID:       "wxid_self",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &wxproto.WxRecvMsgData{
				Sender:   &wxproto.WxString{Value: tt.sender},
				Receiver: &wxproto.WxString{Value: tt.receiver},
				Content:  &wxproto.WxString{Value: "hello"},
				MsgId:    123,
			}

			raw, err := buildWechatMessageJSON(data)
			if err != nil {
				t.Fatalf("build message: %v", err)
			}
			var message WechatMessage
			if err := json.Unmarshal(raw, &message); err != nil {
				t.Fatalf("decode message: %v", err)
			}
			if message.SelfID != "wxid_self" {
				t.Fatalf("expected self id wxid_self, got %q", message.SelfID)
			}
			if message.UserID != tt.wantConversationID {
				t.Fatalf("expected conversation %q, got %q", tt.wantConversationID, message.UserID)
			}
			if message.Sender == nil || message.Sender.UserID != tt.wantAuthorID {
				t.Fatalf("expected author %q, got %#v", tt.wantAuthorID, message.Sender)
			}
		})
	}
}
