package main

import "testing"

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
