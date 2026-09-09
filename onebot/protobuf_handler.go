package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	wxproto "github.com/yincongcyincong/weixin-macos/onebot/proto"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func HandleProtobufMsgAndSend(payload map[string]interface{}) {
	jsonList, err := HandleProtobufMsg(payload)
	if err != nil {
		if isUnsupportedProtobufMessage(err) {
			Warn("跳过不匹配的protobuf消息", "err", err)
			return
		}
		Error("protobuf消息处理失败", "err", err)
		return
	}

	// 一个数据帧可能打包了多条消息，逐条下发
	for _, jsonData := range jsonList {
		if jsonData == nil {
			continue
		}
		if config.ConnType == "http" {
			SendHttpReq(jsonData)
		} else {
			SendWebSocketMsg(jsonData)
		}
	}
}

func isUnsupportedProtobufMessage(err error) bool {
	if err == nil {
		return false
	}

	message := err.Error()
	return strings.Contains(message, "cannot parse invalid wire-format data") ||
		strings.Contains(message, "cannot extract message data") ||
		strings.Contains(message, "missing required fields") ||
		strings.Contains(message, "no messages found")
}

// consumeBytesFields 从一段 protobuf 原始字节里，取出指定字段号、且 wiretype 为
// bytes(2) 的所有值。用于遍历"重复出现的 singular 字段"（proto.Unmarshal 只会保留
// 最后一个，这里手动全部取出）。
func consumeBytesFields(raw []byte, field protowire.Number) [][]byte {
	var out [][]byte
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			break
		}
		raw = raw[n:]
		if typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				break
			}
			if num == field {
				out = append(out, v)
			}
			raw = raw[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			break
		}
		raw = raw[m:]
	}
	return out
}

// consumeAllBytesFields 返回一层 protobuf 中所有 length-delimited 字段。
// 4.1.13 的同步响应更换了外层 envelope，消息数据不再固定出现在连续的 field 2；
// 递归 fallback 需要遍历所有 bytes 子消息，但仍由下游的必填字段校验过滤状态包。
func consumeAllBytesFields(raw []byte) [][]byte {
	var out [][]byte
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			break
		}
		raw = raw[n:]
		if typ == protowire.BytesType {
			value, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				break
			}
			out = append(out, value)
			raw = raw[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			break
		}
		raw = raw[m:]
	}
	return out
}

func looksLikeRecvMsgData(data *wxproto.WxRecvMsgData) bool {
	if data == nil || data.Sender == nil || data.Receiver == nil || data.Content == nil {
		return false
	}
	if data.Sender.Value == "" || data.Receiver.Value == "" || data.Content.Value == "" || data.MsgId == 0 {
		return false
	}
	return len(data.Sender.Value) <= 512 && len(data.Receiver.Value) <= 512
}

// scanRecvMsgDataFallback 兼容 4.1.13 新同步 envelope。消息数据结构仍沿用
// WxRecvMsgData，但外层字段层级和编号发生变化，因此按 bytes 子消息递归查找。
func scanRecvMsgDataFallback(raw []byte) []*wxproto.WxRecvMsgData {
	var result []*wxproto.WxRecvMsgData
	seen := make(map[string]struct{})
	var walk func([]byte, int)
	walk = func(current []byte, depth int) {
		if depth > 8 || len(current) == 0 {
			return
		}
		candidate := &wxproto.WxRecvMsgData{}
		if err := proto.Unmarshal(current, candidate); err == nil && looksLikeRecvMsgData(candidate) {
			key := fmt.Sprintf("%d:%s:%s:%d", candidate.MsgId, candidate.Sender.Value, candidate.Receiver.Value, len(candidate.Content.Value))
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				result = append(result, candidate)
			}
		}
		for _, nested := range consumeAllBytesFields(current) {
			walk(nested, depth+1)
		}
	}
	walk(raw, 0)
	return result
}

// parseAllRecvData 从 WxRecvMsg 原始字节里提取所有消息数据。
// 结构: WxRecvMsg.wrapper(field2) -> wrapper.body(field2, 可重复) -> body.content.data
// 一个 wrapper 里可能打包多条 body，需要全部取出。
func parseAllRecvData(rawBytes []byte) []*wxproto.WxRecvMsgData {
	var result []*wxproto.WxRecvMsgData
	for _, wrapperRaw := range consumeBytesFields(rawBytes, 2) {
		for _, bodyRaw := range consumeBytesFields(wrapperRaw, 2) {
			body := &wxproto.WxRecvMsgBody{}
			if err := proto.Unmarshal(bodyRaw, body); err != nil {
				continue
			}
			if body.Content != nil && looksLikeRecvMsgData(body.Content.Data) {
				result = append(result, body.Content.Data)
			}
		}
	}
	return result
}

func HandleProtobufMsg(payload map[string]interface{}) ([][]byte, error) {
	dataInter, ok := payload["data"]
	if !ok {
		return nil, fmt.Errorf("protobuf_msg: missing data field")
	}

	dataArr, ok := dataInter.([]interface{})
	if !ok {
		return nil, fmt.Errorf("protobuf_msg: data is not array")
	}

	rawBytes := make([]byte, len(dataArr))
	for i, v := range dataArr {
		num, ok := v.(float64)
		if !ok {
			return nil, fmt.Errorf("protobuf_msg: data[%d] is not number", i)
		}
		rawBytes[i] = byte(int(num))
	}

	//fmt.Println("[receive protobuf data]", HexDump(rawBytes, 0))

	dataList := parseAllRecvData(rawBytes)
	if len(dataList) == 0 {
		dataList = scanRecvMsgDataFallback(rawBytes)
	}
	if len(dataList) == 0 {
		return nil, fmt.Errorf("protobuf_msg: cannot extract message data")
	}

	var jsonList [][]byte
	for _, data := range dataList {
		jsonData, err := buildWechatMessageJSON(data)
		if err != nil {
			// 单条消息（如系统通知/字段不全）不阻断其他消息
			Warn("跳过单条protobuf消息", "err", err)
			continue
		}
		if jsonData != nil {
			jsonList = append(jsonList, jsonData)
		}
	}

	if len(jsonList) == 0 {
		return nil, fmt.Errorf("protobuf_msg: no messages found")
	}

	return jsonList, nil
}

// buildWechatMessageJSON 把单条 WxRecvMsgData 转成 WechatMessage JSON。
func buildWechatMessageJSON(data *wxproto.WxRecvMsgData) ([]byte, error) {
	sender := ""
	receiver := ""
	content := ""
	if data.Sender != nil {
		sender = data.Sender.Value
	}
	if data.Receiver != nil {
		receiver = data.Receiver.Value
	}
	if data.Content != nil {
		content = data.Content.Value
	}
	xmlStr := string(data.Xml)
	userContent := string(data.UserContent)
	msgId := fmt.Sprintf("%d", data.MsgId)

	if sender == "" || receiver == "" || content == "" || msgId == "" || msgId == "0" {
		return nil, fmt.Errorf("protobuf_msg: missing required fields sender=%s receiver=%s content_len=%d msgId=%s",
			sender, receiver, len(content), msgId)
	}

	selfId := myWechatId
	if selfId == "" {
		selfId = receiver
		if strings.Contains(receiver, "@chatroom") {
			selfId = sender
		}
	}
	msgType := "private"
	groupId := ""
	senderUser := sender
	conversationUser := sender
	senderNickname := ""
	messages := getMessagesFromProto(content, sender, data.MediaContent)
	if len(messages) == 0 {
		return nil, fmt.Errorf("protobuf_msg: no messages found")
	}

	if strings.Contains(sender, "@chatroom") {
		msgType = "group"
		groupId = sender

		splitIndex := strings.Index(content, ":")
		if splitIndex > 0 {
			candidate := strings.TrimSpace(content[:splitIndex])
			if candidate != "" && !strings.ContainsAny(candidate, "<>\n\r\t ") {
				senderUser = candidate
			}
		}
		conversationUser = senderUser

		messages = applyGroupMentions(messages, groupId, parseAtUsers(xmlStr))

		// 处理用户的名称
		splitIdx := strings.Index(userContent, ":")
		if splitIdx == -1 {
			if idx := strings.Index(userContent, "在群聊中"); idx != -1 {
				senderNickname = strings.TrimSpace(userContent[:idx])
			}
		} else {
			senderNickname = strings.TrimSpace(userContent[:splitIdx])
		}
		if senderNickname == "" {
			senderNickname = senderUser
		}
	} else {
		// 私聊事件中 sender 是实际作者；自己发出的消息要归入 receiver 对应的会话。
		if myWechatId != "" && sender == myWechatId {
			conversationUser = receiver
		}
		splitIdx := strings.Index(userContent, ":")
		if splitIdx != -1 {
			senderNickname = strings.TrimSpace(userContent[:splitIdx])
		}
		if senderNickname == "" {
			senderNickname = senderUser
		}
	}

	if groupId != "" {
		userID2NicknameMap.Store(groupId+"_"+senderUser, senderNickname)
	}

	wechatMsg := &WechatMessage{
		GroupId:     groupId,
		SelfID:      selfId,
		UserID:      conversationUser,
		Sender:      &Sender{UserID: senderUser, Nickname: senderNickname},
		Time:        time.Now().UnixMilli(),
		PostType:    "message",
		MessageId:   msgId,
		Message:     messages,
		MsgResource: xmlStr,
		RawMessage:  content,
		ShowContent: userContent,
		MessageType: msgType,
	}

	return json.Marshal(wechatMsg)
}

func parseAtUsers(xmlStr string) []string {
	match := regexp.MustCompile(`<atuserlist>([\s\S]*?)</atuserlist>`).FindStringSubmatch(xmlStr)
	if len(match) < 2 {
		return nil
	}
	raw := strings.TrimSpace(match[1])
	raw = strings.TrimPrefix(raw, "<![CDATA[")
	raw = strings.TrimSuffix(raw, "]]>")
	var users []string
	for _, value := range strings.Split(raw, ",") {
		user := strings.TrimSpace(value)
		if user != "" && !strings.ContainsAny(user, "<>") {
			users = append(users, user)
		}
	}
	return users
}

func applyGroupMentions(messages []*Message, groupID string, atUsers []string) []*Message {
	searchFrom := 0
	for _, atUser := range atUsers {
		matched := false
		for index := searchFrom; index < len(messages); index++ {
			message := messages[index]
			if message == nil || message.Type != "text" || message.Data == nil {
				continue
			}
			text := strings.TrimSpace(message.Data.Text)
			if !strings.HasPrefix(text, "@") || len(text) <= 1 {
				continue
			}
			nickname := strings.TrimSpace(strings.TrimPrefix(text, "@"))
			messages[index] = &Message{Type: "at", Data: &SendRequestData{QQ: atUser, Nickname: nickname}}
			searchFrom = index + 1
			matched = true
			break
		}
		if matched {
			continue
		}
		nickname := ""
		if value, ok := userID2NicknameMap.Load(groupID + "_" + atUser); ok {
			nickname, _ = value.(string)
		}
		messages = append(messages, &Message{Type: "at", Data: &SendRequestData{QQ: atUser, Nickname: nickname}})
	}
	return messages
}

func getMessagesFromProto(content, sender string, mediaContent []byte) []*Message {
	var messages []*Message

	if strings.Contains(sender, "@chatroom") {
		splitIndex := strings.Index(content, ":")
		pureContent := ""
		if splitIndex >= 0 {
			pureContent = strings.TrimSpace(content[splitIndex+1:])
		} else {
			pureContent = content
		}

		parts := strings.Split(pureContent, "\u2005")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			messages = append(messages, classifyMessage(part, mediaContent))
		}
	} else {
		messages = append(messages, classifyMessage(content, mediaContent))
	}

	return messages
}

func classifyMessage(content string, mediaContent []byte) *Message {
	content = strings.ReplaceAll(content, "\t", "")
	content = strings.ReplaceAll(content, "\n", "")
	switch {
	case strings.HasPrefix(content, "<?xml version=\"1.0\"?><msg><img"):
		return &Message{Type: "image", Data: &SendRequestData{Text: content, Media: mediaContent}}
	case strings.HasPrefix(content, "<msg><voicemsg"):
		if mediaContent != nil {
			// 找到 silk 音频数据起始位置
			for i, b := range mediaContent {
				if b == 0x02 {
					mediaContent = mediaContent[i:]
					break
				}
			}
			return &Message{Type: "record", Data: &SendRequestData{Text: content, Media: mediaContent}}
		}
		return &Message{Type: "record", Data: &SendRequestData{Text: content}}
	case strings.HasPrefix(content, "<?xml version=\"1.0\"?><msg><appmsg"):
		re := regexp.MustCompile(`<type>(.*?)</type>`)
		match := re.FindStringSubmatch(content)
		if len(match) > 1 {
			switch match[1] {
			case "5":
				return &Message{Type: "share", Data: &SendRequestData{Text: content}}
			case "6":
				return &Message{Type: "file", Data: &SendRequestData{Text: content}}
			}
		}
		return &Message{Type: "text", Data: &SendRequestData{Text: content}}
	case strings.HasPrefix(content, "<msg><emoji"):
		return &Message{Type: "face", Data: &SendRequestData{Text: content}}
	case strings.HasPrefix(content, "<?xml version=\"1.0\"?><msg><videomsg"):
		return &Message{Type: "video", Data: &SendRequestData{Text: content}}
	case strings.HasPrefix(content, "<sysmsg") || strings.HasPrefix(content, "<?xml version=\"1.0\"?><sysmsg") || strings.HasPrefix(content, "<msg><op id"):
		return &Message{Type: "sys", Data: &SendRequestData{Text: content}}
	default:
		return &Message{Type: "text", Data: &SendRequestData{Text: content}}
	}
}
