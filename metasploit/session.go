package metasploit

import "fmt"

// Session
type SessionListReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type SessionListRes map[uint32]struct {
	Type        string `msgpack:"type"`
	TunnelLocal string `msgpack:"tunnel_local"`
	TunnelPeer  string `msgpack:"tunnel_peer"`
	ViaExploit  string `msgpack:"via_exploit"`
	ViaPayload  string `msgpack:"via_payload"`
	Description string `msgpack:"desc"`
	Info        string `msgpack:"info"`
	Workspace   string `msgpack:"workspace"`
	SessionHost string `msgpack:"session_host"`
	SessionPort int    `msgpack:"session_port"`
	Username    string `msgpack:"username"`
	UUID        string `msgpack:"uuid"`
	ExploitUUID string `msgpack:"exploit_uuid"`
}

type SessionWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionWriteRes struct {
	WriteCount string `msgpack:"write_count"`
}

type SessionReadReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	SessionID   uint32
	ReadPointer string
}

type SessionReadRes struct {
	Seq  uint32 `msgpack:"seq"`
	Data string `msgpack:"data"`
}

type SessionRingLastReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type SessionRingLastRes struct {
	Seq uint32 `msgpack:"seq"`
}

type SessionMeterpreterWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionMeterpreterWriteRes struct {
	Result string `msgpack:"result"`
}

type SessionMeterpreterReadReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type SessionMeterpreterReadRes struct {
	Data string `msgpack:"data"`
}

type SessionMeterpreterRunSingleReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionMeterpreterRunSingleRes SessionMeterpreterWriteRes

type SessionMeterpreterDetachReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type SessionMeterpreterDetachRes SessionMeterpreterWriteRes

type SessionMeterpreterKillReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type SessionMeterpreterKillRes SessionMeterpreterWriteRes

type SessionMeterpreterTabsReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	InputLine string
}

type SessionMeterpreterTabsRes struct {
	Tabs []string `msgpack:"tabs"`
}

type SessionCompatibleModulesReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type SessionCompatibleModulesRes struct {
	Modules []string `msgpack:"modules"`
}

type SessionShellUpgradeReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	SessionID  uint32
	IpAddress  string
	PortNumber uint32
}

type SessionShellUpgradeRes SessionMeterpreterWriteRes

type SessionRingClearReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type SessionRingClearRes SessionMeterpreterWriteRes

type SessionRingPutReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionRingPutRes struct {
	WriteCount uint32 `msgpack:"write_count"`
}

func (msf *Client) SessionList() (SessionListRes, error) {
	req := &SessionListReq{
		Method: "session.list",
		Token:  msf.token,
	}

	var res SessionListRes
	if err := msf.send(req, &res); err != nil {
		return nil, err
	}

	return res, nil

}

func (msf *Client) SessionReadPointer(Session uint32) (uint32, error) {
	ctx := &SessionRingLastReq{
		Method:    "session.ring_last",
		Token:     msf.token,
		SessionID: Session,
	}

	var sesRingLast SessionRingLastRes
	if err := msf.send(ctx, &sesRingLast); err != nil {
		return 0, err
	}

	return sesRingLast.Seq, nil
}

func (msf *Client) SessionWrite(Session uint32, command string) error {
	ctx := &SessionWriteReq{
		Method:    "session.shell_write",
		Token:     msf.token,
		SessionID: Session,
		Command:   command,
	}

	var res SessionWriteRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}

	return nil
}

func (msf *Client) SessionRead(Session uint32, readPointer uint32) (string, error) {
	ctx := &SessionReadReq{
		Method:      "session.shell_read",
		Token:       msf.token,
		SessionID:   Session,
		ReadPointer: string(readPointer),
	}

	var res SessionReadRes
	if err := msf.send(ctx, &res); err != nil {
		return "", err
	}

	return res.Data, nil
}
func (msf *Client) SessionExecute(Session uint32, command string) (string, error) {
	readPointer, err := msf.SessionReadPointer(Session)
	if err != nil {
		return "", err
	}
	msf.SessionWrite(Session, command)
	data, err := msf.SessionRead(Session, readPointer)
	if err != nil {
		return "", err
	}
	return data, nil
}

func (msf *Client) SessionExecuteList(Session uint32, commands []string) (string, error) {
	var results string
	for _, command := range commands {
		tCommand := fmt.Sprintf("%s\n", command)
		result, err := msf.SessionExecute(Session, tCommand)
		if err != nil {
			return results, err
		}
		results += result
	}

	return results, nil
}

func (msf *Client) SessionMeterpreterWrite(Session uint32, command string) (SessionMeterpreterWriteRes, error) {
	ctx := &SessionMeterpreterWriteReq{
		Method:    "session.meterpreter_write",
		Token:     msf.token,
		SessionID: Session,
		Command:   command,
	}

	var res SessionMeterpreterWriteRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionMeterpreterWriteRes{}, err
	}

	return res, nil
}

func (msf *Client) SessionMeterpreterRead(Session uint32) (SessionMeterpreterReadRes, error) {
	ctx := &SessionMeterpreterReadReq{
		Method:    "session.meterpreter_read",
		Token:     msf.token,
		SessionID: Session,
	}

	var res SessionMeterpreterReadRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionMeterpreterReadRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionMeterpreterRunSingle(Session uint32, command string) (SessionMeterpreterRunSingleRes, error) {
	ctx := &SessionMeterpreterRunSingleReq{
		Method:    "session.meterpreter_run_single",
		Token:     msf.token,
		SessionID: Session,
		Command:   command,
	}

	var res SessionMeterpreterRunSingleRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionMeterpreterRunSingleRes{}, err
	}

	return res, nil
}

func (msf *Client) SessionMeterpreterSessionDetach(Session uint32) (SessionMeterpreterDetachRes, error) {
	ctx := &SessionMeterpreterDetachReq{
		Method:    "session.meterpreter_Session_detach",
		Token:     msf.token,
		SessionID: Session,
	}

	var res SessionMeterpreterDetachRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionMeterpreterDetachRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionMeterpreterSessionKill(Session uint32) (SessionMeterpreterKillRes, error) {
	ctx := &SessionMeterpreterKillReq{
		Method:    "session.meterpreter_Session_kill",
		Token:     msf.token,
		SessionID: Session,
	}

	var res SessionMeterpreterKillRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionMeterpreterKillRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionMeterpreterTabs(Session uint32, inputLine string) (SessionMeterpreterTabsRes, error) {
	ctx := &SessionMeterpreterTabsReq{
		Method:    "session.meterpreter_tabs",
		Token:     msf.token,
		SessionID: Session,
		InputLine: inputLine,
	}

	var res SessionMeterpreterTabsRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionMeterpreterTabsRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionCompatibleModules(Session uint32) (SessionCompatibleModulesRes, error) {
	ctx := &SessionCompatibleModulesReq{
		Method:    "session.compatible_modules",
		Token:     msf.token,
		SessionID: Session,
	}

	var res SessionCompatibleModulesRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionCompatibleModulesRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionShellUpgrade(Session uint32, lhostAddress string, lportNumber uint32) (SessionShellUpgradeRes, error) {
	ctx := &SessionShellUpgradeReq{
		Method:     "session.shell_upgrade",
		Token:      msf.token,
		SessionID:  Session,
		IpAddress:  lhostAddress,
		PortNumber: lportNumber,
	}

	var res SessionShellUpgradeRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionShellUpgradeRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionRingClear(Session uint32) (SessionRingClearRes, error) {
	ctx := &SessionRingClearReq{
		Method:    "session.ring_clear",
		Token:     msf.token,
		SessionID: Session,
	}

	var res SessionRingClearRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionRingClearRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionRingLast(Session uint32) (SessionRingLastRes, error) {
	ctx := &SessionRingLastReq{
		Method:    "session.ring_last",
		Token:     msf.token,
		SessionID: Session,
	}

	var res SessionRingLastRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionRingLastRes{}, err
	}
	return res, nil
}

func (msf *Client) SessionRingPut(Session uint32, command string) (SessionRingPutRes, error) {
	ctx := &SessionRingPutReq{
		Method:    "session.ring_put",
		Token:     msf.token,
		SessionID: Session,
		Command:   command,
	}

	var res SessionRingPutRes
	if err := msf.send(ctx, &res); err != nil {
		return SessionRingPutRes{}, err
	}
	return res, nil
}
