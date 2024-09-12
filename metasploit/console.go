package metasploit

// Console

type ConsoleCreateReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ConsoleCreateRes struct {
	Id     string `msgpack:"id"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

type ConsoleDestroyReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	ConsoleId string
}

type ConsoleDestroyRes struct {
	Result string `msgpack:"result"`
}

type ConsoleListReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ConsoleListRes map[string][]struct {
	Id     string `msgpack:"id"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

type ConsoleWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	ConsoleId string
	Command   string
}

type ConsoleWriteRes struct {
	Wrote uint32 `msgpack:"wrote"`
}

type ConsoleReadReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	ConsoleId string
}

type ConsoleReadRes struct {
	Data   string `msgpack:"data"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

type ConsoleSessionDetachReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	ConsoleId string
}

type ConsoleSessionDetachRes struct {
	Result string `msgpack:"result"`
}

type ConsoleSessionKillReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	ConsoleId string
}

type ConsoleSessionKillRes struct {
	Result string `msgpack:"result"`
}

type ConsoleTabsReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	ConsoleId string
	InputLine string
}

type ConsoleTabsRes struct {
	Tabs []string `msgpack:"tabs"`
}

// Console
func (msf *Client) ConsoleCreate() (ConsoleCreateRes, error) {
	ctx := &ConsoleCreateReq{
		Method: "console.create",
		Token:  msf.token,
	}
	var res ConsoleCreateRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleCreateRes{}, err
	}
	return res, nil
}

func (msf *Client) ConsoleDestroy(consoleid string) (ConsoleDestroyRes, error) {
	ctx := &ConsoleDestroyReq{
		Method:    "console.destroy",
		Token:     msf.token,
		ConsoleId: consoleid,
	}
	var res ConsoleDestroyRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleDestroyRes{}, err
	}
	return res, nil
}

func (msf *Client) ConsoleList() (ConsoleListRes, error) {
	ctx := &ConsoleListReq{
		Method: "console.list",
		Token:  msf.token,
	}
	var res ConsoleListRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleListRes{}, err
	}
	return res, nil
}

func (msf *Client) ConsoleWrite(consoleId, command string) (ConsoleWriteRes, error) {
	ctx := &ConsoleWriteReq{
		Method:    "console.write",
		Token:     msf.token,
		ConsoleId: consoleId,
		Command:   command,
	}
	var res ConsoleWriteRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleWriteRes{}, err
	}
	return res, nil
}

func (msf *Client) ConsoleRead(consoleId string) (ConsoleReadRes, error) {
	ctx := &ConsoleReadReq{
		Method:    "console.read",
		Token:     msf.token,
		ConsoleId: consoleId,
	}
	var res ConsoleReadRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleReadRes{}, err
	}
	return res, nil
}

func (msf *Client) ConsoleSessionDetch(consoleId string) (ConsoleSessionDetachRes, error) {
	ctx := &ConsoleSessionDetachReq{
		Method:    "console.session_detach",
		Token:     msf.token,
		ConsoleId: consoleId,
	}
	var res ConsoleSessionDetachRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleSessionDetachRes{}, err
	}
	return res, nil
}

func (msf *Client) ConsoleSessionKill(consoleId string) (ConsoleSessionKillRes, error) {
	ctx := &ConsoleSessionKillReq{
		Method:    "console.session_kill",
		Token:     msf.token,
		ConsoleId: consoleId,
	}
	var res ConsoleSessionKillRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleSessionKillRes{}, err
	}
	return res, nil
}

func (msf *Client) ConsoleTabs(consoleId, inputLine string) (ConsoleTabsRes, error) {
	ctx := &ConsoleTabsReq{
		Method:    "console.tabs",
		Token:     msf.token,
		ConsoleId: consoleId,
		InputLine: inputLine,
	}
	var res ConsoleTabsRes
	if err := msf.send(ctx, &res); err != nil {
		return ConsoleTabsRes{}, err
	}
	return res, nil
}
