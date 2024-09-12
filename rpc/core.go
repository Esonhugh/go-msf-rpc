package rpc

// Core
type CoreAddModulePathReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
	Path     string
}

type CoreAddModulePathRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

type CoreModuleStatsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type CoreModuleStatsRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

type CoreReloadModulesReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type CoreReloadModulesRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

type CoreSaveReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type CoreSaveRes struct {
	Result string `msgpack:"result"`
}

type CoreSetgReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	OptionName  string
	OptionValue string
}

type CoreSetgRes struct {
	Result string `msgpack:"result"`
}

type CoreUnSetgReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	OptionName string
}

type CoreUnSetgRes struct {
	Result string `msgpack:"result"`
}

type CoreThreadListReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type CoreThreadListRes map[int]struct {
	Status   string `msgpack:"status"`
	Critical bool   `msgpack:"critical"`
	Name     string `msgpack:"name"`
	Started  string `msgpack:"started"`
}

type CoreThreadKillReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
	ThreadId string
}

type CoreThreadKillRes struct {
	Result string `msgpack:"result"`
}

type CoreVersionReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type CoreVersionRes struct {
	Version string `msgpack:"version"`
	Ruby    string `msgpack:"ruby"`
	Api     string `msgpack:"api"`
}

type CoreStopReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type CoreStopRes struct {
	Result string `msgpack:"result"`
}

func (msf *Metasploit) CoreAddModulePath(path string) (CoreAddModulePathRes, error) {
	ctx := &CoreAddModulePathReq{
		Method: "core.add_module_path",
		Token:  msf.token,
		Path:   path,
	}

	var res CoreAddModulePathRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreAddModulePathRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) CoreModuleStats() (CoreModuleStatsRes, error) {
	ctx := &CoreModuleStatsReq{
		Method: "core.module_stats",
		Token:  msf.token,
	}

	var res CoreModuleStatsRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreModuleStatsRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) CoreReloadModules() (CoreReloadModulesRes, error) {
	ctx := &CoreReloadModulesReq{
		Method: "core.reload_modules",
		Token:  msf.token,
	}

	var res CoreReloadModulesRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreReloadModulesRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) CoreSave() (CoreSaveRes, error) {
	ctx := &CoreSaveReq{
		Method: "core.save",
		Token:  msf.token,
	}

	var res CoreSaveRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreSaveRes{}, nil
	}
	return res, nil
}

func (msf *Metasploit) CoreSetg(optionName, optionValue string) (CoreSetgRes, error) {
	ctx := &CoreSetgReq{
		Method:      "core.setg",
		Token:       msf.token,
		OptionName:  optionName,
		OptionValue: optionValue,
	}

	var res CoreSetgRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreSetgRes{}, nil
	}
	return res, nil
}

func (msf *Metasploit) CoreUnSetg(optionName string) (CoreUnSetgRes, error) {
	ctx := &CoreUnSetgReq{
		Method:     "core.unsetg",
		Token:      msf.token,
		OptionName: optionName,
	}

	var res CoreUnSetgRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreUnSetgRes{}, nil
	}
	return res, nil
}

func (msf *Metasploit) CoreThreadList() (CoreThreadListRes, error) {
	ctx := &CoreThreadListReq{
		Method: "core.thread_list",
		Token:  msf.token,
	}

	var res CoreThreadListRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreThreadListRes{}, nil
	}
	return res, nil
}

func (msf *Metasploit) CoreThreadKill(threadId string) (CoreThreadKillRes, error) {
	ctx := &CoreThreadKillReq{
		Method:   "core.thread_kill",
		Token:    msf.token,
		ThreadId: threadId,
	}

	var res CoreThreadKillRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreThreadKillRes{}, nil
	}
	return res, nil
}

func (msf *Metasploit) CoreVersion() (CoreVersionRes, error) {
	ctx := &CoreVersionReq{
		Method: "core.version",
		Token:  msf.token,
	}
	var res CoreVersionRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreVersionRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) CoreStop() (CoreStopRes, error) {
	ctx := &CoreStopReq{
		Method: "core.stop",
		Token:  msf.token,
	}
	var res CoreStopRes
	if err := msf.send(ctx, &res); err != nil {
		return CoreStopRes{}, err
	}
	return res, nil
}
