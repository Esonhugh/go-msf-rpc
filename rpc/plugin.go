package rpc

// Plugins

type PluginLoadReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	PluginName string
	Options    map[string]string
}

type PluginLoadRes struct {
	Result string `msgpack:"result"`
}

type PluginUnLoadReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	PluginName string
}

type PluginUnLoadRes struct {
	Result string `msgpack:"result"`
}

type PluginLoadedReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type PluginLoadedRes struct {
	Plugins []string `msgpack:"plugins"`
}

func (msf *Metasploit) PluginLoad(PluginName string, PluginOptions map[string]string) (PluginLoadRes, error) {
	ctx := &PluginLoadReq{
		Method:     "plugin.load",
		Token:      msf.token,
		PluginName: PluginName,
		Options:    PluginOptions,
	}
	var res PluginLoadRes
	if err := msf.send(ctx, &res); err != nil {
		return PluginLoadRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) PluginUnLoad(PluginName string) (PluginUnLoadRes, error) {
	ctx := &PluginUnLoadReq{
		Method:     "plugin.unload",
		Token:      msf.token,
		PluginName: PluginName,
	}
	var res PluginUnLoadRes
	if err := msf.send(ctx, &res); err != nil {
		return PluginUnLoadRes{}, err
	}
	return res, nil
}

func (msf *Metasploit) PluginLoaded() (PluginLoadedRes, error) {
	ctx := &PluginLoadedReq{
		Method: "plugin.loaded",
		Token:  msf.token,
	}
	var res PluginLoadedRes
	if err := msf.send(ctx, &res); err != nil {
		return PluginLoadedRes{}, err
	}
	return res, nil
}
