package metasploit

// Modules

type ModuleExploitsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleExploitsRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleAuxiliaryReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleAuxiliaryRes struct {
	Modules []string `msgpack:"modules"`
}

type ModulePostReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModulePostRes struct {
	Modules []string `msgpack:"modules"`
}

type ModulePayloadsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModulePayloadsRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleEncodersReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleEncodersRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleNopsReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type ModuleNopsRes struct {
	Modules []string `msgpack:"modules"`
}

type ModuleInfoReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleType string
	ModuleName string
}

type ModuleInfoRes struct {
	Name        string     `msgpack:"name"`
	Description string     `msgpack:"description"`
	License     string     `msgpack:"license"`
	FilePath    string     `msgpack:"filepath"`
	Version     string     `msgpack:"version"`
	Rank        string     `msgpack:"rank"`
	References  [][]string `msgpack:"references"`
	Authors     []string   `msgpack:"authors"`
}

type ModuleOptionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleType string
	ModuleName string
}

type ModuleOptionsRes map[string]struct {
	Type     string      `msgpack:"type"`
	Required bool        `msgpack:"required"`
	Advanced bool        `msgpack:"advanced"`
	Evasion  bool        `msgpack:"evasion"`
	Desc     string      `msgpack:"desc"`
	Default  interface{} `msgpack:"default"`
	Enums    []string    `msgpack:"enums,omitempty"`
}

type ModuleCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

type ModuleTargetCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleName string
	ArchNumber uint32
}

type ModuleTargetCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

type ModuleCompatibleSessionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatibleSessionsRes struct {
	Sessions []string `msgpack:"sessions"`
}

type ModuleEncodeReq struct {
	_msgpack      struct{} `msgpack:",asArray"`
	Method        string
	Token         string
	Data          string
	EncoderModule string
	Options       map[string]string
}

type ModuleEncodeRes struct {
	Encoded []byte `msgpack:"encoded"`
}

type ModuleExecuteReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	ModuleType string
	ModuleName string
	Options    map[string]string
}

type ModuleExecuteRes struct {
	JobId uint32 `msgpack:"job_id"`
}

func (msf *Client) ModuleExploits() (ModuleExploitsRes, error) {
	ctx := &ModuleExploitsReq{
		Method: "module.exploits",
		Token:  msf.token,
	}
	var res ModuleExploitsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleExploitsRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleAuxiliary() (ModuleAuxiliaryRes, error) {
	ctx := &ModuleAuxiliaryReq{
		Method: "module.auxiliary",
		Token:  msf.token,
	}
	var res ModuleAuxiliaryRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleAuxiliaryRes{}, err
	}
	return res, nil
}

func (msf *Client) ModulePost() (ModulePostRes, error) {
	ctx := &ModulePostReq{
		Method: "module.post",
		Token:  msf.token,
	}
	var res ModulePostRes
	if err := msf.send(ctx, &res); err != nil {
		return ModulePostRes{}, err
	}
	return res, nil
}

func (msf *Client) ModulePayloads() (ModulePayloadsRes, error) {
	ctx := &ModulePayloadsReq{
		Method: "module.payloads",
		Token:  msf.token,
	}
	var res ModulePayloadsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModulePayloadsRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleEncoders() (ModuleEncodersRes, error) {
	ctx := &ModuleEncodersReq{
		Method: "module.encoders",
		Token:  msf.token,
	}
	var res ModuleEncodersRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleEncodersRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleNops() (ModuleNopsRes, error) {
	ctx := &ModuleNopsReq{
		Method: "module.nops",
		Token:  msf.token,
	}
	var res ModuleNopsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleNopsRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleInfo(ModuleType, ModuleName string) (ModuleInfoRes, error) {
	ctx := &ModuleInfoReq{
		Method:     "module.info",
		Token:      msf.token,
		ModuleType: ModuleType,
		ModuleName: ModuleName,
	}
	var res ModuleInfoRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleInfoRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleOptions(ModuleType, ModuleName string) (ModuleOptionsRes, error) {
	ctx := &ModuleOptionsReq{
		Method:     "module.options",
		Token:      msf.token,
		ModuleType: ModuleType,
		ModuleName: ModuleName,
	}
	var res ModuleOptionsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleOptionsRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleCompatiblePayloads(ModuleName string) (ModuleCompatiblePayloadsRes, error) {
	ctx := &ModuleCompatiblePayloadsReq{
		Method:     "module.compatible_payloads",
		Token:      msf.token,
		ModuleName: ModuleName,
	}
	var res ModuleCompatiblePayloadsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleCompatiblePayloadsRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleTargetCompatiblePayloads(ModuleName string, targetNumber uint32) (ModuleTargetCompatiblePayloadsRes, error) {
	ctx := &ModuleTargetCompatiblePayloadsReq{
		Method:     "module.target_compatible_payloads",
		Token:      msf.token,
		ModuleName: ModuleName,
		ArchNumber: targetNumber,
	}
	var res ModuleTargetCompatiblePayloadsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleTargetCompatiblePayloadsRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleCompatibleSessions(ModuleName string) (ModuleCompatibleSessionsRes, error) {
	ctx := &ModuleCompatibleSessionsReq{
		Method:     "module.compatible_sessions",
		Token:      msf.token,
		ModuleName: ModuleName,
	}
	var res ModuleCompatibleSessionsRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleCompatibleSessionsRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleEncode(data, encoderModule string, ModuleOptions map[string]string) (ModuleEncodeRes, error) {
	ctx := &ModuleEncodeReq{
		Method:        "module.encode",
		Token:         msf.token,
		Data:          data,
		EncoderModule: encoderModule,
		Options:       ModuleOptions,
	}
	var res ModuleEncodeRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleEncodeRes{}, err
	}
	return res, nil
}

func (msf *Client) ModuleExecute(ModuleType, ModuleName string, ModuleOptions map[string]string) (ModuleExecuteRes, error) {
	ctx := &ModuleExecuteReq{
		Method:     "module.execute",
		Token:      msf.token,
		ModuleType: ModuleType,
		ModuleName: ModuleName,
		Options:    ModuleOptions,
	}
	var res ModuleExecuteRes
	if err := msf.send(ctx, &res); err != nil {
		return ModuleExecuteRes{}, err
	}
	return res, nil
}

func (msf *Client) GetModuleRequires(ModuleType, ModuleName string) ([]string, error) {
	var returnValues []string

	options, err := msf.ModuleOptions(ModuleType, ModuleName)

	if err != nil {
		return nil, err
	}

	for key, option := range options {
		if option.Required {
			returnValues = append(returnValues, key)
		}
	}
	return returnValues, nil
}
