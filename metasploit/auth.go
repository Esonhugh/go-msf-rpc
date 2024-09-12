package metasploit

import "fmt"

// Auth
type LoginReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Username string
	Password string
}

type LoginRes struct {
	Result       string `msgpack:"result"`
	Token        string `msgpack:"token"`
	Error        bool   `msgpack:"error"`
	ErrorClass   string `msgpack:"error_class"`
	ErrorMessage string `msgpack:"error_message"`
}

type LogoutReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	LogoutToken string
}

type LogoutRes struct {
	Result string `msgpack:"result"`
}

func (msf *Client) Login() error {
	ctx := &LoginReq{
		Method:   "auth.login",
		Username: msf.user,
		Password: msf.pass,
	}

	var res LoginRes
	if err := msf.send(ctx, &res); err != nil {
		fmt.Println("Failed at login")
		return err
	}
	msf.token = res.Token
	return nil
}

func (msf *Client) Logout() error {
	ctx := &LogoutReq{
		Method:      "auth.logout",
		Token:       msf.token,
		LogoutToken: msf.token,
	}

	var res LogoutRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}
	msf.token = ""
	return nil
}
