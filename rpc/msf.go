package rpc

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"reflect"

	"github.com/sirupsen/logrus"
	"gopkg.in/vmihailenco/msgpack.v2"
)

type Metasploit struct {
	host     string
	user     string
	pass     string
	token    string
	Debug    bool
	Insecure bool // todo: implement
	logger   *logrus.Entry
}

func New(host, user, pass string) (*Metasploit, error) {
	defaultLogger := logrus.New()
	defaultLogger.SetLevel(logrus.FatalLevel)
	msf := &Metasploit{
		host:     host,
		user:     user,
		pass:     pass,
		Debug:    false,
		Insecure: false,
		logger:   logrus.NewEntry(defaultLogger),
	}
	if err := msf.Login(); err != nil {
		return nil, err
	}
	return msf, nil
}

func (msf *Metasploit) Token() string {
	return msf.token
}

func (msf *Metasploit) WithDebug(debug bool) *Metasploit {
	msf.Debug = debug
	return msf
}

func (msf *Metasploit) WithInsecure(insecure bool) *Metasploit {
	msf.Insecure = insecure
	return msf
}

func (msf *Metasploit) WithLogger(logger *logrus.Entry) *Metasploit {
	msf.logger = logger
	return msf
}

func (msf *Metasploit) Send(req any, res any) error {
	if reflect.TypeOf(res).Kind() != reflect.Ptr {
		return fmt.Errorf("res must be a pointer to recevie response")
	}
	if !reflect.ValueOf(req).FieldByName("_msgpack").IsValid() {
		return fmt.Errorf("req must have _msgpack field")
	}
	return msf.send(req, &res)
}

func (msf *Metasploit) send(req any, res any) error {
	buf := new(bytes.Buffer)
	msgpack.NewEncoder(buf).Encode(req)
	if msf.Debug {
		msf.logger.Printf("%v", req)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	dest := fmt.Sprintf("%s/api", msf.host)
	response, err := http.Post(dest, "binary/message-pack", buf)
	// responseBytes, _ := httputil.DumpResponse(response, true)
	// log.Printf("Response dump: %s\n", string(responseBytes))
	if err != nil {
		return err
	}

	if msf.Debug {
		data, err := httputil.DumpRequest(response.Request, true)
		if err != nil {
			msf.logger.Errorf("Failed to dump request: %s\n", err)
		} else {
			msf.logger.Printf("Request:\n%s\n", string(data))
		}
		data, err = httputil.DumpResponse(response, true)
		if err != nil {
			msf.logger.Errorf("Failed to dump response: %s\n", err)
		} else {
			msf.logger.Printf("Response:\n%s\n", string(data))
		}
	}

	defer response.Body.Close()
	if err := msgpack.NewDecoder(response.Body).Decode(&res); err != nil {
		return err
	}
	if msf.Debug {
		msf.logger.Printf("Response: %v\n", res)
	}
	return nil
}
