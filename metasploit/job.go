package metasploit

// Jobs

type JobListReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

type JobListRes map[string]string

type JobInfoReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
	JobId    string
}

type JobInfoRes struct {
	Jid       int                    `msgpack:"jid"`
	Name      string                 `msgpack:"name"`
	StartTime int                    `msgpack:"start_time"`
	UriPath   interface{}            `msgpack:"uripath,omitempty"`
	Datastore map[string]interface{} `msgpack:"datastore,omitempty"`
}

type JobStopReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
	JobId    string
}

type JobStopRes struct {
	Result string `msgpack:"result"`
}

// Jobs

func (msf *Client) JobList() (JobListRes, error) {
	ctx := &JobListReq{
		Method: "job.list",
		Token:  msf.token,
	}
	var res JobListRes
	if err := msf.send(ctx, &res); err != nil {
		return JobListRes{}, err
	}
	return res, nil
}

func (msf *Client) JobInfo(jobId string) (JobInfoRes, error) {
	ctx := &JobInfoReq{
		Method: "job.info",
		Token:  msf.token,
		JobId:  jobId,
	}
	var res JobInfoRes
	if err := msf.send(ctx, &res); err != nil {
		return JobInfoRes{}, err
	}
	return res, nil
}

func (msf *Client) JobStop(jobId string) (JobStopRes, error) {
	ctx := &JobStopReq{
		Method: "job.stop",
		Token:  msf.token,
		JobId:  jobId,
	}
	var res JobStopRes
	if err := msf.send(ctx, &res); err != nil {
		return JobStopRes{}, err
	}
	return res, nil
}
