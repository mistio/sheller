package MachineSSH

type ExecConfig struct {
	User string
	Host string
	Port string
}

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}
