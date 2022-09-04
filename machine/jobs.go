package machine

import "sync"

type ScriptJobs struct {
	mu       sync.Mutex
	Requests map[string]SSHRequest
}

func (s *ScriptJobs) Update(jobId string, data SSHRequest) {
	s.mu.Lock()
	s.Requests[jobId] = data
	s.mu.Unlock()
}

func (s *ScriptJobs) Get(jobId string) SSHRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Requests[jobId]
}
