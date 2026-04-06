//go:build !windows

package service

import (
	"errors"

	"netch_go/internal/model"
)

type DNSCaptureMonitor struct{}

func NewDNSCaptureMonitor(logf func(string, string), onDomain func(string)) *DNSCaptureMonitor {
	_ = logf
	_ = onDomain
	return &DNSCaptureMonitor{}
}

func (m *DNSCaptureMonitor) Status() model.DNSCaptureState {
	_ = m
	return model.DNSCaptureState{
		Enabled:        false,
		ChannelEnabled: false,
		Capturing:      false,
		Message:        "当前平台不支持 DNS Client ETW 抓取",
		Domains:        []string{},
	}
}

func (m *DNSCaptureMonitor) SetEnabled(enabled bool, sessionRunning bool, ruleSet model.RuleSet) (model.DNSCaptureState, error) {
	_ = m
	_ = enabled
	_ = sessionRunning
	_ = ruleSet
	state := model.DNSCaptureState{
		Enabled:        false,
		ChannelEnabled: false,
		Capturing:      false,
		Message:        "当前平台不支持 DNS Client ETW 抓取",
		Domains:        []string{},
	}
	return state, errors.New(state.Message)
}
