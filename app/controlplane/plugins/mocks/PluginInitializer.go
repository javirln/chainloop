// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	mock "github.com/stretchr/testify/mock"

	sdk "github.com/chainloop-dev/chainloop/app/controlplane/plugins/sdk/v1"
)

// PluginInitializer is an autogenerated mock type for the PluginInitializer type
type PluginInitializer struct {
	mock.Mock
}

// Init provides a mock function with given fields: path
func (_m *PluginInitializer) Init(path string) (*sdk.FanOutP, error) {
	ret := _m.Called(path)

	var r0 *sdk.FanOutP
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*sdk.FanOutP, error)); ok {
		return rf(path)
	}
	if rf, ok := ret.Get(0).(func(string) *sdk.FanOutP); ok {
		r0 = rf(path)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*sdk.FanOutP)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(path)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewPluginInitializer interface {
	mock.TestingT
	Cleanup(func())
}

// NewPluginInitializer creates a new instance of PluginInitializer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewPluginInitializer(t mockConstructorTestingTNewPluginInitializer) *PluginInitializer {
	mock := &PluginInitializer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
