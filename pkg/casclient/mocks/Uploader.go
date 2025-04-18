// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	context "context"

	casclient "github.com/chainloop-dev/chainloop/pkg/casclient"

	io "io"

	mock "github.com/stretchr/testify/mock"
)

// Uploader is an autogenerated mock type for the Uploader type
type Uploader struct {
	mock.Mock
}

// IsReady provides a mock function with given fields: ctx
func (_m *Uploader) IsReady(ctx context.Context) (bool, error) {
	ret := _m.Called(ctx)

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (bool, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) bool); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Upload provides a mock function with given fields: ctx, r, digest, fileName
func (_m *Uploader) Upload(ctx context.Context, r io.Reader, digest string, fileName string) (*casclient.UpDownStatus, error) {
	ret := _m.Called(ctx, r, digest, fileName)

	var r0 *casclient.UpDownStatus
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, io.Reader, string, string) (*casclient.UpDownStatus, error)); ok {
		return rf(ctx, r, digest, fileName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, io.Reader, string, string) *casclient.UpDownStatus); ok {
		r0 = rf(ctx, r, digest, fileName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*casclient.UpDownStatus)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, io.Reader, string, string) error); ok {
		r1 = rf(ctx, r, digest, fileName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UploadFile provides a mock function with given fields: ctx, filepath
func (_m *Uploader) UploadFile(ctx context.Context, filepath string) (*casclient.UpDownStatus, error) {
	ret := _m.Called(ctx, filepath)

	var r0 *casclient.UpDownStatus
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*casclient.UpDownStatus, error)); ok {
		return rf(ctx, filepath)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *casclient.UpDownStatus); ok {
		r0 = rf(ctx, filepath)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*casclient.UpDownStatus)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, filepath)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewUploader interface {
	mock.TestingT
	Cleanup(func())
}

// NewUploader creates a new instance of Uploader. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewUploader(t mockConstructorTestingTNewUploader) *Uploader {
	mock := &Uploader{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
