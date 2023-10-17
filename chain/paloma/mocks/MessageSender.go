// Code generated by mockery v2.35.4. DO NOT EDIT.

package mocks

import (
	context "context"

	types "github.com/cosmos/cosmos-sdk/types"
	mock "github.com/stretchr/testify/mock"
)

// MessageSender is an autogenerated mock type for the MessageSender type
type MessageSender struct {
	mock.Mock
}

// SendMsg provides a mock function with given fields: ctx, msg, memo
func (_m *MessageSender) SendMsg(ctx context.Context, msg types.Msg, memo string) (*types.TxResponse, error) {
	ret := _m.Called(ctx, msg, memo)

	var r0 *types.TxResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, types.Msg, string) (*types.TxResponse, error)); ok {
		return rf(ctx, msg, memo)
	}
	if rf, ok := ret.Get(0).(func(context.Context, types.Msg, string) *types.TxResponse); ok {
		r0 = rf(ctx, msg, memo)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.TxResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, types.Msg, string) error); ok {
		r1 = rf(ctx, msg, memo)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewMessageSender creates a new instance of MessageSender. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMessageSender(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MessageSender {
	mock := &MessageSender{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
