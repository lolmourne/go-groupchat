// Code generated by MockGen. DO NOT EDIT.
// Source: resource/groupchat/init.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	model "github.com/lolmourne/go-groupchat/model"
)

// MockDBItf is a mock of DBItf interface.
type MockDBItf struct {
	ctrl     *gomock.Controller
	recorder *MockDBItfMockRecorder
}

// MockDBItfMockRecorder is the mock recorder for MockDBItf.
type MockDBItfMockRecorder struct {
	mock *MockDBItf
}

// NewMockDBItf creates a new mock instance.
func NewMockDBItf(ctrl *gomock.Controller) *MockDBItf {
	mock := &MockDBItf{ctrl: ctrl}
	mock.recorder = &MockDBItfMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDBItf) EXPECT() *MockDBItfMockRecorder {
	return m.recorder
}

// AddRoomParticipant mocks base method.
func (m *MockDBItf) AddRoomParticipant(roomID, userID int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRoomParticipant", roomID, userID)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRoomParticipant indicates an expected call of AddRoomParticipant.
func (mr *MockDBItfMockRecorder) AddRoomParticipant(roomID, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRoomParticipant", reflect.TypeOf((*MockDBItf)(nil).AddRoomParticipant), roomID, userID)
}

// CreateRoom mocks base method.
func (m *MockDBItf) CreateRoom(roomName string, adminID int64, description string, categoryID int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRoom", roomName, adminID, description, categoryID)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRoom indicates an expected call of CreateRoom.
func (mr *MockDBItfMockRecorder) CreateRoom(roomName, adminID, description, categoryID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRoom", reflect.TypeOf((*MockDBItf)(nil).CreateRoom), roomName, adminID, description, categoryID)
}

// GetJoinedRoom mocks base method.
func (m *MockDBItf) GetJoinedRoom(userID int64) ([]model.Room, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetJoinedRoom", userID)
	ret0, _ := ret[0].([]model.Room)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetJoinedRoom indicates an expected call of GetJoinedRoom.
func (mr *MockDBItfMockRecorder) GetJoinedRoom(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetJoinedRoom", reflect.TypeOf((*MockDBItf)(nil).GetJoinedRoom), userID)
}

// GetRoomByID mocks base method.
func (m *MockDBItf) GetRoomByID(roomID int64) (model.Room, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRoomByID", roomID)
	ret0, _ := ret[0].(model.Room)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRoomByID indicates an expected call of GetRoomByID.
func (mr *MockDBItfMockRecorder) GetRoomByID(roomID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRoomByID", reflect.TypeOf((*MockDBItf)(nil).GetRoomByID), roomID)
}

// GetRooms mocks base method.
func (m *MockDBItf) GetRooms(userID int64) ([]model.Room, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRooms", userID)
	ret0, _ := ret[0].([]model.Room)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRooms indicates an expected call of GetRooms.
func (mr *MockDBItfMockRecorder) GetRooms(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRooms", reflect.TypeOf((*MockDBItf)(nil).GetRooms), userID)
}
