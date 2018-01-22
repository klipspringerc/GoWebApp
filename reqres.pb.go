// Code generated by protoc-gen-go. DO NOT EDIT.
// source: reqres.proto

/*
Package main is a generated protocol buffer package.

It is generated from these files:
	reqres.proto

It has these top-level messages:
	LoginRequest
	UpdatePicRequest
	UpdateNickRequest
	UpdateBothRequest
	GetProfileRequest
	Request
	QueryResponse
	AckResponse
*/
package main

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Command int32

const (
	Command_LOGIN          Command = 0
	Command_UPDATEPICTURE  Command = 1
	Command_UPDATENICKNAME Command = 2
	Command_UPDATEBOTH     Command = 3
	Command_GETPROFILE     Command = 4
)

var Command_name = map[int32]string{
	0: "LOGIN",
	1: "UPDATEPICTURE",
	2: "UPDATENICKNAME",
	3: "UPDATEBOTH",
	4: "GETPROFILE",
}
var Command_value = map[string]int32{
	"LOGIN":          0,
	"UPDATEPICTURE":  1,
	"UPDATENICKNAME": 2,
	"UPDATEBOTH":     3,
	"GETPROFILE":     4,
}

func (x Command) String() string {
	return proto.EnumName(Command_name, int32(x))
}
func (Command) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type LoginRequest struct {
	Username string `protobuf:"bytes,1,opt,name=username" json:"username,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password" json:"password,omitempty"`
}

func (m *LoginRequest) Reset()                    { *m = LoginRequest{} }
func (m *LoginRequest) String() string            { return proto.CompactTextString(m) }
func (*LoginRequest) ProtoMessage()               {}
func (*LoginRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *LoginRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *LoginRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type UpdatePicRequest struct {
	Username string `protobuf:"bytes,1,opt,name=username" json:"username,omitempty"`
	Picture  []byte `protobuf:"bytes,2,opt,name=picture,proto3" json:"picture,omitempty"`
}

func (m *UpdatePicRequest) Reset()                    { *m = UpdatePicRequest{} }
func (m *UpdatePicRequest) String() string            { return proto.CompactTextString(m) }
func (*UpdatePicRequest) ProtoMessage()               {}
func (*UpdatePicRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *UpdatePicRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *UpdatePicRequest) GetPicture() []byte {
	if m != nil {
		return m.Picture
	}
	return nil
}

type UpdateNickRequest struct {
	Username string `protobuf:"bytes,1,opt,name=username" json:"username,omitempty"`
	Nickname string `protobuf:"bytes,2,opt,name=nickname" json:"nickname,omitempty"`
}

func (m *UpdateNickRequest) Reset()                    { *m = UpdateNickRequest{} }
func (m *UpdateNickRequest) String() string            { return proto.CompactTextString(m) }
func (*UpdateNickRequest) ProtoMessage()               {}
func (*UpdateNickRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *UpdateNickRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *UpdateNickRequest) GetNickname() string {
	if m != nil {
		return m.Nickname
	}
	return ""
}

type UpdateBothRequest struct {
	Username string `protobuf:"bytes,1,opt,name=username" json:"username,omitempty"`
	Nickname string `protobuf:"bytes,2,opt,name=nickname" json:"nickname,omitempty"`
	Picture  []byte `protobuf:"bytes,3,opt,name=picture,proto3" json:"picture,omitempty"`
}

func (m *UpdateBothRequest) Reset()                    { *m = UpdateBothRequest{} }
func (m *UpdateBothRequest) String() string            { return proto.CompactTextString(m) }
func (*UpdateBothRequest) ProtoMessage()               {}
func (*UpdateBothRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *UpdateBothRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *UpdateBothRequest) GetNickname() string {
	if m != nil {
		return m.Nickname
	}
	return ""
}

func (m *UpdateBothRequest) GetPicture() []byte {
	if m != nil {
		return m.Picture
	}
	return nil
}

type GetProfileRequest struct {
	Username string `protobuf:"bytes,1,opt,name=username" json:"username,omitempty"`
}

func (m *GetProfileRequest) Reset()                    { *m = GetProfileRequest{} }
func (m *GetProfileRequest) String() string            { return proto.CompactTextString(m) }
func (*GetProfileRequest) ProtoMessage()               {}
func (*GetProfileRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *GetProfileRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

type Request struct {
	Command Command `protobuf:"varint,1,opt,name=command,enum=main.Command" json:"command,omitempty"`
	Token   string  `protobuf:"bytes,2,opt,name=token" json:"token,omitempty"`
	// Types that are valid to be assigned to Req:
	//	*Request_Login
	//	*Request_Updatepicture
	//	*Request_Updatenickname
	//	*Request_Updateboth
	//	*Request_Getprofile
	Req isRequest_Req `protobuf_oneof:"req"`
}

func (m *Request) Reset()                    { *m = Request{} }
func (m *Request) String() string            { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()               {}
func (*Request) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

type isRequest_Req interface {
	isRequest_Req()
}

type Request_Login struct {
	Login *LoginRequest `protobuf:"bytes,3,opt,name=login,oneof"`
}
type Request_Updatepicture struct {
	Updatepicture *UpdatePicRequest `protobuf:"bytes,4,opt,name=updatepicture,oneof"`
}
type Request_Updatenickname struct {
	Updatenickname *UpdateNickRequest `protobuf:"bytes,5,opt,name=updatenickname,oneof"`
}
type Request_Updateboth struct {
	Updateboth *UpdateBothRequest `protobuf:"bytes,6,opt,name=updateboth,oneof"`
}
type Request_Getprofile struct {
	Getprofile *GetProfileRequest `protobuf:"bytes,7,opt,name=getprofile,oneof"`
}

func (*Request_Login) isRequest_Req()          {}
func (*Request_Updatepicture) isRequest_Req()  {}
func (*Request_Updatenickname) isRequest_Req() {}
func (*Request_Updateboth) isRequest_Req()     {}
func (*Request_Getprofile) isRequest_Req()     {}

func (m *Request) GetReq() isRequest_Req {
	if m != nil {
		return m.Req
	}
	return nil
}

func (m *Request) GetCommand() Command {
	if m != nil {
		return m.Command
	}
	return Command_LOGIN
}

func (m *Request) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *Request) GetLogin() *LoginRequest {
	if x, ok := m.GetReq().(*Request_Login); ok {
		return x.Login
	}
	return nil
}

func (m *Request) GetUpdatepicture() *UpdatePicRequest {
	if x, ok := m.GetReq().(*Request_Updatepicture); ok {
		return x.Updatepicture
	}
	return nil
}

func (m *Request) GetUpdatenickname() *UpdateNickRequest {
	if x, ok := m.GetReq().(*Request_Updatenickname); ok {
		return x.Updatenickname
	}
	return nil
}

func (m *Request) GetUpdateboth() *UpdateBothRequest {
	if x, ok := m.GetReq().(*Request_Updateboth); ok {
		return x.Updateboth
	}
	return nil
}

func (m *Request) GetGetprofile() *GetProfileRequest {
	if x, ok := m.GetReq().(*Request_Getprofile); ok {
		return x.Getprofile
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Request) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Request_OneofMarshaler, _Request_OneofUnmarshaler, _Request_OneofSizer, []interface{}{
		(*Request_Login)(nil),
		(*Request_Updatepicture)(nil),
		(*Request_Updatenickname)(nil),
		(*Request_Updateboth)(nil),
		(*Request_Getprofile)(nil),
	}
}

func _Request_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Request)
	// req
	switch x := m.Req.(type) {
	case *Request_Login:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Login); err != nil {
			return err
		}
	case *Request_Updatepicture:
		b.EncodeVarint(4<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Updatepicture); err != nil {
			return err
		}
	case *Request_Updatenickname:
		b.EncodeVarint(5<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Updatenickname); err != nil {
			return err
		}
	case *Request_Updateboth:
		b.EncodeVarint(6<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Updateboth); err != nil {
			return err
		}
	case *Request_Getprofile:
		b.EncodeVarint(7<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Getprofile); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Request.Req has unexpected type %T", x)
	}
	return nil
}

func _Request_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Request)
	switch tag {
	case 3: // req.login
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(LoginRequest)
		err := b.DecodeMessage(msg)
		m.Req = &Request_Login{msg}
		return true, err
	case 4: // req.updatepicture
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(UpdatePicRequest)
		err := b.DecodeMessage(msg)
		m.Req = &Request_Updatepicture{msg}
		return true, err
	case 5: // req.updatenickname
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(UpdateNickRequest)
		err := b.DecodeMessage(msg)
		m.Req = &Request_Updatenickname{msg}
		return true, err
	case 6: // req.updateboth
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(UpdateBothRequest)
		err := b.DecodeMessage(msg)
		m.Req = &Request_Updateboth{msg}
		return true, err
	case 7: // req.getprofile
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(GetProfileRequest)
		err := b.DecodeMessage(msg)
		m.Req = &Request_Getprofile{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Request_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Request)
	// req
	switch x := m.Req.(type) {
	case *Request_Login:
		s := proto.Size(x.Login)
		n += proto.SizeVarint(3<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Request_Updatepicture:
		s := proto.Size(x.Updatepicture)
		n += proto.SizeVarint(4<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Request_Updatenickname:
		s := proto.Size(x.Updatenickname)
		n += proto.SizeVarint(5<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Request_Updateboth:
		s := proto.Size(x.Updateboth)
		n += proto.SizeVarint(6<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Request_Getprofile:
		s := proto.Size(x.Getprofile)
		n += proto.SizeVarint(7<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type QueryResponse struct {
	Token    string `protobuf:"bytes,1,opt,name=token" json:"token,omitempty"`
	Status   bool   `protobuf:"varint,2,opt,name=status" json:"status,omitempty"`
	Username string `protobuf:"bytes,3,opt,name=username" json:"username,omitempty"`
	Nickname string `protobuf:"bytes,4,opt,name=nickname" json:"nickname,omitempty"`
	Picture  []byte `protobuf:"bytes,5,opt,name=picture,proto3" json:"picture,omitempty"`
}

func (m *QueryResponse) Reset()                    { *m = QueryResponse{} }
func (m *QueryResponse) String() string            { return proto.CompactTextString(m) }
func (*QueryResponse) ProtoMessage()               {}
func (*QueryResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *QueryResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *QueryResponse) GetStatus() bool {
	if m != nil {
		return m.Status
	}
	return false
}

func (m *QueryResponse) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *QueryResponse) GetNickname() string {
	if m != nil {
		return m.Nickname
	}
	return ""
}

func (m *QueryResponse) GetPicture() []byte {
	if m != nil {
		return m.Picture
	}
	return nil
}

type AckResponse struct {
	Token  string `protobuf:"bytes,1,opt,name=token" json:"token,omitempty"`
	Status bool   `protobuf:"varint,2,opt,name=status" json:"status,omitempty"`
}

func (m *AckResponse) Reset()                    { *m = AckResponse{} }
func (m *AckResponse) String() string            { return proto.CompactTextString(m) }
func (*AckResponse) ProtoMessage()               {}
func (*AckResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *AckResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *AckResponse) GetStatus() bool {
	if m != nil {
		return m.Status
	}
	return false
}

func init() {
	proto.RegisterType((*LoginRequest)(nil), "main.LoginRequest")
	proto.RegisterType((*UpdatePicRequest)(nil), "main.UpdatePicRequest")
	proto.RegisterType((*UpdateNickRequest)(nil), "main.UpdateNickRequest")
	proto.RegisterType((*UpdateBothRequest)(nil), "main.UpdateBothRequest")
	proto.RegisterType((*GetProfileRequest)(nil), "main.GetProfileRequest")
	proto.RegisterType((*Request)(nil), "main.Request")
	proto.RegisterType((*QueryResponse)(nil), "main.QueryResponse")
	proto.RegisterType((*AckResponse)(nil), "main.AckResponse")
	proto.RegisterEnum("main.Command", Command_name, Command_value)
}

func init() { proto.RegisterFile("reqres.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 461 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x54, 0xc1, 0x6e, 0xda, 0x40,
	0x14, 0xb4, 0x01, 0xe3, 0xe4, 0x05, 0x90, 0x59, 0x55, 0xa9, 0xd5, 0x53, 0xe5, 0x4b, 0xab, 0x1c,
	0xa8, 0x94, 0x9e, 0xaa, 0x4a, 0x95, 0x80, 0x3a, 0x18, 0x85, 0x82, 0xbb, 0x82, 0x53, 0x4f, 0x8e,
	0x79, 0x4d, 0x2c, 0x82, 0xd7, 0xec, 0xae, 0x55, 0xf5, 0x2b, 0xfa, 0xb3, 0xfd, 0x80, 0xca, 0xbb,
	0x38, 0xb1, 0x83, 0x5a, 0xa1, 0xe6, 0x38, 0x6f, 0xdf, 0x0c, 0xc3, 0xcc, 0x93, 0xa1, 0xc3, 0x71,
	0xc7, 0x51, 0x0c, 0x32, 0xce, 0x24, 0x23, 0xad, 0x6d, 0x94, 0xa4, 0xde, 0x15, 0x74, 0x66, 0xec,
	0x36, 0x49, 0x29, 0xee, 0x72, 0x14, 0x92, 0xbc, 0x82, 0x93, 0x5c, 0x20, 0x4f, 0xa3, 0x2d, 0xba,
	0xe6, 0x6b, 0xf3, 0xed, 0x29, 0x7d, 0xc0, 0xc5, 0x5b, 0x16, 0x09, 0xf1, 0x83, 0xf1, 0xb5, 0xdb,
	0xd0, 0x6f, 0x25, 0xf6, 0x02, 0x70, 0x56, 0xd9, 0x3a, 0x92, 0x18, 0x26, 0xf1, 0x31, 0x5a, 0x2e,
	0xd8, 0x59, 0x12, 0xcb, 0x9c, 0xa3, 0x92, 0xea, 0xd0, 0x12, 0x7a, 0xd7, 0xd0, 0xd7, 0x4a, 0xf3,
	0x24, 0xde, 0x1c, 0x69, 0x2b, 0x4d, 0xe2, 0x8d, 0x7a, 0xdb, 0xdb, 0x2a, 0xb1, 0x87, 0xa5, 0xd8,
	0x88, 0xc9, 0xbb, 0x67, 0x8a, 0x55, 0x3d, 0x37, 0xeb, 0x9e, 0xdf, 0x41, 0x7f, 0x82, 0x32, 0xe4,
	0xec, 0x7b, 0x72, 0x8f, 0x47, 0xfc, 0x8c, 0xf7, 0xbb, 0x01, 0x76, 0xb9, 0xf7, 0x06, 0xec, 0x98,
	0x6d, 0xb7, 0x51, 0xba, 0x56, 0x6b, 0xbd, 0xcb, 0xee, 0xa0, 0xa8, 0x66, 0x30, 0xd6, 0x43, 0x5a,
	0xbe, 0x92, 0x17, 0x60, 0x49, 0xb6, 0xc1, 0x74, 0x6f, 0x4c, 0x03, 0x72, 0x01, 0xd6, 0x7d, 0xd1,
	0xa0, 0xf2, 0x74, 0x76, 0x49, 0x34, 0xb9, 0x5a, 0x6a, 0x60, 0x50, 0xbd, 0x42, 0x3e, 0x41, 0x37,
	0x57, 0x71, 0x94, 0xff, 0xa3, 0xa5, 0x38, 0xe7, 0x9a, 0xf3, 0xb4, 0xc0, 0xc0, 0xa0, 0xf5, 0x75,
	0x32, 0x84, 0x9e, 0x1e, 0x3c, 0x64, 0x64, 0x29, 0x81, 0x97, 0x55, 0x81, 0x4a, 0x6f, 0x81, 0x41,
	0x9f, 0x10, 0xc8, 0x07, 0x00, 0x3d, 0xb9, 0x61, 0xf2, 0xce, 0x6d, 0x1f, 0xd2, 0x2b, 0x4d, 0x05,
	0x06, 0xad, 0x2c, 0x17, 0xd4, 0x5b, 0x94, 0x99, 0x4e, 0xd9, 0xb5, 0xab, 0xd4, 0x83, 0xf4, 0x0b,
	0xea, 0xe3, 0xf2, 0xc8, 0x82, 0x26, 0xc7, 0x9d, 0xf7, 0xcb, 0x84, 0xee, 0xd7, 0x1c, 0xf9, 0x4f,
	0x8a, 0x22, 0x63, 0xa9, 0xc0, 0xc7, 0x4c, 0xcd, 0x6a, 0xa6, 0xe7, 0xd0, 0x16, 0x32, 0x92, 0xb9,
	0x50, 0x51, 0x9f, 0xd0, 0x3d, 0xaa, 0x55, 0xda, 0xfc, 0xc7, 0xe5, 0xb4, 0xfe, 0x7e, 0x39, 0x56,
	0xfd, 0x72, 0x3e, 0xc2, 0xd9, 0xb0, 0x88, 0xeb, 0x7f, 0xec, 0x5c, 0x7c, 0x03, 0x7b, 0x7f, 0x24,
	0xe4, 0x14, 0xac, 0xd9, 0x62, 0x32, 0x9d, 0x3b, 0x06, 0xe9, 0x43, 0x77, 0x15, 0x7e, 0x1e, 0x2e,
	0xfd, 0x70, 0x3a, 0x5e, 0xae, 0xa8, 0xef, 0x98, 0x84, 0x40, 0x4f, 0x8f, 0xe6, 0xd3, 0xf1, 0xf5,
	0x7c, 0xf8, 0xc5, 0x77, 0x1a, 0xa4, 0x07, 0xa0, 0x67, 0xa3, 0xc5, 0x32, 0x70, 0x9a, 0x05, 0x9e,
	0xf8, 0xcb, 0x90, 0x2e, 0xae, 0xa6, 0x33, 0xdf, 0x69, 0xdd, 0xb4, 0xd5, 0x67, 0xe2, 0xfd, 0x9f,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x09, 0x5f, 0xf7, 0x31, 0x36, 0x04, 0x00, 0x00,
}
