//
// Copyright 2024 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: controlplane/v1/referrer.proto

package v1

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ReferrerServiceDiscoverPrivateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Digest string `protobuf:"bytes,1,opt,name=digest,proto3" json:"digest,omitempty"`
	// Optional kind of referrer, i.e CONTAINER_IMAGE, GIT_HEAD, ...
	// Used to filter and resolve ambiguities
	Kind string `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
}

func (x *ReferrerServiceDiscoverPrivateRequest) Reset() {
	*x = ReferrerServiceDiscoverPrivateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_referrer_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReferrerServiceDiscoverPrivateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReferrerServiceDiscoverPrivateRequest) ProtoMessage() {}

func (x *ReferrerServiceDiscoverPrivateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_referrer_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReferrerServiceDiscoverPrivateRequest.ProtoReflect.Descriptor instead.
func (*ReferrerServiceDiscoverPrivateRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_referrer_proto_rawDescGZIP(), []int{0}
}

func (x *ReferrerServiceDiscoverPrivateRequest) GetDigest() string {
	if x != nil {
		return x.Digest
	}
	return ""
}

func (x *ReferrerServiceDiscoverPrivateRequest) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

type DiscoverPublicSharedRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Digest string `protobuf:"bytes,1,opt,name=digest,proto3" json:"digest,omitempty"`
	// Optional kind of referrer, i.e CONTAINER_IMAGE, GIT_HEAD, ...
	// Used to filter and resolve ambiguities
	Kind string `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
}

func (x *DiscoverPublicSharedRequest) Reset() {
	*x = DiscoverPublicSharedRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_referrer_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DiscoverPublicSharedRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DiscoverPublicSharedRequest) ProtoMessage() {}

func (x *DiscoverPublicSharedRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_referrer_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DiscoverPublicSharedRequest.ProtoReflect.Descriptor instead.
func (*DiscoverPublicSharedRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_referrer_proto_rawDescGZIP(), []int{1}
}

func (x *DiscoverPublicSharedRequest) GetDigest() string {
	if x != nil {
		return x.Digest
	}
	return ""
}

func (x *DiscoverPublicSharedRequest) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

type DiscoverPublicSharedResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result *ReferrerItem `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *DiscoverPublicSharedResponse) Reset() {
	*x = DiscoverPublicSharedResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_referrer_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DiscoverPublicSharedResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DiscoverPublicSharedResponse) ProtoMessage() {}

func (x *DiscoverPublicSharedResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_referrer_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DiscoverPublicSharedResponse.ProtoReflect.Descriptor instead.
func (*DiscoverPublicSharedResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_referrer_proto_rawDescGZIP(), []int{2}
}

func (x *DiscoverPublicSharedResponse) GetResult() *ReferrerItem {
	if x != nil {
		return x.Result
	}
	return nil
}

type ReferrerServiceDiscoverPrivateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result *ReferrerItem `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *ReferrerServiceDiscoverPrivateResponse) Reset() {
	*x = ReferrerServiceDiscoverPrivateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_referrer_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReferrerServiceDiscoverPrivateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReferrerServiceDiscoverPrivateResponse) ProtoMessage() {}

func (x *ReferrerServiceDiscoverPrivateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_referrer_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReferrerServiceDiscoverPrivateResponse.ProtoReflect.Descriptor instead.
func (*ReferrerServiceDiscoverPrivateResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_referrer_proto_rawDescGZIP(), []int{3}
}

func (x *ReferrerServiceDiscoverPrivateResponse) GetResult() *ReferrerItem {
	if x != nil {
		return x.Result
	}
	return nil
}

type ReferrerItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Digest of the referrer, i.e sha256:deadbeef or sha1:beefdead
	Digest string `protobuf:"bytes,1,opt,name=digest,proto3" json:"digest,omitempty"`
	// Kind of referrer, i.e CONTAINER_IMAGE, GIT_HEAD, ...
	Kind string `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
	// Whether the referrer is downloadable or not from CAS
	Downloadable bool `protobuf:"varint,3,opt,name=downloadable,proto3" json:"downloadable,omitempty"`
	// Whether the referrer is public since it belongs to a public workflow
	Public      bool                   `protobuf:"varint,6,opt,name=public,proto3" json:"public,omitempty"`
	References  []*ReferrerItem        `protobuf:"bytes,4,rep,name=references,proto3" json:"references,omitempty"`
	CreatedAt   *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	Metadata    map[string]string      `protobuf:"bytes,7,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Annotations map[string]string      `protobuf:"bytes,8,rep,name=annotations,proto3" json:"annotations,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ReferrerItem) Reset() {
	*x = ReferrerItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_referrer_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReferrerItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReferrerItem) ProtoMessage() {}

func (x *ReferrerItem) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_referrer_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReferrerItem.ProtoReflect.Descriptor instead.
func (*ReferrerItem) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_referrer_proto_rawDescGZIP(), []int{4}
}

func (x *ReferrerItem) GetDigest() string {
	if x != nil {
		return x.Digest
	}
	return ""
}

func (x *ReferrerItem) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *ReferrerItem) GetDownloadable() bool {
	if x != nil {
		return x.Downloadable
	}
	return false
}

func (x *ReferrerItem) GetPublic() bool {
	if x != nil {
		return x.Public
	}
	return false
}

func (x *ReferrerItem) GetReferences() []*ReferrerItem {
	if x != nil {
		return x.References
	}
	return nil
}

func (x *ReferrerItem) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *ReferrerItem) GetMetadata() map[string]string {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *ReferrerItem) GetAnnotations() map[string]string {
	if x != nil {
		return x.Annotations
	}
	return nil
}

var File_controlplane_v1_referrer_proto protoreflect.FileDescriptor

var file_controlplane_v1_referrer_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x72, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76,
	0x31, 0x1a, 0x1b, 0x62, 0x75, 0x66, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5c, 0x0a,
	0x25, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x06, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xba, 0x48, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52,
	0x06, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x22, 0x52, 0x0a, 0x1b, 0x44,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x53, 0x68, 0x61,
	0x72, 0x65, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x06, 0x64, 0x69,
	0x67, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xba, 0x48, 0x04, 0x72,
	0x02, 0x10, 0x01, 0x52, 0x06, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6b,
	0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x22,
	0x55, 0x0a, 0x1c, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x35, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x06,
	0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x5f, 0x0a, 0x26, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72,
	0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x35, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x52,
	0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x88, 0x04, 0x0a, 0x0c, 0x52, 0x65, 0x66, 0x65,
	0x72, 0x72, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x69, 0x67, 0x65,
	0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6b, 0x69, 0x6e, 0x64, 0x12, 0x22, 0x0a, 0x0c, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64,
	0x61, 0x62, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x64, 0x6f, 0x77, 0x6e,
	0x6c, 0x6f, 0x61, 0x64, 0x61, 0x62, 0x6c, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x12, 0x3d, 0x0a, 0x0a, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c,
	0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x49,
	0x74, 0x65, 0x6d, 0x52, 0x0a, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x12,
	0x39, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x47, 0x0a, 0x08, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52,
	0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x2e, 0x4d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x12, 0x50, 0x0a, 0x0b, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x66, 0x65, 0x72,
	0x72, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x2e, 0x41, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x3b, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x1a, 0x3e, 0x0a, 0x10, 0x41, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x32, 0xcb, 0x02, 0x0a, 0x0f, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x9e, 0x01, 0x0a, 0x0f, 0x44, 0x69, 0x73, 0x63, 0x6f,
	0x76, 0x65, 0x72, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x12, 0x36, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x66,
	0x65, 0x72, 0x72, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x44, 0x69, 0x73, 0x63,
	0x6f, 0x76, 0x65, 0x72, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x37, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x72, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x50, 0x72, 0x69, 0x76,
	0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1a, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x14, 0x12, 0x12, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x2f, 0x7b,
	0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x7d, 0x12, 0x96, 0x01, 0x0a, 0x14, 0x44, 0x69, 0x73, 0x63,
	0x6f, 0x76, 0x65, 0x72, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64,
	0x12, 0x2c, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x21, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x1b, 0x12, 0x19, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2f, 0x7b, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x7d,
	0x42, 0x4c, 0x5a, 0x4a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63,
	0x68, 0x61, 0x69, 0x6e, 0x6c, 0x6f, 0x6f, 0x70, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x63, 0x68, 0x61,
	0x69, 0x6e, 0x6c, 0x6f, 0x6f, 0x70, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x76, 0x31, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controlplane_v1_referrer_proto_rawDescOnce sync.Once
	file_controlplane_v1_referrer_proto_rawDescData = file_controlplane_v1_referrer_proto_rawDesc
)

func file_controlplane_v1_referrer_proto_rawDescGZIP() []byte {
	file_controlplane_v1_referrer_proto_rawDescOnce.Do(func() {
		file_controlplane_v1_referrer_proto_rawDescData = protoimpl.X.CompressGZIP(file_controlplane_v1_referrer_proto_rawDescData)
	})
	return file_controlplane_v1_referrer_proto_rawDescData
}

var file_controlplane_v1_referrer_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_controlplane_v1_referrer_proto_goTypes = []interface{}{
	(*ReferrerServiceDiscoverPrivateRequest)(nil),  // 0: controlplane.v1.ReferrerServiceDiscoverPrivateRequest
	(*DiscoverPublicSharedRequest)(nil),            // 1: controlplane.v1.DiscoverPublicSharedRequest
	(*DiscoverPublicSharedResponse)(nil),           // 2: controlplane.v1.DiscoverPublicSharedResponse
	(*ReferrerServiceDiscoverPrivateResponse)(nil), // 3: controlplane.v1.ReferrerServiceDiscoverPrivateResponse
	(*ReferrerItem)(nil),                           // 4: controlplane.v1.ReferrerItem
	nil,                                            // 5: controlplane.v1.ReferrerItem.MetadataEntry
	nil,                                            // 6: controlplane.v1.ReferrerItem.AnnotationsEntry
	(*timestamppb.Timestamp)(nil),                  // 7: google.protobuf.Timestamp
}
var file_controlplane_v1_referrer_proto_depIdxs = []int32{
	4, // 0: controlplane.v1.DiscoverPublicSharedResponse.result:type_name -> controlplane.v1.ReferrerItem
	4, // 1: controlplane.v1.ReferrerServiceDiscoverPrivateResponse.result:type_name -> controlplane.v1.ReferrerItem
	4, // 2: controlplane.v1.ReferrerItem.references:type_name -> controlplane.v1.ReferrerItem
	7, // 3: controlplane.v1.ReferrerItem.created_at:type_name -> google.protobuf.Timestamp
	5, // 4: controlplane.v1.ReferrerItem.metadata:type_name -> controlplane.v1.ReferrerItem.MetadataEntry
	6, // 5: controlplane.v1.ReferrerItem.annotations:type_name -> controlplane.v1.ReferrerItem.AnnotationsEntry
	0, // 6: controlplane.v1.ReferrerService.DiscoverPrivate:input_type -> controlplane.v1.ReferrerServiceDiscoverPrivateRequest
	1, // 7: controlplane.v1.ReferrerService.DiscoverPublicShared:input_type -> controlplane.v1.DiscoverPublicSharedRequest
	3, // 8: controlplane.v1.ReferrerService.DiscoverPrivate:output_type -> controlplane.v1.ReferrerServiceDiscoverPrivateResponse
	2, // 9: controlplane.v1.ReferrerService.DiscoverPublicShared:output_type -> controlplane.v1.DiscoverPublicSharedResponse
	8, // [8:10] is the sub-list for method output_type
	6, // [6:8] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_controlplane_v1_referrer_proto_init() }
func file_controlplane_v1_referrer_proto_init() {
	if File_controlplane_v1_referrer_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controlplane_v1_referrer_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReferrerServiceDiscoverPrivateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_referrer_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DiscoverPublicSharedRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_referrer_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DiscoverPublicSharedResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_referrer_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReferrerServiceDiscoverPrivateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_referrer_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReferrerItem); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controlplane_v1_referrer_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controlplane_v1_referrer_proto_goTypes,
		DependencyIndexes: file_controlplane_v1_referrer_proto_depIdxs,
		MessageInfos:      file_controlplane_v1_referrer_proto_msgTypes,
	}.Build()
	File_controlplane_v1_referrer_proto = out.File
	file_controlplane_v1_referrer_proto_rawDesc = nil
	file_controlplane_v1_referrer_proto_goTypes = nil
	file_controlplane_v1_referrer_proto_depIdxs = nil
}
