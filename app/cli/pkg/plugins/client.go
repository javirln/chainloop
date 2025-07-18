//
// Copyright 2025 The Chainloop Authors.
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

package plugins

import (
	"context"
	"net/rpc"

	"github.com/hashicorp/go-plugin"
)

// ChainloopCliPlugin is the implementation of plugin.Plugin.
type ChainloopCliPlugin struct {
	Impl Plugin
}

func (p *ChainloopCliPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &RPCServer{Impl: p.Impl}, nil
}

func (ChainloopCliPlugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &RPCClient{client: c}, nil
}

// RPCClient is an implementation of Plugin that talks over RPC.
type RPCClient struct {
	client *rpc.Client
}

func (m *RPCClient) Exec(_ context.Context, config PluginExecConfig) (*PluginExecResult, error) {
	var resp PluginExecResult
	err := m.client.Call("Plugin.Exec", config, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *RPCClient) GetMetadata(_ context.Context) (PluginMetadata, error) {
	var resp PluginMetadata
	err := m.client.Call("Plugin.GetMetadata", new(any), &resp)
	return resp, err
}

// RPCServer is the RPC server that RPCClient talks to, conforming to the requirements of net/rpc.
type RPCServer struct {
	Impl Plugin
}

func (m *RPCServer) Exec(config PluginExecConfig, resp *PluginExecResult) error {
	ctx := context.Background()

	result, err := m.Impl.Exec(ctx, config)
	if err != nil {
		return err
	}

	*resp = PluginExecResult{
		Output:   result.Output,
		Error:    result.Error,
		ExitCode: result.ExitCode,
	}
	return nil
}

func (m *RPCServer) GetMetadata(_ any, resp *PluginMetadata) error {
	metadata, err := m.Impl.GetMetadata(context.Background())
	if err != nil {
		return err
	}
	*resp = metadata
	return nil
}
