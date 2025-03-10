//
// Copyright 2023-2025 The Chainloop Authors.
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

package action

import (
	"context"

	pb "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
)

type OrgUpdate struct {
	cfg *ActionsOpts
}

func NewOrgUpdate(cfg *ActionsOpts) *OrgUpdate {
	return &OrgUpdate{cfg}
}

type NewOrgUpdateOpts struct {
	BlockOnPolicyViolation *bool
}

func (action *OrgUpdate) Run(ctx context.Context, name string, opts *NewOrgUpdateOpts) (*OrgItem, error) {
	client := pb.NewOrganizationServiceClient(action.cfg.CPConnection)
	resp, err := client.Update(ctx, &pb.OrganizationServiceUpdateRequest{
		Name: name, BlockOnPolicyViolation: opts.BlockOnPolicyViolation,
	})
	if err != nil {
		return nil, err
	}

	return pbOrgItemToAction(resp.Result), nil
}
