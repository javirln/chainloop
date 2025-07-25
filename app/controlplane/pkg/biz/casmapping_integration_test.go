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

package biz_test

import (
	"context"
	"testing"

	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz/testhelpers"
	creds "github.com/chainloop-dev/chainloop/pkg/credentials/mocks"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	// This is the digest of the empty envelope
	validDigest           = "sha256:f845058d865c3d4d491c9019f6afe9c543ad2cd11b31620cc512e341fb03d3d8"
	validDigest2          = "sha256:2b0f04c276be095e62f3ac03b9991913c37df1fcd44548e75069adce313aba4d"
	validDigest3          = "sha256:1b0f04c276be095e62f3ac03b9991913c37df1fcd44548e75069adce313aba4d"
	validDigestPublic     = "sha256:8b0f04c276be095e62f3ac03b9991913c37df1fcd44548e75069adce313aba4d"
	validDigestWithoutRun = "sha256:63e8ec8e489d31265fb920241da3300ec36c10865d2e287e055d4e1287ce25e6"
	invalidDigest         = "sha256:deadbeef"
)

func (s *casMappingIntegrationSuite) TestCASMappingForDownloadUser() {
	// Let's create 3 CASMappings:
	// 1. Digest: validDigest, CASBackend: casBackend1, WorkflowRunID: workflowRun
	// 2. Digest: validDigest, CASBackend: casBackend2, WorkflowRunID: workflowRun
	// 3. Digest: validDigest2, CASBackend: casBackend2, WorkflowRunID: workflowRun
	// 4. Digest: validDigest3, CASBackend: casBackend3, WorkflowRunID: workflowRun
	// 4. Digest: validDigestPublic, CASBackend: casBackend3, WorkflowRunID: workflowRunPublic
	_, err := s.CASMapping.Create(context.TODO(), validDigest, s.casBackend1.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(context.TODO(), validDigest, s.casBackend2.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(context.TODO(), validDigest2, s.casBackend2.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(context.TODO(), validDigest3, s.casBackend3.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(context.TODO(), validDigestPublic, s.casBackend3.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.publicWorkflowRun.ID})
	require.NoError(s.T(), err)

	// Since the userOrg1And2 is member of org1 and org2, she should be able to download
	// both validDigest and validDigest2 from two different orgs
	s.Run("userOrg1And2 can download validDigest from org1", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), validDigest, s.userOrg1And2.ID)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend1.ID, mapping.CASBackend.ID)
	})

	s.Run("userOrg1And2 can download validDigest2 from org2", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), validDigest2, s.userOrg1And2.ID)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend2.ID, mapping.CASBackend.ID)
	})

	s.Run("userOrg1And2 can not download validDigest3 from org3", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), validDigest3, s.userOrg1And2.ID)
		s.Error(err)
		s.Nil(mapping)
	})

	s.Run("userOrg1And2 can download validDigestPublic from org3", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), validDigestPublic, s.userOrg1And2.ID)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend3.ID, mapping.CASBackend.ID)
	})

	s.Run("userOrg2 can download validDigest2 from org2", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), validDigest2, s.userOrg2.ID)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend2.ID, mapping.CASBackend.ID)
	})

	s.Run("userOrg2 can download validDigestPublic from org3", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), validDigestPublic, s.userOrg2.ID)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend3.ID, mapping.CASBackend.ID)
	})

	s.Run("userOrg2 can download validDigest from org2", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), validDigest, s.userOrg2.ID)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend2.ID, mapping.CASBackend.ID)
	})

	s.Run("userOrg2 can not download invalidDigest", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByUser(context.TODO(), invalidDigest, s.userOrg2.ID)
		s.Error(err)
		s.Nil(mapping)
	})
}

func (s *casMappingIntegrationSuite) TestCASMappingForDownloadByOrg() {
	ctx := context.Background()
	_, err := s.CASMapping.Create(ctx, validDigest, s.casBackend1.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(ctx, validDigestPublic, s.casBackend3.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.publicWorkflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(ctx, validDigestWithoutRun, s.casBackend3.ID.String(), nil)
	require.NoError(s.T(), err)

	// both validDigest and validDigest2 from two different orgs
	s.Run("validDigest is in org1", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByOrg(ctx, validDigest, []uuid.UUID{uuid.MustParse(s.org1.ID)}, nil)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend1.ID, mapping.CASBackend.ID)
	})

	s.Run("validDigestPublic is available from any org", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByOrg(ctx, validDigestPublic, []uuid.UUID{uuid.New()}, nil)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend3.ID, mapping.CASBackend.ID)
	})

	s.Run("validDigestWithoutRun is available only to org 3", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByOrg(ctx, validDigestWithoutRun, []uuid.UUID{s.casBackend3.OrganizationID}, nil)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(s.casBackend3.ID, mapping.CASBackend.ID)

		mapping, err = s.CASMapping.FindCASMappingForDownloadByOrg(ctx, validDigestWithoutRun, []uuid.UUID{uuid.MustParse(s.org1.ID)}, nil)
		s.Error(err)
		s.Nil(mapping)
	})

	s.Run("can't find an invalid digest", func() {
		mapping, err := s.CASMapping.FindCASMappingForDownloadByOrg(ctx, invalidDigest, []uuid.UUID{uuid.MustParse(s.org1.ID)}, nil)
		s.Error(err)
		s.Nil(mapping)
	})
}

func (s *casMappingIntegrationSuite) TestFindByDigest() {
	// 1. Digest: validDigest, CASBackend: casBackend1, WorkflowRunID: workflowRun
	// 2. Digest: validDigest2, CASBackend: casBackend1, WorkflowRunID: workflowRun
	// 3. Digest: validDigest, CASBackend: casBackend2, WorkflowRunID: workflowRun
	// 4. Digest: validDigest, CASBackend: casBackend3, WorkflowRunID: publicWorkflowRun
	_, err := s.CASMapping.Create(context.TODO(), validDigest, s.casBackend1.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(context.TODO(), validDigest2, s.casBackend1.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(context.TODO(), validDigest, s.casBackend2.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.workflowRun.ID})
	require.NoError(s.T(), err)
	_, err = s.CASMapping.Create(context.TODO(), validDigest, s.casBackend3.ID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: &s.publicWorkflowRun.ID})
	require.NoError(s.T(), err)

	testcases := []struct {
		name    string
		digest  string
		want    []*biz.CASMapping
		wantErr bool
	}{
		{
			name:   "validDigest",
			digest: validDigest,
			want: []*biz.CASMapping{
				{
					Digest:        validDigest,
					CASBackend:    &biz.CASBackend{ID: s.casBackend1.ID},
					WorkflowRunID: s.workflowRun.ID,
					OrgID:         s.casBackend1.OrganizationID,
					Public:        false,
				},
				{
					Digest:        validDigest,
					CASBackend:    &biz.CASBackend{ID: s.casBackend2.ID},
					WorkflowRunID: s.workflowRun.ID,
					OrgID:         s.casBackend2.OrganizationID,
					Public:        false,
				},
				{
					Digest:        validDigest,
					CASBackend:    &biz.CASBackend{ID: s.casBackend3.ID},
					WorkflowRunID: s.publicWorkflowRun.ID,
					OrgID:         s.casBackend3.OrganizationID,
					Public:        true,
				},
			},
		},
		{
			name:   "validDigest2",
			digest: validDigest2,
			want: []*biz.CASMapping{
				{
					Digest:        validDigest2,
					CASBackend:    &biz.CASBackend{ID: s.casBackend1.ID},
					WorkflowRunID: s.workflowRun.ID,
					OrgID:         s.casBackend1.OrganizationID,
					Public:        false,
				},
			},
		},
		{
			name:   "invalidDigest",
			digest: invalidDigest,
			want:   []*biz.CASMapping{},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			got, err := s.CASMapping.FindByDigest(context.Background(), tc.digest)
			if tc.wantErr {
				s.Error(err)
			} else {
				s.NoError(err)
				if diff := cmp.Diff(tc.want, got,
					cmpopts.IgnoreFields(biz.CASMapping{}, "CreatedAt", "ID"),
					cmpopts.IgnoreTypes(biz.CASBackend{}),
				); diff != "" {
					assert.Failf(s.T(), "mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func (s *casMappingIntegrationSuite) TestCreate() {
	testCases := []struct {
		name          string
		digest        string
		casBackendID  uuid.UUID
		workflowRunID *uuid.UUID
		wantErr       bool
		wantPublic    bool
	}{
		{
			name:          "valid",
			digest:        validDigest,
			casBackendID:  s.casBackend1.ID,
			workflowRunID: biz.ToPtr(s.workflowRun.ID),
		},
		{
			name:          "created again with same digest",
			digest:        validDigest,
			casBackendID:  s.casBackend1.ID,
			workflowRunID: biz.ToPtr(s.workflowRun.ID),
		},
		{
			name:          "invalid digest format",
			digest:        invalidDigest,
			casBackendID:  s.casBackend1.ID,
			workflowRunID: biz.ToPtr(s.workflowRun.ID),
			wantErr:       true,
		},
		{
			name:          "invalid digest missing prefix",
			digest:        "3b0f04c276be095e62f3ac03b9991913c37df1fcd44548e75069adce313aba4d",
			casBackendID:  s.casBackend1.ID,
			workflowRunID: biz.ToPtr(s.workflowRun.ID),
			wantErr:       true,
		},
		{
			name:          "non-existing CASBackend",
			digest:        validDigest,
			casBackendID:  uuid.New(),
			workflowRunID: biz.ToPtr(s.workflowRun.ID),
			wantErr:       true,
		},
		{
			name:          "non-existing WorkflowRunID",
			digest:        validDigest,
			casBackendID:  s.casBackend1.ID,
			workflowRunID: biz.ToPtr(uuid.New()),
			wantErr:       true,
		},
		{
			name:          "public workflowrun",
			digest:        validDigest,
			casBackendID:  s.casBackend1.ID,
			workflowRunID: biz.ToPtr(s.publicWorkflowRun.ID),
			wantPublic:    true,
		},
		{
			name:         "not associated to any workflowrun",
			digest:       validDigest,
			casBackendID: s.casBackend1.ID,
			wantPublic:   false,
		},
	}

	for _, tc := range testCases {
		want := &biz.CASMapping{
			Digest:     validDigest,
			CASBackend: &biz.CASBackend{ID: s.casBackend1.ID},
			OrgID:      s.casBackend1.OrganizationID,
			Public:     tc.wantPublic,
		}

		if tc.workflowRunID != nil {
			want.WorkflowRunID = *tc.workflowRunID
		}

		s.Run(tc.name, func() {
			got, err := s.CASMapping.Create(context.TODO(), tc.digest, tc.casBackendID.String(), &biz.CASMappingCreateOpts{WorkflowRunID: tc.workflowRunID})
			if tc.wantErr {
				s.Error(err)
			} else {
				s.NoError(err)
				if diff := cmp.Diff(want, got,
					cmpopts.IgnoreFields(biz.CASMapping{}, "CreatedAt", "ID"),
					cmpopts.IgnoreTypes(biz.CASBackend{}),
				); diff != "" {
					assert.Failf(s.T(), "mismatch (-want +got):\n%s", diff)
				}

				assert.Equal(s.T(), want.CASBackend.ID, got.CASBackend.ID)
			}
		})
	}
}

type casMappingIntegrationSuite struct {
	testhelpers.UseCasesEachTestSuite
	casBackend1, casBackend2, casBackend3 *biz.CASBackend
	workflowRun, publicWorkflowRun        *biz.WorkflowRun
	userOrg1And2, userOrg2                *biz.User
	org1, org2, orgNoUsers                *biz.Organization
}

func (s *casMappingIntegrationSuite) SetupTest() {
	var err error
	assert := assert.New(s.T())
	ctx := context.Background()

	// RunDB
	credsWriter := creds.NewReaderWriter(s.T())
	credsWriter.On(
		"SaveCredentials", ctx, mock.Anything, mock.Anything,
	).Return("stored-OCI-secret", nil)

	s.TestingUseCases = testhelpers.NewTestingUseCases(s.T(), testhelpers.WithCredsReaderWriter(credsWriter))

	// Create casBackend in the database
	s.org1, err = s.Organization.Create(ctx, "testing-org-1-with-one0backend")
	assert.NoError(err)
	s.casBackend1, err = s.CASBackend.Create(ctx, s.org1.ID, randomName(), "my-location", "backend 1 description", backendType, nil, true)
	assert.NoError(err)
	s.org2, err = s.Organization.Create(ctx, "testing-org-2")
	assert.NoError(err)
	s.casBackend2, err = s.CASBackend.Create(ctx, s.org2.ID, randomName(), "my-location", "backend 1 description", backendType, nil, true)
	assert.NoError(err)
	// Create casBackend associated with an org which users are not member of
	s.orgNoUsers, err = s.Organization.Create(ctx, "org-without-users")
	assert.NoError(err)
	s.casBackend3, err = s.CASBackend.Create(ctx, s.orgNoUsers.ID, randomName(), "my-location", "backend 1 description", backendType, nil, true)
	assert.NoError(err)

	// Create workflowRun in the database
	// Workflow
	workflow, err := s.Workflow.Create(ctx, &biz.WorkflowCreateOpts{Name: "test-workflow", OrgID: s.org1.ID, Project: "test-project"})
	assert.NoError(err)

	publicWorkflow, err := s.Workflow.Create(ctx, &biz.WorkflowCreateOpts{Name: "test-workflow-public", OrgID: s.org1.ID, Public: true, Project: "test-project"})
	assert.NoError(err)

	// Find contract revision
	contractVersion, err := s.WorkflowContract.Describe(ctx, s.org1.ID, workflow.ContractID.String(), 0)
	assert.NoError(err)

	s.workflowRun, err = s.WorkflowRun.Create(ctx, &biz.WorkflowRunCreateOpts{
		WorkflowID: workflow.ID.String(), ContractRevision: contractVersion, CASBackendID: s.casBackend1.ID,
		RunnerType: "runnerType", RunnerRunURL: "runURL",
	})
	assert.NoError(err)

	s.publicWorkflowRun, err = s.WorkflowRun.Create(ctx, &biz.WorkflowRunCreateOpts{
		WorkflowID: publicWorkflow.ID.String(), ContractRevision: contractVersion, CASBackendID: s.casBackend1.ID,
		RunnerType: "runnerType", RunnerRunURL: "runURL",
	})
	assert.NoError(err)

	// Create User
	s.userOrg1And2, err = s.User.UpsertByEmail(ctx, "foo@test.com", nil)
	assert.NoError(err)

	s.userOrg2, err = s.User.UpsertByEmail(ctx, "foo-org2@test.com", nil)
	assert.NoError(err)

	_, err = s.Membership.Create(ctx, s.org1.ID, s.userOrg1And2.ID)
	assert.NoError(err)
	_, err = s.Membership.Create(ctx, s.org2.ID, s.userOrg1And2.ID, biz.WithCurrentMembership())
	assert.NoError(err)
	_, err = s.Membership.Create(ctx, s.org2.ID, s.userOrg2.ID, biz.WithCurrentMembership())
	assert.NoError(err)
}

func TestCASMappingIntegration(t *testing.T) {
	suite.Run(t, new(casMappingIntegrationSuite))
}
