//
// Copyright 2024-2025 The Chainloop Authors.
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

package policies

import (
	"context"
	"testing"

	v1 "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	api "github.com/chainloop-dev/chainloop/pkg/attestation/crafter/api/attestation/v1"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type groupsTestSuite struct {
	suite.Suite

	logger zerolog.Logger
}

func (s *groupsTestSuite) SetupTest() {
	s.logger = zerolog.Nop()
}

func TestPolicyGroups(t *testing.T) {
	suite.Run(t, new(groupsTestSuite))
}

func (s *groupsTestSuite) TestLoadGroupSpec() {
	var cases = []struct {
		name             string
		attachment       *v1.PolicyGroupAttachment
		wantErr          bool
		expectedName     string
		expectedDesc     string
		expectedCategory string
	}{
		{
			name:       "missing ref",
			attachment: &v1.PolicyGroupAttachment{},
			wantErr:    true,
		},
		{
			name: "by file ref",
			attachment: &v1.PolicyGroupAttachment{
				Ref: "file://testdata/policy_group.yaml",
			},
			expectedName: "sbom-quality",
		},
		{
			name: "with wrong digest",
			attachment: &v1.PolicyGroupAttachment{
				Ref: "file://testdata/policy_group.yaml@sha256:24c4bd4f56b470d7436ed0c5a340483fff9ad058033f94b164f5efc59aba5136",
			},
			expectedName: "sbom-quality",
			wantErr:      true,
		},
		{
			name: "with correct digest",
			attachment: &v1.PolicyGroupAttachment{
				Ref: "file://testdata/policy_group.yaml@sha256:e35d8effedf522b33a080168a69b0d56ca7d7e2779e2fe6e7d8c460509771f88",
			},
			expectedName: "sbom-quality",
		},
		{
			name: "materials in policy groups must have a type",
			attachment: &v1.PolicyGroupAttachment{
				Ref: "file://testdata/policy_group_wrong.yaml",
			},
			wantErr: true,
		},
		{
			name: "named materials in policy groups must have a type",
			attachment: &v1.PolicyGroupAttachment{
				Ref: "file://testdata/policy_group_wrong.yaml",
			},
			wantErr: true,
		},
		{
			name: "policy group without name-less materials are supported",
			attachment: &v1.PolicyGroupAttachment{
				Ref: "file://testdata/policy_group_no_name.yaml",
			},
			expectedName: "sbom-quality",
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			group, _, err := LoadPolicyGroup(context.TODO(), tc.attachment, &LoadPolicyGroupOptions{
				Client: nil,
				Logger: &s.logger,
			})
			if tc.wantErr {
				s.Error(err)
				return
			}
			s.Require().NoError(err)
			s.Equal(tc.expectedName, group.GetMetadata().GetName())
			if tc.expectedDesc != "" {
				s.Equal(tc.expectedDesc, group.Metadata.Description)
			}

			if tc.expectedCategory != "" {
				s.Equal(tc.expectedCategory, group.Metadata.Annotations["category"])
			}
		})
	}
}

func (s *groupsTestSuite) TestRequiredPoliciesForMaterial() {
	cases := []struct {
		name         string
		materialName string
		schemaRef    string
		materialType v1.CraftingSchema_Material_MaterialType
		expected     int
	}{
		{
			name:         "no match",
			materialName: "gitlab-report",
			schemaRef:    "file://testdata/policy_group.yaml",
			materialType: v1.CraftingSchema_Material_GITLAB_SECURITY_REPORT,
			expected:     0,
		},
		{
			name:         "match by name",
			materialName: "sbom",
			schemaRef:    "file://testdata/policy_group.yaml",
			materialType: v1.CraftingSchema_Material_SBOM_SPDX_JSON,
			expected:     1,
		},
		{
			name:         "name-less group",
			materialName: "sbom",
			schemaRef:    "file://testdata/policy_group_no_name.yaml",
			materialType: v1.CraftingSchema_Material_SBOM_SPDX_JSON,
			expected:     1,
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			schema := &v1.CraftingSchema{PolicyGroups: []*v1.PolicyGroupAttachment{{Ref: tc.schemaRef}}}

			material := &api.Attestation_Material{
				MaterialType: tc.materialType,
				Id:           tc.materialName,
				M: &api.Attestation_Material_Artifact_{
					Artifact: &api.Attestation_Material_Artifact{},
				},
			}

			v := NewPolicyGroupVerifier(schema, nil, &s.logger)
			group, _, err := new(FileGroupLoader).Load(context.TODO(), &v1.PolicyGroupAttachment{
				Ref: tc.schemaRef,
			})
			s.Require().NoError(err)
			atts, err := v.requiredPoliciesForMaterial(context.TODO(), material, group, nil)
			s.Require().NoError(err)
			s.Len(atts, tc.expected)
		})
	}
}

func (s *groupsTestSuite) TestGroupLoader() {
	cases := []struct {
		name     string
		ref      string
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "file ref",
			ref:      "file://local-policy.yaml",
			expected: &FileGroupLoader{},
		},
		{
			name:     "http ref",
			ref:      "https://myhost/policy.yaml",
			expected: &HTTPSGroupLoader{},
		},
		{
			name:    "invalid ref",
			ref:     "env://environmentvar",
			wantErr: true,
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			att := &v1.PolicyGroupAttachment{Ref: tc.ref}
			loader, err := getGroupLoader(att, &LoadPolicyGroupOptions{
				Client: nil,
				Logger: &s.logger,
			})
			if tc.wantErr {
				s.Error(err)
				return
			}
			s.NoError(err)
			s.IsType(tc.expected, loader)
		})
	}
}

func (s *groupsTestSuite) TestVerifyStatement() {
	cases := []struct {
		name       string
		schema     *v1.CraftingSchema
		statement  string
		npolicies  int
		violations int
		groupName  string
		wantErr    error
	}{
		{
			name: "test attestation with violations",
			schema: &v1.CraftingSchema{
				PolicyGroups: []*v1.PolicyGroupAttachment{
					{
						Ref: "file://testdata/policy_group.yaml",
					},
				},
			},
			statement:  "testdata/statement.json",
			npolicies:  1,
			violations: 1,
			groupName:  "sbom-quality",
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			v := NewPolicyGroupVerifier(tc.schema, nil, &s.logger)
			statement := loadStatement(tc.statement, &s.Suite)
			res, err := v.VerifyStatement(context.TODO(), statement)
			if tc.wantErr != nil {
				// #nosec G601
				s.ErrorAs(err, &tc.wantErr)
				return
			}
			s.Require().NoError(err)
			s.Len(res, tc.npolicies)
			if tc.npolicies > 0 {
				violations := 0
				for _, pol := range res {
					violations += len(pol.Violations)
					s.Equal(tc.groupName, pol.GroupReference.GetName())
				}
				s.Equal(tc.violations, violations)
			}
		})
	}
}

func (s *groupsTestSuite) TestVerifyMaterialMultiKind() {
	cases := []struct {
		name                string
		policyGroup         string
		material            string
		expectErr           bool
		expectedEvaluations int
		expectSkipped       bool
		expectReasons       []string
		expectIgnore        bool
	}{
		{
			name:                "not evaluation results, ignore",
			policyGroup:         "file://testdata/policy_group_multikind.yaml",
			material:            "{\"specVersion\": \"1.0\"}",
			expectedEvaluations: 0,
			expectIgnore:        true,
		},
		{
			name:                "evaluation results, no ignore",
			policyGroup:         "file://testdata/policy_group_multikind.yaml",
			material:            "{\"specVersion\": \"1.4\"}",
			expectedEvaluations: 1,
			expectIgnore:        false,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			schema := &v1.CraftingSchema{
				Materials: []*v1.CraftingSchema_Material{
					{
						Name: "sbom",
						Type: v1.CraftingSchema_Material_SBOM_CYCLONEDX_JSON,
					},
				},
				PolicyGroups: []*v1.PolicyGroupAttachment{
					{
						Ref: tc.policyGroup,
					},
				},
			}

			material := &api.Attestation_Material{
				M: &api.Attestation_Material_Artifact_{Artifact: &api.Attestation_Material_Artifact{
					Content: []byte(tc.material),
				}},
				MaterialType: v1.CraftingSchema_Material_SBOM_CYCLONEDX_JSON,
				InlineCas:    true,
			}

			if !tc.expectIgnore {
				material.MaterialType = v1.CraftingSchema_Material_OPENVEX
			}

			verifier := NewPolicyGroupVerifier(schema, nil, &s.logger)
			res, err := verifier.VerifyMaterial(context.TODO(), material, "")

			if tc.expectErr {
				s.Error(err)
				return
			}

			if tc.expectIgnore {
				s.Nil(err)
				s.Len(res, tc.expectedEvaluations)
				return
			}

			s.Require().NoError(err)
			s.Len(res, tc.expectedEvaluations)
			s.Equal(tc.expectSkipped, res[0].Skipped)
			if len(res[0].SkipReasons) > 0 {
				s.Equal(tc.expectReasons, res[0].SkipReasons)
			}
		})
	}
}

func (s *groupsTestSuite) TestGroupInputs() {
	cases := []struct {
		name         string
		args         map[string]string
		group        string
		materialName string // the material name in the crafting state
		nEvals       int
		skipReason   string
		wantErr      bool
		errMsg       string
	}{
		{
			name:       "group inputs with interpolation, default values",
			args:       map[string]string{"user_name": "devel"},
			group:      "file://testdata/group_with_inputs.yaml",
			nEvals:     1,
			skipReason: "the email is: devel@chainloop.dev",
		},
		{
			name:    "missing username input",
			group:   "file://testdata/group_with_inputs.yaml",
			wantErr: true,
			errMsg:  "missing required input \"user_name\"",
		},
		{
			name:       "group inputs with interpolation, all values",
			group:      "file://testdata/group_with_inputs.yaml",
			args:       map[string]string{"user_name": "foo", "domainName": "bar.com"},
			nEvals:     1,
			skipReason: "the email is: foo@bar.com",
		},
		{
			name:         "group with interpolated material name, no matched material",
			group:        "file://testdata/group_with_interpolated_material.yaml",
			args:         map[string]string{"user_name": "foo", "domainName": "bar.com", "sbom_name": "foo"},
			materialName: "foo",
			nEvals:       1,
			skipReason:   "the email is: foo@bar.com",
		},
	}

	for _, tc := range cases {
		schema := &v1.CraftingSchema{
			PolicyGroups: []*v1.PolicyGroupAttachment{
				{
					Ref:  tc.group,
					With: tc.args,
				},
			},
		}
		mName := "sbom"
		if tc.materialName != "" {
			mName = tc.materialName
		}
		material := &api.Attestation_Material{
			Id: mName,
			M: &api.Attestation_Material_Artifact_{Artifact: &api.Attestation_Material_Artifact{
				Content: []byte(`{}`), // content not validated in this context
			}},
			MaterialType: v1.CraftingSchema_Material_SBOM_CYCLONEDX_JSON,
			InlineCas:    true,
		}
		s.Run(tc.name, func() {
			v := NewPolicyGroupVerifier(schema, nil, &s.logger)
			evs, err := v.VerifyMaterial(context.TODO(), material, "")
			if tc.wantErr {
				s.Error(err)
				s.Contains(err.Error(), tc.errMsg)
				return
			}
			s.Require().NoError(err)
			s.Len(evs, tc.nEvals)
			if tc.nEvals > 0 {
				s.Equal(tc.skipReason, evs[0].SkipReasons[0])
			}
		})
	}
}
