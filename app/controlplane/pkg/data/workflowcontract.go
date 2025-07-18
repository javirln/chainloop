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

package data

import (
	"bytes"
	"context"
	"fmt"
	"time"

	schemav1 "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/organization"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/project"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/workflow"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/workflowcontract"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/workflowcontractversion"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/unmarshal"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type WorkflowContractRepo struct {
	data *Data
	log  *log.Helper
}

func NewWorkflowContractRepo(data *Data, logger log.Logger) biz.WorkflowContractRepo {
	return &WorkflowContractRepo{
		data: data,
		log:  log.NewHelper(logger),
	}
}

// List returns a list of workflow contracts for a given organization
// If no project filters are provided, we return all the contracts scoped to the organization
// otherwise we return the global contracts alongside the org scoped projects
func (r *WorkflowContractRepo) List(ctx context.Context, orgID uuid.UUID, filter *biz.WorkflowContractListFilters) ([]*biz.WorkflowContract, error) {
	wcontractQuery := orgScopedQuery(r.data.DB, orgID).
		QueryWorkflowContracts().
		Where(workflowcontract.DeletedAtIsNil())

	// If specific projects are provided
	// we return the global contracts alongside the org scoped projects
	if len(filter.FilterByProjects) > 0 {
		wcontractQuery = wcontractQuery.Where(
			workflowcontract.Or(
				workflowcontract.And(
					workflowcontract.ScopedResourceTypeIn(biz.ContractScopeProject),
					workflowcontract.ScopedResourceIDIn(filter.FilterByProjects...),
				),
				workflowcontract.ScopedResourceIDIsNil(),
			),
		)
	}

	contracts, err := wcontractQuery.
		WithWorkflows(func(q *ent.WorkflowQuery) {
			q.Where(workflow.DeletedAtIsNil())
		}).
		Order(ent.Desc(workflow.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*biz.WorkflowContract, 0, len(contracts))
	for _, s := range contracts {
		latestV, err := latestVersion(ctx, s)
		if err != nil {
			return nil, err
		}

		workflowReferences, err := getWorkflowReferences(ctx, s)
		if err != nil {
			return nil, err
		}
		res := r.entContractToBizContract(ctx, s, latestV, workflowReferences)
		result = append(result, res)
	}

	return result, nil
}

func (r *WorkflowContractRepo) Create(ctx context.Context, opts *biz.ContractCreateOpts) (*biz.WorkflowContract, error) {
	var (
		contract *ent.WorkflowContract
		version  *ent.WorkflowContractVersion
		err      error
	)

	if err = WithTx(ctx, r.data.DB, func(tx *ent.Tx) error {
		contract, version, err = r.addCreateToTx(ctx, tx, opts)
		if err != nil {
			return handleError(err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	res := r.entContractToBizContract(ctx, contract, version, nil)
	return res, nil
}

func (r *WorkflowContractRepo) addCreateToTx(ctx context.Context, tx *ent.Tx, opts *biz.ContractCreateOpts) (*ent.WorkflowContract, *ent.WorkflowContractVersion, error) {
	contractQuery := tx.WorkflowContract.Create().
		SetName(opts.Name).SetOrganizationID(opts.OrgID).
		SetNillableDescription(opts.Description)

	if opts.ProjectID != nil {
		contractQuery = contractQuery.SetScopedResourceID(*opts.ProjectID).SetScopedResourceType(biz.ContractScopeProject)
	}

	contract, err := contractQuery.Save(ctx)
	if err != nil {
		return nil, nil, handleError(err)
	}

	version, err := tx.WorkflowContractVersion.Create().
		SetRawBody(opts.Contract.Raw).
		SetRawBodyFormat(opts.Contract.Format).
		SetContract(contract).Save(ctx)
	if err != nil {
		return nil, nil, handleError(err)
	}

	return contract, version, nil
}

func (r *WorkflowContractRepo) FindVersionByID(ctx context.Context, versionID uuid.UUID) (*biz.WorkflowContractWithVersion, error) {
	// .Get(ctx, versionID) is an alias to .Query().Where(workflowcontractversion.ID(versionID)).Only(ctx)
	version, err := r.data.DB.WorkflowContractVersion.Query().Where(workflowcontractversion.ID(versionID)).WithContract().Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	} else if version == nil {
		return nil, nil
	}

	contractVersion, err := entContractVersionToBizContractVersion(version)
	if err != nil {
		return nil, err
	}

	return &biz.WorkflowContractWithVersion{
		Contract: r.entContractToBizContract(ctx, version.Edges.Contract, version, nil),
		Version:  contractVersion,
	}, nil
}

func (r *WorkflowContractRepo) Describe(ctx context.Context, orgID, contractID uuid.UUID, revision int, opts ...biz.ContractQueryOpt) (*biz.WorkflowContractWithVersion, error) {
	contract, err := contractInOrg(ctx, r.data.DB, orgID, &contractID, nil, opts...)
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	} else if contract == nil {
		return nil, biz.NewErrNotFound("contract")
	}

	latestV, err := latestVersion(ctx, contract)
	if err != nil {
		return nil, err
	}

	// revision 0 means latest
	version := latestV
	if revision != 0 {
		version, err = contract.QueryVersions().Where(workflowcontractversion.RevisionEQ(revision)).Only(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return nil, err
		} else if version == nil {
			return nil, biz.NewErrNotFound("contract")
		}
	}

	v, err := entContractVersionToBizContractVersion(version)
	if err != nil {
		return nil, err
	}

	c := &biz.ContractQueryOpts{}
	for _, opt := range opts {
		opt(c)
	}

	var workflowReferences []*biz.WorkflowRef
	if !c.SkipGetReferences {
		workflowReferences, err = getWorkflowReferences(ctx, contract)
		if err != nil {
			return nil, err
		}
	}

	s := r.entContractToBizContract(ctx, contract, latestV, workflowReferences)
	return &biz.WorkflowContractWithVersion{
		Contract: s,
		Version:  v,
	}, nil
}

// Update will add a new version of the contract.
// NOTE: ContractVersions are immutable
func (r *WorkflowContractRepo) Update(ctx context.Context, orgID uuid.UUID, name string, opts *biz.ContractUpdateOpts) (*biz.WorkflowContractWithVersion, error) {
	contract, err := contractInOrg(ctx, r.data.DB, orgID, nil, &name)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}

		return nil, handleError(err)
	}

	if contract == nil {
		return nil, nil
	}

	var (
		lv                 *ent.WorkflowContractVersion
		workflowReferences []*biz.WorkflowRef
	)

	if err = WithTx(ctx, r.data.DB, func(tx *ent.Tx) error {
		contract, err = contract.Update().SetNillableDescription(opts.Description).Save(ctx)
		if err != nil {
			return handleError(err)
		}

		lv, err = latestVersion(ctx, contract)
		if err != nil {
			return handleError(err)
		}

		// Create a revision only if we are providing a new contract and it has changed
		if opts.Contract != nil && !bytes.Equal(lv.RawBody, opts.Contract.Raw) {
			// TODO: Add pessimist locking to make sure we are incrementing the latest revision
			lv, err = tx.WorkflowContractVersion.Create().
				SetRawBody(opts.Contract.Raw).
				SetRawBodyFormat(opts.Contract.Format).
				SetContract(contract).
				SetRevision(lv.Revision + 1).
				Save(ctx)
			if err != nil {
				return handleError(err)
			}
		}

		workflowReferences, err = getWorkflowReferences(ctx, contract)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// The transaction is committed, we can now return the result
	contract, err = contractInOrg(ctx, r.data.DB, orgID, nil, &name)
	if err != nil {
		return nil, err
	}

	v, err := entContractVersionToBizContractVersion(lv)
	if err != nil {
		return nil, err
	}

	return &biz.WorkflowContractWithVersion{
		Contract: r.entContractToBizContract(ctx, contract, lv, workflowReferences),
		Version:  v,
	}, nil
}

func (r *WorkflowContractRepo) FindByIDInOrg(ctx context.Context, orgID, contractID uuid.UUID) (*biz.WorkflowContract, error) {
	contract, err := contractInOrg(ctx, r.data.DB, orgID, &contractID, nil)
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	} else if contract == nil {
		return nil, nil
	}

	workflowReferences, err := getWorkflowReferences(ctx, contract)
	if err != nil {
		return nil, err
	}

	latestV, err := latestVersion(ctx, contract)
	if err != nil {
		return nil, err
	}

	return r.entContractToBizContract(ctx, contract, latestV, workflowReferences), nil
}

func (r *WorkflowContractRepo) FindByNameInOrg(ctx context.Context, orgID uuid.UUID, name string) (*biz.WorkflowContract, error) {
	contract, err := contractInOrg(ctx, r.data.DB, orgID, nil, &name)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("failed to find contract: %w", err)
	} else if contract == nil {
		return nil, biz.NewErrNotFound("contract")
	}

	workflowReferences, err := getWorkflowReferences(ctx, contract)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflows: %w", err)
	}

	latestV, err := latestVersion(ctx, contract)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest version: %w", err)
	}

	return r.entContractToBizContract(ctx, contract, latestV, workflowReferences), nil
}

func (r *WorkflowContractRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return r.data.DB.WorkflowContract.UpdateOneID(id).SetDeletedAt(time.Now()).Exec(ctx)
}

func entContractVersionToBizContractVersion(w *ent.WorkflowContractVersion) (*biz.WorkflowContractVersion, error) {
	contract := &biz.Contract{
		Raw:    w.RawBody,
		Format: w.RawBodyFormat,
	}

	// We have two ways of storing the contract body, the old way is the body column which contains the binary representation of the proto message
	// and the new way which is the raw_body and raw_body_format pairs
	// Regardless of what's stored, we want to make sure we always return the contract object that contains the raw and binary representation
	var err error
	// Scenario 1: contracts that have been stored (and not updated) before the introduction of the raw_body field will have an empty raw_body
	// so we will generate a json representation of the contract to populate the raw_body field in that case
	// that way clients can always expect a raw_body field to be present
	if len(contract.Raw) == 0 {
		schema := &schemav1.CraftingSchema{}
		if err := proto.Unmarshal(w.Body, schema); err != nil {
			return nil, err
		}

		contract, err = biz.SchemaToRawContract(schema)
		if err != nil {
			return nil, fmt.Errorf("failed to generate fallback raw body: %w", err)
		}
		// Scenario 2: contracts that have been updated after the introduction of the raw_body field will have the raw_body field populated
		// but we also want to keep the Body field populated for backward compatibility
	} else if len(w.Body) == 0 {
		schema := &schemav1.CraftingSchema{}
		err := unmarshal.FromRaw(w.RawBody, w.RawBodyFormat, schema, false)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal raw body: %w", err)
		}
		contract.Schema = schema
	}

	return &biz.WorkflowContractVersion{
		ID: w.ID, CreatedAt: toTimePtr(w.CreatedAt), Revision: w.Revision, Schema: contract,
	}, nil
}

// wraps the given error
func handleError(err error) error {
	// If the error is a constraint error, we return a more specific error to indicate the client that's a duplicate
	if ent.IsConstraintError(err) {
		return biz.NewErrAlreadyExists(err)
	}

	return err
}

func latestVersion(ctx context.Context, contract *ent.WorkflowContract) (*ent.WorkflowContractVersion, error) {
	return contract.QueryVersions().Order(ent.Desc(workflowcontractversion.FieldRevision)).First(ctx)
}

func contractInOrg(ctx context.Context, client *ent.Client, orgID uuid.UUID, contractID *uuid.UUID, name *string, opts ...biz.ContractQueryOpt) (*ent.WorkflowContract, error) {
	return contractInOrgQuery(ctx, client.Organization.Query(), orgID, contractID, name, opts...)
}

// It can be loaded via by ID or name
func contractInOrgQuery(ctx context.Context, q *ent.OrganizationQuery, orgID uuid.UUID, contractID *uuid.UUID, name *string, opts ...biz.ContractQueryOpt) (*ent.WorkflowContract, error) {
	c := &biz.ContractQueryOpts{}
	for _, opt := range opts {
		opt(c)
	}

	if contractID == nil && name == nil {
		return nil, fmt.Errorf("either contractID or name must be provided")
	}

	query := q.
		Where(organization.ID(orgID)).
		QueryWorkflowContracts().
		Where(workflowcontract.DeletedAtIsNil())

	if !c.SkipGetReferences {
		query = query.WithWorkflows(func(q *ent.WorkflowQuery) {
			q.Where(workflow.DeletedAtIsNil()).WithProject().Select(project.FieldID, project.FieldName)
		})
	}

	if contractID != nil {
		query = query.Where(workflowcontract.ID(*contractID))
	}

	if name != nil {
		query = query.Where(workflowcontract.NameEQ(*name))
	}

	return query.Only(ctx)
}

func (r *WorkflowContractRepo) entContractToBizContract(ctx context.Context, w *ent.WorkflowContract, version *ent.WorkflowContractVersion, workflowReferences []*biz.WorkflowRef) *biz.WorkflowContract {
	c := &biz.WorkflowContract{
		Name:                    w.Name,
		ID:                      w.ID,
		CreatedAt:               toTimePtr(w.CreatedAt),
		LatestRevisionCreatedAt: toTimePtr(version.CreatedAt),
		WorkflowRefs:            workflowReferences,
		Description:             w.Description,
	}

	if w.ScopedResourceID != uuid.Nil {
		c.ScopedEntity = &biz.ScopedEntity{
			Type: string(w.ScopedResourceType),
			ID:   w.ScopedResourceID,
		}
	}

	// preload the project name if the contract is scoped to a project
	if w.ScopedResourceType == biz.ContractScopeProject {
		project, err := r.data.DB.Project.Get(ctx, w.ScopedResourceID)
		if err != nil {
			r.log.Errorf("failed to get project: %w", err)
			return c
		}
		c.ScopedEntity.Name = project.Name
	}

	c.LatestRevision = version.Revision
	return c
}

// getWorkflowReferences get the list of workflows associated with a given contract
func getWorkflowReferences(ctx context.Context, schema *ent.WorkflowContract) ([]*biz.WorkflowRef, error) {
	// Either get it from preloaded entity or query it
	workflows := schema.Edges.Workflows
	if workflows == nil {
		var err error
		workflows, err = schema.QueryWorkflows().
			Where(workflow.DeletedAtIsNil()).
			WithProject().
			Select(workflow.FieldID, workflow.FieldName).
			All(ctx)
		if err != nil {
			return nil, err
		}
	}

	references := make([]*biz.WorkflowRef, 0, len(workflows))
	for _, wf := range workflows {
		wfBiz, err := entWFToBizWF(ctx, wf)
		if err != nil {
			return nil, err
		}

		references = append(references, &biz.WorkflowRef{
			ID:          wfBiz.ID,
			Name:        wfBiz.Name,
			ProjectName: wfBiz.Project,
		})
	}

	return references, nil
}
