//
// Copyright 2023 The Chainloop Authors.
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

package service

import (
	"context"
	"io"

	"github.com/chainloop-dev/chainloop/app/controlplane/internal/usercontext"
	"github.com/chainloop-dev/chainloop/app/controlplane/internal/usercontext/entities"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/pagination"
	"github.com/chainloop-dev/chainloop/pkg/servicelogger"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ProviderSet is service providers.
var ProviderSet = wire.NewSet(
	NewWorkflowService,
	NewAuthService,
	NewRobotAccountService,
	NewWorkflowRunService,
	NewAttestationService,
	NewWorkflowSchemaService,
	NewCASCredentialsService,
	NewContextService,
	NewOrgMetricsService,
	NewIntegrationsService,
	NewCASBackendService,
	NewCASRedirectService,
	NewOrganizationService,
	NewOrgInvitationService,
	NewReferrerService,
	NewAPITokenService,
	NewAttestationStateService,
	NewUserService,
	NewSigningService,
	NewPrometheusService,
	wire.Struct(new(NewWorkflowRunServiceOpts), "*"),
	wire.Struct(new(NewAttestationServiceOpts), "*"),
	wire.Struct(new(NewAttestationStateServiceOpt), "*"),
)

func requireCurrentUser(ctx context.Context) (*entities.User, error) {
	currentUser := entities.CurrentUser(ctx)
	if currentUser == nil {
		return nil, errors.NotFound("not found", "logged in user")
	}

	return currentUser, nil
}

func requireAPIToken(ctx context.Context) (*entities.APIToken, error) {
	token := entities.CurrentAPIToken(ctx)
	if token == nil {
		return nil, errors.NotFound("not found", "API token")
	}

	return token, nil
}

func requireCurrentUserOrAPIToken(ctx context.Context) (*entities.User, *entities.APIToken, error) {
	user, err := requireCurrentUser(ctx)
	if err != nil && !errors.IsNotFound(err) {
		return nil, nil, err
	}

	apiToken, err := requireAPIToken(ctx)
	if err != nil && !errors.IsNotFound(err) {
		return nil, nil, err
	}

	if user == nil && apiToken == nil {
		return nil, nil, errors.Forbidden("authN required", "logged in user nor API token found")
	}

	return user, apiToken, nil
}

func requireCurrentOrg(ctx context.Context) (*entities.Org, error) {
	currentOrg := entities.CurrentOrg(ctx)
	if currentOrg == nil {
		return nil, errors.NotFound("not found", "current organization not set")
	}

	return currentOrg, nil
}

func requireCurrentAuthzSubject(ctx context.Context) (string, error) {
	sub := usercontext.CurrentAuthzSubject(ctx)
	if sub == "" {
		return "", errors.NotFound("not found", "authorization subject not set")
	}

	return sub, nil
}

func newService(opts ...NewOpt) *service {
	s := &service{
		log: log.NewHelper(log.NewStdLogger(io.Discard)),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

type service struct {
	log *log.Helper
}

type NewOpt func(s *service)

func WithLogger(logger log.Logger) NewOpt {
	return func(s *service) {
		s.log = servicelogger.ScopedHelper(logger, "service")
	}
}

// NOTE: some of these http errors get automatically translated to gRPC status codes
// because they implement the gRPC status error interface
// so it is safe to return either a gRPC status error or a kratos error
func handleUseCaseErr(err error, l *log.Helper) error {
	switch {
	case errors.Is(err, context.Canceled):
		return errors.ClientClosed("client closed", err.Error())
	case biz.IsErrValidation(err) || biz.IsErrInvalidUUID(err) || biz.IsErrInvalidTimeWindow(err) ||
		pagination.IsOffsetPaginationError(err) || pagination.IsCursorPaginationError(err):
		return errors.BadRequest("invalid", err.Error())
	case biz.IsNotFound(err):
		return errors.NotFound("not found", err.Error())
	case biz.IsErrUnauthorized(err):
		return errors.Forbidden("unauthorized", err.Error())
	case biz.IsErrNotImplemented(err):
		return status.Error(codes.Unimplemented, err.Error())
	case biz.IsErrAlreadyExists(err):
		return status.Error(codes.AlreadyExists, err.Error())
	default:
		return servicelogger.LogAndMaskErr(err, l)
	}
}
