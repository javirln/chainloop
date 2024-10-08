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

package policies

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	pb "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	v1 "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	v12 "github.com/chainloop-dev/chainloop/pkg/attestation/crafter/api/attestation/v1"
	crv1 "github.com/google/go-containerregistry/pkg/v1"
)

// GroupLoader defines the interface for policy loaders from contract attachments
type GroupLoader interface {
	Load(context.Context, *v1.PolicyGroupAttachment) (*v1.PolicyGroup, *v12.ResourceDescriptor, error)
}

// FileGroupLoader loader loads policies from filesystem and HTTPS references using Cosign's blob package
type FileGroupLoader struct{}

func (l *FileGroupLoader) Load(_ context.Context, attachment *v1.PolicyGroupAttachment) (*v1.PolicyGroup, *v12.ResourceDescriptor, error) {
	var (
		raw []byte
		err error
	)

	// First remove the digest if present
	ref, wantDigest := ExtractDigest(attachment.GetRef())
	filePath, err := ensureScheme(ref, fileScheme)
	if err != nil {
		return nil, nil, err
	}

	raw, err = os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, nil, fmt.Errorf("loading policy spec: %w", err)
	}

	var group v1.PolicyGroup
	d, err := unmarshallResource(raw, ref, wantDigest, &group)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling policy spec: %w", err)
	}

	return &group, d, nil
}

// HTTPSGroupLoader loader loads policies from HTTP or HTTPS references
type HTTPSGroupLoader struct{}

func (l *HTTPSGroupLoader) Load(_ context.Context, attachment *v1.PolicyGroupAttachment) (*v1.PolicyGroup, *v12.ResourceDescriptor, error) {
	ref, wantDigest := ExtractDigest(attachment.GetRef())

	// and do not remove the scheme since we need http(s):// to make the request
	if _, err := ensureScheme(ref, httpScheme, httpsScheme); err != nil {
		return nil, nil, fmt.Errorf("invalid policy reference %q: %w", ref, err)
	}

	// #nosec G107
	resp, err := http.Get(ref)
	if err != nil {
		return nil, nil, fmt.Errorf("requesting remote policy: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading remote policy: %w", err)
	}

	var group v1.PolicyGroup
	d, err := unmarshallResource(raw, ref, wantDigest, &group)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling policy spec: %w", err)
	}

	return &group, d, nil
}

// ChainloopGroupLoader loads groups referenced with chainloop://provider/name URLs
type ChainloopGroupLoader struct {
	Client pb.AttestationServiceClient

	cacheMutex sync.Mutex
}

type groupWithReference struct {
	group     *v1.PolicyGroup
	reference *v12.ResourceDescriptor
}

var remoteGroupCache = make(map[string]*groupWithReference)

func NewChainloopGroupLoader(client pb.AttestationServiceClient) *ChainloopGroupLoader {
	return &ChainloopGroupLoader{Client: client}
}

func (c *ChainloopGroupLoader) Load(ctx context.Context, attachment *v1.PolicyGroupAttachment) (*v1.PolicyGroup, *v12.ResourceDescriptor, error) {
	ref := attachment.GetRef()

	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	if v, ok := remoteGroupCache[ref]; ok {
		return v.group, v.reference, nil
	}

	if !IsProviderScheme(ref) {
		return nil, nil, fmt.Errorf("invalid group reference %q", ref)
	}

	provider, name := ProviderParts(ref)

	resp, err := c.Client.GetPolicyGroup(ctx, &pb.AttestationServiceGetPolicyGroupRequest{
		Provider:  provider,
		GroupName: name,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("requesting remote group (provider: %s, name: %s): %w", provider, name, err)
	}

	h, err := crv1.NewHash(resp.Reference.GetDigest())
	if err != nil {
		return nil, nil, fmt.Errorf("parsing digest: %w", err)
	}

	reference := policyReferenceResourceDescriptor(resp.Reference.GetUrl(), h)
	// cache result
	remoteGroupCache[ref] = &groupWithReference{group: resp.GetGroup(), reference: reference}
	return resp.GetGroup(), reference, nil
}