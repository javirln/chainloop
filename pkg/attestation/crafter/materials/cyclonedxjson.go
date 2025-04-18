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

package materials

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	schemaapi "github.com/chainloop-dev/chainloop/app/controlplane/api/workflowcontract/v1"
	"github.com/chainloop-dev/chainloop/internal/schemavalidators"
	api "github.com/chainloop-dev/chainloop/pkg/attestation/crafter/api/attestation/v1"
	"github.com/chainloop-dev/chainloop/pkg/casclient"
	remotename "github.com/google/go-containerregistry/pkg/name"

	"github.com/rs/zerolog"
)

const (
	// containerComponentKind is the kind of the main component when it's a container
	containerComponentKind = "container"
	// aquaTrivyRepoDigestPropertyKey is the key used by Aqua Trivy to store the repo digest
	aquaTrivyRepoDigestPropertyKey = "aquasecurity:trivy:RepoDigest"
)

type CyclonedxJSONCrafter struct {
	backend *casclient.CASBackend
	*crafterCommon
}

// mainComponentStruct internal struct to unmarshall the incoming CycloneDX JSON
type mainComponentStruct struct {
	Metadata struct {
		Component struct {
			Name       string `json:"name"`
			Type       string `json:"type"`
			Version    string `json:"version"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"component"`
	} `json:"metadata"`
}

func NewCyclonedxJSONCrafter(materialSchema *schemaapi.CraftingSchema_Material, backend *casclient.CASBackend, l *zerolog.Logger) (*CyclonedxJSONCrafter, error) {
	if materialSchema.Type != schemaapi.CraftingSchema_Material_SBOM_CYCLONEDX_JSON {
		return nil, fmt.Errorf("material type is not cyclonedx json")
	}

	return &CyclonedxJSONCrafter{
		backend:       backend,
		crafterCommon: &crafterCommon{logger: l, input: materialSchema},
	}, nil
}

func (i *CyclonedxJSONCrafter) Craft(ctx context.Context, filePath string) (*api.Attestation_Material, error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("can't open the file: %w", err)
	}

	var v interface{}
	if err := json.Unmarshal(f, &v); err != nil {
		i.logger.Debug().Err(err).Msg("error decoding file")
		return nil, fmt.Errorf("invalid cyclonedx sbom file: %w", ErrInvalidMaterialType)
	}

	// Setting the version to empty string to validate against the latest version of the schema
	err = schemavalidators.ValidateCycloneDX(v, "")
	if err != nil {
		i.logger.Debug().Err(err).Msgf("error decoding file: %#v", err)
		return nil, fmt.Errorf("invalid cyclonedx sbom file: %w", ErrInvalidMaterialType)
	}

	m, err := uploadAndCraft(ctx, i.input, i.backend, filePath, i.logger)
	if err != nil {
		return nil, fmt.Errorf("error crafting material: %w", err)
	}

	res := m
	res.M = &api.Attestation_Material_SbomArtifact{
		SbomArtifact: &api.Attestation_Material_SBOMArtifact{
			Artifact: m.GetArtifact(),
		},
	}

	// Include the main component information if available
	mainComponent, err := i.extractMainComponent(f)
	if err != nil {
		i.logger.Debug().Err(err).Msg("error extracting main component from sbom, skipping...")
	}

	// If the main component is available, include it in the material
	if mainComponent != nil {
		res.M.(*api.Attestation_Material_SbomArtifact).SbomArtifact.MainComponent = &api.Attestation_Material_SBOMArtifact_MainComponent{
			Name:    mainComponent.name,
			Kind:    mainComponent.kind,
			Version: mainComponent.version,
		}
	}

	return res, nil
}

// extractMainComponent inspects the SBOM and extracts the main component if any and available
func (i *CyclonedxJSONCrafter) extractMainComponent(rawFile []byte) (*SBOMMainComponentInfo, error) {
	var mainComponent mainComponentStruct
	err := json.Unmarshal(rawFile, &mainComponent)
	if err != nil {
		return nil, fmt.Errorf("error extracting main component: %w", err)
	}

	component := mainComponent.Metadata.Component

	// If the version is empty, try to extract it from the properties
	if component.Version == "" {
		for _, prop := range component.Properties {
			if prop.Name == aquaTrivyRepoDigestPropertyKey {
				if parts := strings.Split(prop.Value, "sha256:"); len(parts) == 2 {
					component.Version = fmt.Sprintf("sha256:%s", parts[1])
					break
				}
			}
		}
	}

	if component.Type != containerComponentKind {
		return &SBOMMainComponentInfo{
			name:    component.Name,
			kind:    component.Type,
			version: component.Version,
		}, nil
	}

	// Standardize the name to have the full repository name including the registry and
	// sanitize the name to remove the possible tag from the repository name
	ref, err := remotename.ParseReference(component.Name)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse OCI image repository name: %w", err)
	}

	return &SBOMMainComponentInfo{
		name:    ref.Context().String(),
		kind:    component.Type,
		version: component.Version,
	}, nil
}
