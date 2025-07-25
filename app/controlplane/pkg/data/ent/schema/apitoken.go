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

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type APIToken struct {
	ent.Schema
}

// Fields of the APIToken.
func (APIToken) Fields() []ent.Field {
	return []ent.Field{
		// API token identifier
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Unique(),
		field.String("name").Immutable(),
		// Optional description
		field.String("description").Optional(),
		field.Time("created_at").Default(time.Now).Immutable().Annotations(&entsql.Annotation{Default: "CURRENT_TIMESTAMP"}),
		field.Time("expires_at").Optional(),
		// the token can be manually revoked
		field.Time("revoked_at").Optional(),
		field.Time("last_used_at").Optional(),
		field.UUID("organization_id", uuid.UUID{}),
		// Tokens can be associated with a project
		// if this value is not set, the token is an organization level token
		field.UUID("project_id", uuid.UUID{}).Optional(),
	}
}

func (APIToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).Field("organization_id").Ref("api_tokens").Unique().Required(),
		edge.To("project", Project.Type).Field("project_id").Unique(),
	}
}

func (APIToken) Indexes() []ent.Index {
	return []ent.Index{
		// names are unique within a organization and affects only to non-deleted items
		// These are for org level tokens
		index.Fields("name").Edges("organization").Unique().Annotations(
			entsql.IndexWhere("revoked_at IS NULL AND project_id IS NULL"),
		),

		// for project level tokens, we scope the uniqueness to the organization and project
		index.Fields("name").Edges("project").Unique().Annotations(
			entsql.IndexWhere("revoked_at IS NULL AND project_id IS NOT NULL"),
		),
	}
}
