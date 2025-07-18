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
	"github.com/google/uuid"
)

// Organization holds the schema definition for the Organization entity.
type Organization struct {
	ent.Schema
}

// Fields of the Organization.
func (Organization) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Unique(),
		field.String("name").Unique(),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Annotations(&entsql.Annotation{
				Default: "CURRENT_TIMESTAMP",
			}),
		field.Bool("block_on_policy_violation").Default(false),
	}
}

// Edges of the Organization.
func (Organization) Edges() []ent.Edge {
	return []ent.Edge{
		// an org can have and belong to many users
		edge.To("memberships", Membership.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("workflow_contracts", WorkflowContract.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("workflows", Workflow.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("cas_backends", CASBackend.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("integrations", Integration.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("api_tokens", APIToken.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("projects", Project.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("groups", Group.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}
