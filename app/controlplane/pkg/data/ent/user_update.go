// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/group"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/groupmembership"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/membership"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/predicate"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/user"
	"github.com/google/uuid"
)

// UserUpdate is the builder for updating User entities.
type UserUpdate struct {
	config
	hooks     []Hook
	mutation  *UserMutation
	modifiers []func(*sql.UpdateBuilder)
}

// Where appends a list predicates to the UserUpdate builder.
func (uu *UserUpdate) Where(ps ...predicate.User) *UserUpdate {
	uu.mutation.Where(ps...)
	return uu
}

// SetEmail sets the "email" field.
func (uu *UserUpdate) SetEmail(s string) *UserUpdate {
	uu.mutation.SetEmail(s)
	return uu
}

// SetNillableEmail sets the "email" field if the given value is not nil.
func (uu *UserUpdate) SetNillableEmail(s *string) *UserUpdate {
	if s != nil {
		uu.SetEmail(*s)
	}
	return uu
}

// SetHasRestrictedAccess sets the "has_restricted_access" field.
func (uu *UserUpdate) SetHasRestrictedAccess(b bool) *UserUpdate {
	uu.mutation.SetHasRestrictedAccess(b)
	return uu
}

// SetNillableHasRestrictedAccess sets the "has_restricted_access" field if the given value is not nil.
func (uu *UserUpdate) SetNillableHasRestrictedAccess(b *bool) *UserUpdate {
	if b != nil {
		uu.SetHasRestrictedAccess(*b)
	}
	return uu
}

// ClearHasRestrictedAccess clears the value of the "has_restricted_access" field.
func (uu *UserUpdate) ClearHasRestrictedAccess() *UserUpdate {
	uu.mutation.ClearHasRestrictedAccess()
	return uu
}

// SetFirstName sets the "first_name" field.
func (uu *UserUpdate) SetFirstName(s string) *UserUpdate {
	uu.mutation.SetFirstName(s)
	return uu
}

// SetNillableFirstName sets the "first_name" field if the given value is not nil.
func (uu *UserUpdate) SetNillableFirstName(s *string) *UserUpdate {
	if s != nil {
		uu.SetFirstName(*s)
	}
	return uu
}

// ClearFirstName clears the value of the "first_name" field.
func (uu *UserUpdate) ClearFirstName() *UserUpdate {
	uu.mutation.ClearFirstName()
	return uu
}

// SetLastName sets the "last_name" field.
func (uu *UserUpdate) SetLastName(s string) *UserUpdate {
	uu.mutation.SetLastName(s)
	return uu
}

// SetNillableLastName sets the "last_name" field if the given value is not nil.
func (uu *UserUpdate) SetNillableLastName(s *string) *UserUpdate {
	if s != nil {
		uu.SetLastName(*s)
	}
	return uu
}

// ClearLastName clears the value of the "last_name" field.
func (uu *UserUpdate) ClearLastName() *UserUpdate {
	uu.mutation.ClearLastName()
	return uu
}

// AddMembershipIDs adds the "memberships" edge to the Membership entity by IDs.
func (uu *UserUpdate) AddMembershipIDs(ids ...uuid.UUID) *UserUpdate {
	uu.mutation.AddMembershipIDs(ids...)
	return uu
}

// AddMemberships adds the "memberships" edges to the Membership entity.
func (uu *UserUpdate) AddMemberships(m ...*Membership) *UserUpdate {
	ids := make([]uuid.UUID, len(m))
	for i := range m {
		ids[i] = m[i].ID
	}
	return uu.AddMembershipIDs(ids...)
}

// AddGroupIDs adds the "group" edge to the Group entity by IDs.
func (uu *UserUpdate) AddGroupIDs(ids ...uuid.UUID) *UserUpdate {
	uu.mutation.AddGroupIDs(ids...)
	return uu
}

// AddGroup adds the "group" edges to the Group entity.
func (uu *UserUpdate) AddGroup(g ...*Group) *UserUpdate {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uu.AddGroupIDs(ids...)
}

// AddGroupUserIDs adds the "group_users" edge to the GroupMembership entity by IDs.
func (uu *UserUpdate) AddGroupUserIDs(ids ...uuid.UUID) *UserUpdate {
	uu.mutation.AddGroupUserIDs(ids...)
	return uu
}

// AddGroupUsers adds the "group_users" edges to the GroupMembership entity.
func (uu *UserUpdate) AddGroupUsers(g ...*GroupMembership) *UserUpdate {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uu.AddGroupUserIDs(ids...)
}

// Mutation returns the UserMutation object of the builder.
func (uu *UserUpdate) Mutation() *UserMutation {
	return uu.mutation
}

// ClearMemberships clears all "memberships" edges to the Membership entity.
func (uu *UserUpdate) ClearMemberships() *UserUpdate {
	uu.mutation.ClearMemberships()
	return uu
}

// RemoveMembershipIDs removes the "memberships" edge to Membership entities by IDs.
func (uu *UserUpdate) RemoveMembershipIDs(ids ...uuid.UUID) *UserUpdate {
	uu.mutation.RemoveMembershipIDs(ids...)
	return uu
}

// RemoveMemberships removes "memberships" edges to Membership entities.
func (uu *UserUpdate) RemoveMemberships(m ...*Membership) *UserUpdate {
	ids := make([]uuid.UUID, len(m))
	for i := range m {
		ids[i] = m[i].ID
	}
	return uu.RemoveMembershipIDs(ids...)
}

// ClearGroup clears all "group" edges to the Group entity.
func (uu *UserUpdate) ClearGroup() *UserUpdate {
	uu.mutation.ClearGroup()
	return uu
}

// RemoveGroupIDs removes the "group" edge to Group entities by IDs.
func (uu *UserUpdate) RemoveGroupIDs(ids ...uuid.UUID) *UserUpdate {
	uu.mutation.RemoveGroupIDs(ids...)
	return uu
}

// RemoveGroup removes "group" edges to Group entities.
func (uu *UserUpdate) RemoveGroup(g ...*Group) *UserUpdate {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uu.RemoveGroupIDs(ids...)
}

// ClearGroupUsers clears all "group_users" edges to the GroupMembership entity.
func (uu *UserUpdate) ClearGroupUsers() *UserUpdate {
	uu.mutation.ClearGroupUsers()
	return uu
}

// RemoveGroupUserIDs removes the "group_users" edge to GroupMembership entities by IDs.
func (uu *UserUpdate) RemoveGroupUserIDs(ids ...uuid.UUID) *UserUpdate {
	uu.mutation.RemoveGroupUserIDs(ids...)
	return uu
}

// RemoveGroupUsers removes "group_users" edges to GroupMembership entities.
func (uu *UserUpdate) RemoveGroupUsers(g ...*GroupMembership) *UserUpdate {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uu.RemoveGroupUserIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (uu *UserUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, uu.sqlSave, uu.mutation, uu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (uu *UserUpdate) SaveX(ctx context.Context) int {
	affected, err := uu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (uu *UserUpdate) Exec(ctx context.Context) error {
	_, err := uu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (uu *UserUpdate) ExecX(ctx context.Context) {
	if err := uu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (uu *UserUpdate) check() error {
	if v, ok := uu.mutation.Email(); ok {
		if err := user.EmailValidator(v); err != nil {
			return &ValidationError{Name: "email", err: fmt.Errorf(`ent: validator failed for field "User.email": %w`, err)}
		}
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (uu *UserUpdate) Modify(modifiers ...func(u *sql.UpdateBuilder)) *UserUpdate {
	uu.modifiers = append(uu.modifiers, modifiers...)
	return uu
}

func (uu *UserUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := uu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(user.Table, user.Columns, sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID))
	if ps := uu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := uu.mutation.Email(); ok {
		_spec.SetField(user.FieldEmail, field.TypeString, value)
	}
	if value, ok := uu.mutation.HasRestrictedAccess(); ok {
		_spec.SetField(user.FieldHasRestrictedAccess, field.TypeBool, value)
	}
	if uu.mutation.HasRestrictedAccessCleared() {
		_spec.ClearField(user.FieldHasRestrictedAccess, field.TypeBool)
	}
	if value, ok := uu.mutation.FirstName(); ok {
		_spec.SetField(user.FieldFirstName, field.TypeString, value)
	}
	if uu.mutation.FirstNameCleared() {
		_spec.ClearField(user.FieldFirstName, field.TypeString)
	}
	if value, ok := uu.mutation.LastName(); ok {
		_spec.SetField(user.FieldLastName, field.TypeString, value)
	}
	if uu.mutation.LastNameCleared() {
		_spec.ClearField(user.FieldLastName, field.TypeString)
	}
	if uu.mutation.MembershipsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   user.MembershipsTable,
			Columns: []string{user.MembershipsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.RemovedMembershipsIDs(); len(nodes) > 0 && !uu.mutation.MembershipsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   user.MembershipsTable,
			Columns: []string{user.MembershipsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.MembershipsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   user.MembershipsTable,
			Columns: []string{user.MembershipsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if uu.mutation.GroupCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   user.GroupTable,
			Columns: user.GroupPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		createE := &GroupMembershipCreate{config: uu.config, mutation: newGroupMembershipMutation(uu.config, OpCreate)}
		createE.defaults()
		_, specE := createE.createSpec()
		edge.Target.Fields = specE.Fields
		if specE.ID.Value != nil {
			edge.Target.Fields = append(edge.Target.Fields, specE.ID)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.RemovedGroupIDs(); len(nodes) > 0 && !uu.mutation.GroupCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   user.GroupTable,
			Columns: user.GroupPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		createE := &GroupMembershipCreate{config: uu.config, mutation: newGroupMembershipMutation(uu.config, OpCreate)}
		createE.defaults()
		_, specE := createE.createSpec()
		edge.Target.Fields = specE.Fields
		if specE.ID.Value != nil {
			edge.Target.Fields = append(edge.Target.Fields, specE.ID)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.GroupIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   user.GroupTable,
			Columns: user.GroupPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		createE := &GroupMembershipCreate{config: uu.config, mutation: newGroupMembershipMutation(uu.config, OpCreate)}
		createE.defaults()
		_, specE := createE.createSpec()
		edge.Target.Fields = specE.Fields
		if specE.ID.Value != nil {
			edge.Target.Fields = append(edge.Target.Fields, specE.ID)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if uu.mutation.GroupUsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   user.GroupUsersTable,
			Columns: []string{user.GroupUsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(groupmembership.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.RemovedGroupUsersIDs(); len(nodes) > 0 && !uu.mutation.GroupUsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   user.GroupUsersTable,
			Columns: []string{user.GroupUsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(groupmembership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.GroupUsersIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   user.GroupUsersTable,
			Columns: []string{user.GroupUsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(groupmembership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(uu.modifiers...)
	if n, err = sqlgraph.UpdateNodes(ctx, uu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{user.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	uu.mutation.done = true
	return n, nil
}

// UserUpdateOne is the builder for updating a single User entity.
type UserUpdateOne struct {
	config
	fields    []string
	hooks     []Hook
	mutation  *UserMutation
	modifiers []func(*sql.UpdateBuilder)
}

// SetEmail sets the "email" field.
func (uuo *UserUpdateOne) SetEmail(s string) *UserUpdateOne {
	uuo.mutation.SetEmail(s)
	return uuo
}

// SetNillableEmail sets the "email" field if the given value is not nil.
func (uuo *UserUpdateOne) SetNillableEmail(s *string) *UserUpdateOne {
	if s != nil {
		uuo.SetEmail(*s)
	}
	return uuo
}

// SetHasRestrictedAccess sets the "has_restricted_access" field.
func (uuo *UserUpdateOne) SetHasRestrictedAccess(b bool) *UserUpdateOne {
	uuo.mutation.SetHasRestrictedAccess(b)
	return uuo
}

// SetNillableHasRestrictedAccess sets the "has_restricted_access" field if the given value is not nil.
func (uuo *UserUpdateOne) SetNillableHasRestrictedAccess(b *bool) *UserUpdateOne {
	if b != nil {
		uuo.SetHasRestrictedAccess(*b)
	}
	return uuo
}

// ClearHasRestrictedAccess clears the value of the "has_restricted_access" field.
func (uuo *UserUpdateOne) ClearHasRestrictedAccess() *UserUpdateOne {
	uuo.mutation.ClearHasRestrictedAccess()
	return uuo
}

// SetFirstName sets the "first_name" field.
func (uuo *UserUpdateOne) SetFirstName(s string) *UserUpdateOne {
	uuo.mutation.SetFirstName(s)
	return uuo
}

// SetNillableFirstName sets the "first_name" field if the given value is not nil.
func (uuo *UserUpdateOne) SetNillableFirstName(s *string) *UserUpdateOne {
	if s != nil {
		uuo.SetFirstName(*s)
	}
	return uuo
}

// ClearFirstName clears the value of the "first_name" field.
func (uuo *UserUpdateOne) ClearFirstName() *UserUpdateOne {
	uuo.mutation.ClearFirstName()
	return uuo
}

// SetLastName sets the "last_name" field.
func (uuo *UserUpdateOne) SetLastName(s string) *UserUpdateOne {
	uuo.mutation.SetLastName(s)
	return uuo
}

// SetNillableLastName sets the "last_name" field if the given value is not nil.
func (uuo *UserUpdateOne) SetNillableLastName(s *string) *UserUpdateOne {
	if s != nil {
		uuo.SetLastName(*s)
	}
	return uuo
}

// ClearLastName clears the value of the "last_name" field.
func (uuo *UserUpdateOne) ClearLastName() *UserUpdateOne {
	uuo.mutation.ClearLastName()
	return uuo
}

// AddMembershipIDs adds the "memberships" edge to the Membership entity by IDs.
func (uuo *UserUpdateOne) AddMembershipIDs(ids ...uuid.UUID) *UserUpdateOne {
	uuo.mutation.AddMembershipIDs(ids...)
	return uuo
}

// AddMemberships adds the "memberships" edges to the Membership entity.
func (uuo *UserUpdateOne) AddMemberships(m ...*Membership) *UserUpdateOne {
	ids := make([]uuid.UUID, len(m))
	for i := range m {
		ids[i] = m[i].ID
	}
	return uuo.AddMembershipIDs(ids...)
}

// AddGroupIDs adds the "group" edge to the Group entity by IDs.
func (uuo *UserUpdateOne) AddGroupIDs(ids ...uuid.UUID) *UserUpdateOne {
	uuo.mutation.AddGroupIDs(ids...)
	return uuo
}

// AddGroup adds the "group" edges to the Group entity.
func (uuo *UserUpdateOne) AddGroup(g ...*Group) *UserUpdateOne {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uuo.AddGroupIDs(ids...)
}

// AddGroupUserIDs adds the "group_users" edge to the GroupMembership entity by IDs.
func (uuo *UserUpdateOne) AddGroupUserIDs(ids ...uuid.UUID) *UserUpdateOne {
	uuo.mutation.AddGroupUserIDs(ids...)
	return uuo
}

// AddGroupUsers adds the "group_users" edges to the GroupMembership entity.
func (uuo *UserUpdateOne) AddGroupUsers(g ...*GroupMembership) *UserUpdateOne {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uuo.AddGroupUserIDs(ids...)
}

// Mutation returns the UserMutation object of the builder.
func (uuo *UserUpdateOne) Mutation() *UserMutation {
	return uuo.mutation
}

// ClearMemberships clears all "memberships" edges to the Membership entity.
func (uuo *UserUpdateOne) ClearMemberships() *UserUpdateOne {
	uuo.mutation.ClearMemberships()
	return uuo
}

// RemoveMembershipIDs removes the "memberships" edge to Membership entities by IDs.
func (uuo *UserUpdateOne) RemoveMembershipIDs(ids ...uuid.UUID) *UserUpdateOne {
	uuo.mutation.RemoveMembershipIDs(ids...)
	return uuo
}

// RemoveMemberships removes "memberships" edges to Membership entities.
func (uuo *UserUpdateOne) RemoveMemberships(m ...*Membership) *UserUpdateOne {
	ids := make([]uuid.UUID, len(m))
	for i := range m {
		ids[i] = m[i].ID
	}
	return uuo.RemoveMembershipIDs(ids...)
}

// ClearGroup clears all "group" edges to the Group entity.
func (uuo *UserUpdateOne) ClearGroup() *UserUpdateOne {
	uuo.mutation.ClearGroup()
	return uuo
}

// RemoveGroupIDs removes the "group" edge to Group entities by IDs.
func (uuo *UserUpdateOne) RemoveGroupIDs(ids ...uuid.UUID) *UserUpdateOne {
	uuo.mutation.RemoveGroupIDs(ids...)
	return uuo
}

// RemoveGroup removes "group" edges to Group entities.
func (uuo *UserUpdateOne) RemoveGroup(g ...*Group) *UserUpdateOne {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uuo.RemoveGroupIDs(ids...)
}

// ClearGroupUsers clears all "group_users" edges to the GroupMembership entity.
func (uuo *UserUpdateOne) ClearGroupUsers() *UserUpdateOne {
	uuo.mutation.ClearGroupUsers()
	return uuo
}

// RemoveGroupUserIDs removes the "group_users" edge to GroupMembership entities by IDs.
func (uuo *UserUpdateOne) RemoveGroupUserIDs(ids ...uuid.UUID) *UserUpdateOne {
	uuo.mutation.RemoveGroupUserIDs(ids...)
	return uuo
}

// RemoveGroupUsers removes "group_users" edges to GroupMembership entities.
func (uuo *UserUpdateOne) RemoveGroupUsers(g ...*GroupMembership) *UserUpdateOne {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return uuo.RemoveGroupUserIDs(ids...)
}

// Where appends a list predicates to the UserUpdate builder.
func (uuo *UserUpdateOne) Where(ps ...predicate.User) *UserUpdateOne {
	uuo.mutation.Where(ps...)
	return uuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (uuo *UserUpdateOne) Select(field string, fields ...string) *UserUpdateOne {
	uuo.fields = append([]string{field}, fields...)
	return uuo
}

// Save executes the query and returns the updated User entity.
func (uuo *UserUpdateOne) Save(ctx context.Context) (*User, error) {
	return withHooks(ctx, uuo.sqlSave, uuo.mutation, uuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (uuo *UserUpdateOne) SaveX(ctx context.Context) *User {
	node, err := uuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (uuo *UserUpdateOne) Exec(ctx context.Context) error {
	_, err := uuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (uuo *UserUpdateOne) ExecX(ctx context.Context) {
	if err := uuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (uuo *UserUpdateOne) check() error {
	if v, ok := uuo.mutation.Email(); ok {
		if err := user.EmailValidator(v); err != nil {
			return &ValidationError{Name: "email", err: fmt.Errorf(`ent: validator failed for field "User.email": %w`, err)}
		}
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (uuo *UserUpdateOne) Modify(modifiers ...func(u *sql.UpdateBuilder)) *UserUpdateOne {
	uuo.modifiers = append(uuo.modifiers, modifiers...)
	return uuo
}

func (uuo *UserUpdateOne) sqlSave(ctx context.Context) (_node *User, err error) {
	if err := uuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(user.Table, user.Columns, sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID))
	id, ok := uuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "User.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := uuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, user.FieldID)
		for _, f := range fields {
			if !user.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != user.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := uuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := uuo.mutation.Email(); ok {
		_spec.SetField(user.FieldEmail, field.TypeString, value)
	}
	if value, ok := uuo.mutation.HasRestrictedAccess(); ok {
		_spec.SetField(user.FieldHasRestrictedAccess, field.TypeBool, value)
	}
	if uuo.mutation.HasRestrictedAccessCleared() {
		_spec.ClearField(user.FieldHasRestrictedAccess, field.TypeBool)
	}
	if value, ok := uuo.mutation.FirstName(); ok {
		_spec.SetField(user.FieldFirstName, field.TypeString, value)
	}
	if uuo.mutation.FirstNameCleared() {
		_spec.ClearField(user.FieldFirstName, field.TypeString)
	}
	if value, ok := uuo.mutation.LastName(); ok {
		_spec.SetField(user.FieldLastName, field.TypeString, value)
	}
	if uuo.mutation.LastNameCleared() {
		_spec.ClearField(user.FieldLastName, field.TypeString)
	}
	if uuo.mutation.MembershipsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   user.MembershipsTable,
			Columns: []string{user.MembershipsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.RemovedMembershipsIDs(); len(nodes) > 0 && !uuo.mutation.MembershipsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   user.MembershipsTable,
			Columns: []string{user.MembershipsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.MembershipsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   user.MembershipsTable,
			Columns: []string{user.MembershipsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if uuo.mutation.GroupCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   user.GroupTable,
			Columns: user.GroupPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		createE := &GroupMembershipCreate{config: uuo.config, mutation: newGroupMembershipMutation(uuo.config, OpCreate)}
		createE.defaults()
		_, specE := createE.createSpec()
		edge.Target.Fields = specE.Fields
		if specE.ID.Value != nil {
			edge.Target.Fields = append(edge.Target.Fields, specE.ID)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.RemovedGroupIDs(); len(nodes) > 0 && !uuo.mutation.GroupCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   user.GroupTable,
			Columns: user.GroupPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		createE := &GroupMembershipCreate{config: uuo.config, mutation: newGroupMembershipMutation(uuo.config, OpCreate)}
		createE.defaults()
		_, specE := createE.createSpec()
		edge.Target.Fields = specE.Fields
		if specE.ID.Value != nil {
			edge.Target.Fields = append(edge.Target.Fields, specE.ID)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.GroupIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   user.GroupTable,
			Columns: user.GroupPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		createE := &GroupMembershipCreate{config: uuo.config, mutation: newGroupMembershipMutation(uuo.config, OpCreate)}
		createE.defaults()
		_, specE := createE.createSpec()
		edge.Target.Fields = specE.Fields
		if specE.ID.Value != nil {
			edge.Target.Fields = append(edge.Target.Fields, specE.ID)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if uuo.mutation.GroupUsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   user.GroupUsersTable,
			Columns: []string{user.GroupUsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(groupmembership.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.RemovedGroupUsersIDs(); len(nodes) > 0 && !uuo.mutation.GroupUsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   user.GroupUsersTable,
			Columns: []string{user.GroupUsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(groupmembership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.GroupUsersIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   user.GroupUsersTable,
			Columns: []string{user.GroupUsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(groupmembership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(uuo.modifiers...)
	_node = &User{config: uuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, uuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{user.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	uuo.mutation.done = true
	return _node, nil
}
