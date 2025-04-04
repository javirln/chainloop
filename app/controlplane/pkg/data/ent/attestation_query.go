// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/attestation"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/predicate"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/workflowrun"
	"github.com/google/uuid"
)

// AttestationQuery is the builder for querying Attestation entities.
type AttestationQuery struct {
	config
	ctx             *QueryContext
	order           []attestation.OrderOption
	inters          []Interceptor
	predicates      []predicate.Attestation
	withWorkflowrun *WorkflowRunQuery
	modifiers       []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AttestationQuery builder.
func (aq *AttestationQuery) Where(ps ...predicate.Attestation) *AttestationQuery {
	aq.predicates = append(aq.predicates, ps...)
	return aq
}

// Limit the number of records to be returned by this query.
func (aq *AttestationQuery) Limit(limit int) *AttestationQuery {
	aq.ctx.Limit = &limit
	return aq
}

// Offset to start from.
func (aq *AttestationQuery) Offset(offset int) *AttestationQuery {
	aq.ctx.Offset = &offset
	return aq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (aq *AttestationQuery) Unique(unique bool) *AttestationQuery {
	aq.ctx.Unique = &unique
	return aq
}

// Order specifies how the records should be ordered.
func (aq *AttestationQuery) Order(o ...attestation.OrderOption) *AttestationQuery {
	aq.order = append(aq.order, o...)
	return aq
}

// QueryWorkflowrun chains the current query on the "workflowrun" edge.
func (aq *AttestationQuery) QueryWorkflowrun() *WorkflowRunQuery {
	query := (&WorkflowRunClient{config: aq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := aq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := aq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(attestation.Table, attestation.FieldID, selector),
			sqlgraph.To(workflowrun.Table, workflowrun.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, attestation.WorkflowrunTable, attestation.WorkflowrunColumn),
		)
		fromU = sqlgraph.SetNeighbors(aq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Attestation entity from the query.
// Returns a *NotFoundError when no Attestation was found.
func (aq *AttestationQuery) First(ctx context.Context) (*Attestation, error) {
	nodes, err := aq.Limit(1).All(setContextOp(ctx, aq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{attestation.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (aq *AttestationQuery) FirstX(ctx context.Context) *Attestation {
	node, err := aq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Attestation ID from the query.
// Returns a *NotFoundError when no Attestation ID was found.
func (aq *AttestationQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = aq.Limit(1).IDs(setContextOp(ctx, aq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{attestation.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (aq *AttestationQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := aq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Attestation entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Attestation entity is found.
// Returns a *NotFoundError when no Attestation entities are found.
func (aq *AttestationQuery) Only(ctx context.Context) (*Attestation, error) {
	nodes, err := aq.Limit(2).All(setContextOp(ctx, aq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{attestation.Label}
	default:
		return nil, &NotSingularError{attestation.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (aq *AttestationQuery) OnlyX(ctx context.Context) *Attestation {
	node, err := aq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Attestation ID in the query.
// Returns a *NotSingularError when more than one Attestation ID is found.
// Returns a *NotFoundError when no entities are found.
func (aq *AttestationQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = aq.Limit(2).IDs(setContextOp(ctx, aq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{attestation.Label}
	default:
		err = &NotSingularError{attestation.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (aq *AttestationQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := aq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Attestations.
func (aq *AttestationQuery) All(ctx context.Context) ([]*Attestation, error) {
	ctx = setContextOp(ctx, aq.ctx, ent.OpQueryAll)
	if err := aq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Attestation, *AttestationQuery]()
	return withInterceptors[[]*Attestation](ctx, aq, qr, aq.inters)
}

// AllX is like All, but panics if an error occurs.
func (aq *AttestationQuery) AllX(ctx context.Context) []*Attestation {
	nodes, err := aq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Attestation IDs.
func (aq *AttestationQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if aq.ctx.Unique == nil && aq.path != nil {
		aq.Unique(true)
	}
	ctx = setContextOp(ctx, aq.ctx, ent.OpQueryIDs)
	if err = aq.Select(attestation.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (aq *AttestationQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := aq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (aq *AttestationQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, aq.ctx, ent.OpQueryCount)
	if err := aq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, aq, querierCount[*AttestationQuery](), aq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (aq *AttestationQuery) CountX(ctx context.Context) int {
	count, err := aq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (aq *AttestationQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, aq.ctx, ent.OpQueryExist)
	switch _, err := aq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (aq *AttestationQuery) ExistX(ctx context.Context) bool {
	exist, err := aq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AttestationQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (aq *AttestationQuery) Clone() *AttestationQuery {
	if aq == nil {
		return nil
	}
	return &AttestationQuery{
		config:          aq.config,
		ctx:             aq.ctx.Clone(),
		order:           append([]attestation.OrderOption{}, aq.order...),
		inters:          append([]Interceptor{}, aq.inters...),
		predicates:      append([]predicate.Attestation{}, aq.predicates...),
		withWorkflowrun: aq.withWorkflowrun.Clone(),
		// clone intermediate query.
		sql:       aq.sql.Clone(),
		path:      aq.path,
		modifiers: append([]func(*sql.Selector){}, aq.modifiers...),
	}
}

// WithWorkflowrun tells the query-builder to eager-load the nodes that are connected to
// the "workflowrun" edge. The optional arguments are used to configure the query builder of the edge.
func (aq *AttestationQuery) WithWorkflowrun(opts ...func(*WorkflowRunQuery)) *AttestationQuery {
	query := (&WorkflowRunClient{config: aq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	aq.withWorkflowrun = query
	return aq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Attestation.Query().
//		GroupBy(attestation.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (aq *AttestationQuery) GroupBy(field string, fields ...string) *AttestationGroupBy {
	aq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &AttestationGroupBy{build: aq}
	grbuild.flds = &aq.ctx.Fields
	grbuild.label = attestation.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//	}
//
//	client.Attestation.Query().
//		Select(attestation.FieldCreatedAt).
//		Scan(ctx, &v)
func (aq *AttestationQuery) Select(fields ...string) *AttestationSelect {
	aq.ctx.Fields = append(aq.ctx.Fields, fields...)
	sbuild := &AttestationSelect{AttestationQuery: aq}
	sbuild.label = attestation.Label
	sbuild.flds, sbuild.scan = &aq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a AttestationSelect configured with the given aggregations.
func (aq *AttestationQuery) Aggregate(fns ...AggregateFunc) *AttestationSelect {
	return aq.Select().Aggregate(fns...)
}

func (aq *AttestationQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range aq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, aq); err != nil {
				return err
			}
		}
	}
	for _, f := range aq.ctx.Fields {
		if !attestation.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if aq.path != nil {
		prev, err := aq.path(ctx)
		if err != nil {
			return err
		}
		aq.sql = prev
	}
	return nil
}

func (aq *AttestationQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Attestation, error) {
	var (
		nodes       = []*Attestation{}
		_spec       = aq.querySpec()
		loadedTypes = [1]bool{
			aq.withWorkflowrun != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Attestation).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Attestation{config: aq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(aq.modifiers) > 0 {
		_spec.Modifiers = aq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, aq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := aq.withWorkflowrun; query != nil {
		if err := aq.loadWorkflowrun(ctx, query, nodes, nil,
			func(n *Attestation, e *WorkflowRun) { n.Edges.Workflowrun = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (aq *AttestationQuery) loadWorkflowrun(ctx context.Context, query *WorkflowRunQuery, nodes []*Attestation, init func(*Attestation), assign func(*Attestation, *WorkflowRun)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Attestation)
	for i := range nodes {
		fk := nodes[i].WorkflowrunID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(workflowrun.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "workflowrun_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (aq *AttestationQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := aq.querySpec()
	if len(aq.modifiers) > 0 {
		_spec.Modifiers = aq.modifiers
	}
	_spec.Node.Columns = aq.ctx.Fields
	if len(aq.ctx.Fields) > 0 {
		_spec.Unique = aq.ctx.Unique != nil && *aq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, aq.driver, _spec)
}

func (aq *AttestationQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(attestation.Table, attestation.Columns, sqlgraph.NewFieldSpec(attestation.FieldID, field.TypeUUID))
	_spec.From = aq.sql
	if unique := aq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if aq.path != nil {
		_spec.Unique = true
	}
	if fields := aq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, attestation.FieldID)
		for i := range fields {
			if fields[i] != attestation.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if aq.withWorkflowrun != nil {
			_spec.Node.AddColumnOnce(attestation.FieldWorkflowrunID)
		}
	}
	if ps := aq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := aq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := aq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := aq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (aq *AttestationQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(aq.driver.Dialect())
	t1 := builder.Table(attestation.Table)
	columns := aq.ctx.Fields
	if len(columns) == 0 {
		columns = attestation.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if aq.sql != nil {
		selector = aq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if aq.ctx.Unique != nil && *aq.ctx.Unique {
		selector.Distinct()
	}
	for _, m := range aq.modifiers {
		m(selector)
	}
	for _, p := range aq.predicates {
		p(selector)
	}
	for _, p := range aq.order {
		p(selector)
	}
	if offset := aq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := aq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ForUpdate locks the selected rows against concurrent updates, and prevent them from being
// updated, deleted or "selected ... for update" by other sessions, until the transaction is
// either committed or rolled-back.
func (aq *AttestationQuery) ForUpdate(opts ...sql.LockOption) *AttestationQuery {
	if aq.driver.Dialect() == dialect.Postgres {
		aq.Unique(false)
	}
	aq.modifiers = append(aq.modifiers, func(s *sql.Selector) {
		s.ForUpdate(opts...)
	})
	return aq
}

// ForShare behaves similarly to ForUpdate, except that it acquires a shared mode lock
// on any rows that are read. Other sessions can read the rows, but cannot modify them
// until your transaction commits.
func (aq *AttestationQuery) ForShare(opts ...sql.LockOption) *AttestationQuery {
	if aq.driver.Dialect() == dialect.Postgres {
		aq.Unique(false)
	}
	aq.modifiers = append(aq.modifiers, func(s *sql.Selector) {
		s.ForShare(opts...)
	})
	return aq
}

// Modify adds a query modifier for attaching custom logic to queries.
func (aq *AttestationQuery) Modify(modifiers ...func(s *sql.Selector)) *AttestationSelect {
	aq.modifiers = append(aq.modifiers, modifiers...)
	return aq.Select()
}

// AttestationGroupBy is the group-by builder for Attestation entities.
type AttestationGroupBy struct {
	selector
	build *AttestationQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (agb *AttestationGroupBy) Aggregate(fns ...AggregateFunc) *AttestationGroupBy {
	agb.fns = append(agb.fns, fns...)
	return agb
}

// Scan applies the selector query and scans the result into the given value.
func (agb *AttestationGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, agb.build.ctx, ent.OpQueryGroupBy)
	if err := agb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AttestationQuery, *AttestationGroupBy](ctx, agb.build, agb, agb.build.inters, v)
}

func (agb *AttestationGroupBy) sqlScan(ctx context.Context, root *AttestationQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(agb.fns))
	for _, fn := range agb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*agb.flds)+len(agb.fns))
		for _, f := range *agb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*agb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := agb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// AttestationSelect is the builder for selecting fields of Attestation entities.
type AttestationSelect struct {
	*AttestationQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (as *AttestationSelect) Aggregate(fns ...AggregateFunc) *AttestationSelect {
	as.fns = append(as.fns, fns...)
	return as
}

// Scan applies the selector query and scans the result into the given value.
func (as *AttestationSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, as.ctx, ent.OpQuerySelect)
	if err := as.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AttestationQuery, *AttestationSelect](ctx, as.AttestationQuery, as, as.inters, v)
}

func (as *AttestationSelect) sqlScan(ctx context.Context, root *AttestationQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(as.fns))
	for _, fn := range as.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*as.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := as.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// Modify adds a query modifier for attaching custom logic to queries.
func (as *AttestationSelect) Modify(modifiers ...func(s *sql.Selector)) *AttestationSelect {
	as.modifiers = append(as.modifiers, modifiers...)
	return as
}
