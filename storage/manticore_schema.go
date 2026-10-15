package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"enode/logging"
)

// ErrManticoreSchemaDrift is Init's answer to a Manticore table that differs from
// the one this build creates in a way only a rebuild repairs.
var ErrManticoreSchemaDrift = errors.New("manticore: table does not match this build")

// manticoreColumn is one column of the search table.
type manticoreColumn struct {
	name string
	// decl is the column's type as CREATE TABLE and ALTER TABLE ADD COLUMN spell it.
	decl string
}

// manticoreColumns is the table: one document per source row, carrying its file's
// hash and size so a search can group the sources back into files. The CREATE
// statement is built from it and a drifted table is repaired from it, so the two
// cannot disagree. Text fields are stored as well as indexed (Manticore's default
// for "text"), because a search result is answered from the index alone.
var manticoreColumns = []manticoreColumn{
	{name: "name", decl: "text"},
	{name: "title", decl: "text"},
	{name: "artist", decl: "text"},
	{name: "album", decl: "text"},
	{name: "file_key", decl: "bigint"},
	{name: "file_hash", decl: "string"},
	{name: "size", decl: "bigint"},
	{name: "client_key", decl: "bigint"},
	{name: "type", decl: "string"},
	{name: "ext", decl: "string"},
	{name: "codec", decl: "string"},
	{name: "length", decl: "uint"},
	{name: "bitrate", decl: "uint"},
	{name: "complete", decl: "uint"},
	{name: "online", decl: "uint"},
	{name: "time_offer", decl: "timestamp"},
	{name: "src_id", decl: "uint"},
	{name: "src_port", decl: "uint"},
	{name: "pass", decl: "bigint"},
}

// manticoreDescribed is one row of DESCRIBE, less the name.
type manticoreDescribed struct {
	Type       string
	Properties []string
}

// manticoreShape is what Manticore reports about a table.
//
// Settings holds only what differs from the engine's defaults: Manticore leaves a
// setting out of SHOW TABLE SETTINGS when it equals the default and normalises
// the rest (ngram_len='01' reads back as 1). That is why the shape a table should
// have is read off a probe table rather than written down here.
type manticoreShape struct {
	Columns  map[string]manticoreDescribed
	Settings map[string]string
}

// manticoreProbeDropTimeout bounds dropping the probe table, which runs even when
// the caller's context has ended so a cancelled startup does not leave one behind.
const manticoreProbeDropTimeout = 5 * time.Second

// manticoreCreateStatement is the CREATE TABLE for this build's definition.
func manticoreCreateStatement(table, options string) string {
	declarations := make([]string, 0, len(manticoreColumns))
	for _, c := range manticoreColumns {
		declarations = append(declarations, c.name+" "+c.decl)
	}
	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s) %s", table, strings.Join(declarations, ", "), options)
}

// compareManticoreTable lists what separates a table from the one this build
// would create.
//
// add is the attribute columns the table lacks, which can be added in place.
// problems is everything that cannot: a missing text field, a column of another
// type, a text field that is not indexed or not stored, a setting that differs.
// Extra columns and extra column properties are not drift — a Manticore upgrade
// adds properties of its own, and a false alarm here stops the server starting.
func compareManticoreTable(want, got manticoreShape) (add []manticoreColumn, problems []string) {
	for _, c := range manticoreColumns {
		wanted, ok := want.Columns[c.name]
		if !ok {
			continue
		}
		have, ok := got.Columns[c.name]
		switch {
		case !ok && c.fullText():
			problems = append(problems, fmt.Sprintf("text field %s is missing", c.name))
		case !ok:
			add = append(add, c)
		case !strings.EqualFold(have.Type, wanted.Type):
			problems = append(problems, fmt.Sprintf("column %s is %s, want %s", c.name, have.Type, wanted.Type))
		default:
			for _, property := range []string{"indexed", "stored"} {
				if slices.Contains(wanted.Properties, property) && !slices.Contains(have.Properties, property) {
					problems = append(problems, fmt.Sprintf("text field %s is not %s", c.name, property))
				}
			}
		}
	}

	keys := make([]string, 0, len(want.Settings)+len(got.Settings))
	for key := range want.Settings {
		keys = append(keys, key)
	}
	for key := range got.Settings {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range slices.Compact(keys) {
		wanted, inWant := want.Settings[key]
		have, inGot := got.Settings[key]
		switch {
		case !inGot:
			problems = append(problems, fmt.Sprintf("option %s is the default, want %s", key, wanted))
		case !inWant:
			problems = append(problems, fmt.Sprintf("option %s is %s, want the default", key, have))
		case have != wanted:
			problems = append(problems, fmt.Sprintf("option %s is %s, want %s", key, have, wanted))
		}
	}
	return add, problems
}

// parseManticoreDescribe turns DESCRIBE rows — field, type and, where the version
// reports them, properties — into columns by lower-case name.
func parseManticoreDescribe(rows [][]string) map[string]manticoreDescribed {
	columns := make(map[string]manticoreDescribed, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		described := manticoreDescribed{Type: strings.ToLower(strings.TrimSpace(row[1]))}
		if len(row) >= 3 {
			described.Properties = strings.Fields(strings.ToLower(row[2]))
		}
		columns[strings.ToLower(strings.TrimSpace(row[0]))] = described
	}
	return columns
}

// parseManticoreSettings reads the value of SHOW TABLE ... SETTINGS: one
// "key = value" per line.
func parseManticoreSettings(value string) map[string]string {
	settings := map[string]string{}
	for line := range strings.Lines(value) {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		settings[key] = strings.TrimSpace(val)
	}
	return settings
}

// checkTable makes sure an existing table is the one this build would create.
//
// The comparison is against a probe: a table made from this build's definition
// and the configured options, read back and dropped. Manticore reports both
// tables the same way, so a Manticore upgrade that changes how DESCRIBE spells a
// type, or which settings count as defaults, cannot make a correct table look
// wrong. A table that only lacks attribute columns is given them in place;
// anything else is refused as a whole and nothing is altered.
func (m *ManticoreEngine) checkTable(ctx context.Context) error {
	want, err := m.probeShape(ctx)
	if err != nil {
		return err
	}
	got, err := m.readShape(ctx, m.cfg.Table)
	if err != nil {
		return err
	}
	add, problems := compareManticoreTable(want, got)
	if len(problems) > 0 {
		return fmt.Errorf("%w (%s: %s). Start once with -reindex-manticore to recreate it",
			ErrManticoreSchemaDrift, m.cfg.Table, strings.Join(problems, "; "))
	}
	if len(add) == 0 {
		return nil
	}
	// An attribute starts out empty rather than wrong, so the table stays usable
	// while the next reconcile pass fills it.
	names := make([]string, 0, len(add))
	for _, c := range add {
		alter := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", m.cfg.Table, c.name, c.decl)
		if _, err := m.db.ExecContext(ctx, alter); err != nil {
			return fmt.Errorf("manticore: adding the %s column to %s: %w", c.name, m.cfg.Table, err)
		}
		names = append(names, c.name)
	}
	logging.Infof("manticore: added the %s column(s) to %s; the startup reconcile pass fills them",
		strings.Join(names, ", "), m.cfg.Table)
	return nil
}

// probeShape creates a throwaway table from this build's definition, reads it
// and drops it. The name is random so two servers sharing one Manticore cannot
// drop each other's probe halfway through reading it.
func (m *ManticoreEngine) probeShape(ctx context.Context) (manticoreShape, error) {
	name := manticoreProbeName(m.cfg.Table)
	if _, err := m.db.ExecContext(ctx, manticoreCreateStatement(name, m.cfg.TableOptions)); err != nil {
		return manticoreShape{}, fmt.Errorf("manticore: creating the probe table %s: %w", name, err)
	}
	defer func() {
		dropCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), manticoreProbeDropTimeout)
		defer cancel()
		if _, err := m.db.ExecContext(dropCtx, "DROP TABLE IF EXISTS "+name); err != nil {
			logging.Warnf("manticore: dropping the probe table %s: %v; it is empty and safe to drop by hand", name, err)
		}
	}()
	return m.readShape(ctx, name)
}

// readShape reads a table's columns and settings.
func (m *ManticoreEngine) readShape(ctx context.Context, table string) (manticoreShape, error) {
	described, err := m.readRows(ctx, "DESCRIBE "+table)
	if err != nil {
		return manticoreShape{}, fmt.Errorf("manticore: describing table %s: %w", table, err)
	}
	settings, err := m.readRows(ctx, fmt.Sprintf("SHOW TABLE %s SETTINGS", table))
	if err != nil {
		return manticoreShape{}, fmt.Errorf("manticore: reading the settings of table %s: %w", table, err)
	}
	shape := manticoreShape{Columns: parseManticoreDescribe(described), Settings: map[string]string{}}
	for _, row := range settings {
		if len(row) >= 2 && strings.EqualFold(row[0], "settings") {
			shape.Settings = parseManticoreSettings(row[1])
		}
	}
	return shape, nil
}

// readRows runs a statement and returns every row as strings. DESCRIBE's column
// count varies between Manticore versions, so rows are scanned into as many cells
// as the result actually has.
func (m *ManticoreEngine) readRows(ctx context.Context, statement string) ([][]string, error) {
	rows, err := m.db.QueryContext(ctx, statement)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]string
	for rows.Next() {
		cells := make([]sql.RawBytes, len(columns))
		targets := make([]any, len(cells))
		for i := range cells {
			targets[i] = &cells[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, err
		}
		row := make([]string, len(cells))
		for i, cell := range cells {
			row[i] = string(cell)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// recreateTable drops the table and creates it from this build's definition. A
// drop rather than TRUNCATE, which would keep whatever definition and options the
// table was made with — and a table that no longer matches them is the reason to
// call this.
func (m *ManticoreEngine) recreateTable(ctx context.Context) error {
	if _, err := m.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+m.cfg.Table); err != nil {
		return fmt.Errorf("manticore: dropping %s: %w", m.cfg.Table, err)
	}
	if _, err := m.db.ExecContext(ctx, manticoreCreateStatement(m.cfg.Table, m.cfg.TableOptions)); err != nil {
		return fmt.Errorf("manticore: creating table %s: %w", m.cfg.Table, err)
	}
	return nil
}

// manticoreProbeName is a table name no other process will pick.
func manticoreProbeName(table string) string {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix) // never fails: crypto/rand crashes the program instead
	return table + "_probe_" + hex.EncodeToString(suffix)
}

// fullText reports whether the column is a text field. A text field is never
// added in place: a table without one is far more likely someone else's than an
// older build's, and a table that is not ours is refused rather than reshaped.
func (c manticoreColumn) fullText() bool {
	return strings.HasPrefix(c.decl, "text")
}
