package botguard

import (
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
)

type pgxFakeDriver struct{ brokenDriver }
type sqlite3FakeDriver struct{ brokenDriver }

func (pgxFakeDriver) Open(string) (driver.Conn, error)     { return brokenConn{}, nil }
func (sqlite3FakeDriver) Open(string) (driver.Conn, error) { return brokenConn{}, nil }

func TestDetectDialectFromDriverType(t *testing.T) {
	sql.Register("bg_pgx_fake", pgxFakeDriver{})
	sql.Register("bg_sqlite3_fake", sqlite3FakeDriver{})
	pg, _ := sql.Open("bg_pgx_fake", "")
	lite, _ := sql.Open("bg_sqlite3_fake", "")
	if d := detectDialect(pg); d != DialectPostgres {
		t.Errorf("pgx driver detected as %q", d)
	}
	if d := detectDialect(lite); d != DialectSQLite {
		t.Errorf("sqlite driver detected as %q", d)
	}
	if d := detectDialect(nil); d != DialectMySQL {
		t.Errorf("nil db must fall back to mysql, got %q", d)
	}
}

func TestPlaceholdersPerDialect(t *testing.T) {
	if DialectPostgres.placeholder(3) != "$3" {
		t.Error("postgres wants $n markers")
	}
	if DialectMySQL.placeholder(3) != "?" || DialectSQLite.placeholder(3) != "?" {
		t.Error("mysql/sqlite want ? markers")
	}
}

func TestUpsertClausePerDialect(t *testing.T) {
	if !strings.Contains(DialectMySQL.upsertClause(), "ON DUPLICATE KEY UPDATE") {
		t.Error("mysql upsert")
	}
	for _, d := range []Dialect{DialectPostgres, DialectSQLite} {
		c := d.upsertClause()
		if !strings.Contains(c, "ON CONFLICT (fp_kind, fingerprint, ua_hash) DO UPDATE") ||
			!strings.Contains(c, "hits=hits+EXCLUDED.hits") {
			t.Errorf("%s upsert wrong:\n%s", d, c)
		}
	}
}

// Postgres/SQLite DDL comes as separate statements (pgx refuses
// multi-statement strings), with index names derived from the table.
func TestSchemaForPortableDialects(t *testing.T) {
	for _, d := range []Dialect{DialectPostgres, DialectSQLite} {
		stmts := SchemaFor(d, "ja4.bg_fingerprints")
		if len(stmts) != 4 {
			t.Fatalf("%s: %d statements, want table + 3 indexes", d, len(stmts))
		}
		if !strings.Contains(stmts[0], "CREATE TABLE IF NOT EXISTS ja4.bg_fingerprints") ||
			strings.Contains(stmts[0], "ENUM") || strings.Contains(stmts[0], "ENGINE=") {
			t.Errorf("%s DDL carries MySQL-isms:\n%s", d, stmts[0])
		}
		if !strings.Contains(stmts[1], "idx_ja4_bg_fingerprints_verdict") {
			t.Errorf("%s: index name not derived from table: %s", d, stmts[1])
		}
	}
	if s := SchemaFor(DialectMySQL, "bg_fingerprints"); len(s) != 1 || !strings.Contains(s[0], "ENGINE=InnoDB") {
		t.Error("mysql keeps its own DDL")
	}
}
