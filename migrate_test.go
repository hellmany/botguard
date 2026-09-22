package botguard

import (
	"strings"
	"testing"
)

func TestCreateTableSQLUsesConfiguredName(t *testing.T) {
	ddl := createTableSQL("ja4.bg_fingerprints")
	if !strings.Contains(ddl, "CREATE TABLE IF NOT EXISTS ja4.bg_fingerprints") {
		t.Errorf("the schema-qualified name did not reach the DDL:\n%s", first(ddl))
	}
	if strings.Contains(ddl, "IF NOT EXISTS bg_fingerprints") {
		t.Error("the default name survived alongside the configured one")
	}
	// The trailing comments are not a statement and would break Exec.
	if strings.Contains(ddl, "-- Useful queries") {
		t.Error("comments must be stripped from the executed DDL")
	}
	if !strings.Contains(ddl, "PRIMARY KEY") {
		t.Error("the DDL lost its body")
	}
}

func TestCreateTableSQLPlainName(t *testing.T) {
	if ddl := createTableSQL("bg_fingerprints"); !strings.Contains(ddl, "CREATE TABLE IF NOT EXISTS bg_fingerprints") {
		t.Errorf("plain name broken:\n%s", first(ddl))
	}
}

// The store does not start when the table cannot be created.
func TestStoreDisabledWhenTableUnusable(t *testing.T) {
	db := openBrokenDB(t)
	defer db.Close()

	var got error
	s := newFingerprintStore(FingerprintStoreConfig{
		Enabled: true, DB: db, Table: "bg_fingerprints",
	}, func(err error) { got = err })

	if s != nil {
		t.Fatal("the store started even though the table is unusable")
	}
	if got == nil {
		t.Fatal("the caller was not told why statistics are off")
	}
	if !strings.Contains(got.Error(), "disabled") {
		t.Errorf("the error should say the store is disabled, got: %v", got)
	}
}

func first(s string) string {
	if i := strings.Index(s, "\n("); i > 0 {
		return s[:i]
	}
	return s
}

// Several instances may create the table at once; the DDL must be
// idempotent.
func TestCreateTableIsIdempotent(t *testing.T) {
	for _, name := range []string{"bg_fingerprints", "ja4.bg_fingerprints"} {
		if ddl := createTableSQL(name); !strings.Contains(ddl, "IF NOT EXISTS") {
			t.Errorf("%s: the DDL lost IF NOT EXISTS, concurrent starts would fail", name)
		}
	}
}

func TestAllowedCounterEverywhere(t *testing.T) {
	if !strings.Contains(createTableSQL("t"), "allowed") {
		t.Error("MySQL DDL lacks the allowed column")
	}
	for _, d := range []Dialect{DialectMySQL, DialectPostgres, DialectSQLite} {
		if !strings.Contains(d.upsertClause(), "allowed") {
			t.Errorf("%v upsert does not add allowed", d)
		}
		joined := strings.Join(SchemaFor(d, "t"), "\n")
		if !strings.Contains(joined, "allowed") {
			t.Errorf("%v DDL lacks the allowed column", d)
		}
	}
}
