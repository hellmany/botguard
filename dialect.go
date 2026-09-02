package botguard

import (
	"database/sql"
	"fmt"
	"strings"
)

// Dialect selects the SQL flavour for the fingerprint store. Empty means
// auto-detect from the driver behind *sql.DB, with MySQL as the fallback.
type Dialect string

const (
	DialectMySQL    Dialect = "mysql"
	DialectPostgres Dialect = "postgres"
	DialectSQLite   Dialect = "sqlite"
)

// detectDialect guesses the flavour from the driver's Go type: pgx and pq for
// Postgres, mattn and modernc for SQLite, everything else is treated as MySQL.
func detectDialect(db *sql.DB) Dialect {
	if db == nil {
		return DialectMySQL
	}
	name := strings.ToLower(fmt.Sprintf("%T", db.Driver()))
	switch {
	case strings.Contains(name, "pgx"), strings.Contains(name, "pq."), strings.Contains(name, "postgres"):
		return DialectPostgres
	case strings.Contains(name, "sqlite"):
		return DialectSQLite
	}
	return DialectMySQL
}

// placeholder returns the n-th (1-based) bind marker for the dialect.
func (d Dialect) placeholder(n int) string {
	if d == DialectPostgres {
		return "$" + fmt.Sprint(n)
	}
	return "?"
}

// upsertClause is what follows the VALUES list: counters add up, the
// descriptive columns take the latest value, verdict is left alone (it is
// labelled by hand or by an external job).
func (d Dialect) upsertClause() string {
	if d == DialectMySQL {
		return ` ON DUPLICATE KEY UPDATE
      hits=hits+VALUES(hits), challenged=challenged+VALUES(challenged),
      solved=solved+VALUES(solved), failed=failed+VALUES(failed),
      ua=VALUES(ua), ua_family=VALUES(ua_family), last_asn=VALUES(last_asn),
      last_cc=VALUES(last_cc), last_type=VALUES(last_type),
      last_seen=VALUES(last_seen)`
	}
	return ` ON CONFLICT (fp_kind, fingerprint, ua_hash) DO UPDATE SET
      hits=hits+EXCLUDED.hits, challenged=challenged+EXCLUDED.challenged,
      solved=solved+EXCLUDED.solved, failed=failed+EXCLUDED.failed,
      ua=EXCLUDED.ua, ua_family=EXCLUDED.ua_family, last_asn=EXCLUDED.last_asn,
      last_cc=EXCLUDED.last_cc, last_type=EXCLUDED.last_type,
      last_seen=EXCLUDED.last_seen`
}

// indexPrefix turns a possibly schema-qualified table name into something an
// index name can carry: "ja4.bg_fingerprints" → "ja4_bg_fingerprints".
func indexPrefix(table string) string {
	var b strings.Builder
	for _, c := range table {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// SchemaFor returns the DDL for the given dialect and table as separate
// statements, ready to be executed one by one. Postgres and SQLite get plain
// portable types instead of MySQL's ENUM and engine clause; the index names
// are derived from the table name so several tables can share a database.
func SchemaFor(d Dialect, table string) []string {
	if d == DialectMySQL {
		return []string{createTableSQL(table)}
	}
	// Postgres and SQLite: identical DDL apart from the counter type.
	counter := "BIGINT"
	if d == DialectSQLite {
		counter = "INTEGER"
	}
	p := indexPrefix(table)
	return []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  fp_kind     VARCHAR(8)    NOT NULL,
  fingerprint VARCHAR(64)   NOT NULL,
  ua_hash     CHAR(16)      NOT NULL,
  ua          VARCHAR(512)  NOT NULL,
  ua_family   VARCHAR(24)   NOT NULL DEFAULT '',
  last_asn    %[2]s         NOT NULL DEFAULT 0,
  last_cc     CHAR(2)       NOT NULL DEFAULT '',
  last_type   VARCHAR(32)   NOT NULL DEFAULT '',
  hits        %[2]s         NOT NULL DEFAULT 0,
  challenged  %[2]s         NOT NULL DEFAULT 0,
  solved      %[2]s         NOT NULL DEFAULT 0,
  failed      %[2]s         NOT NULL DEFAULT 0,
  verdict     VARCHAR(8)    NOT NULL DEFAULT 'unknown',
  first_seen  TIMESTAMP     NOT NULL,
  last_seen   TIMESTAMP     NOT NULL,
  PRIMARY KEY (fp_kind, fingerprint, ua_hash)
)`, table, counter),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_verdict ON %s (verdict)", p, table),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_last_seen ON %s (last_seen)", p, table),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_family ON %s (ua_family, fp_kind)", p, table),
	}
}
