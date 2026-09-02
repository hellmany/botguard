package botguard

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
)

// brokenDriver fails every statement, standing in for a database where the
// table is missing and cannot be created.
type brokenDriver struct{}

func (brokenDriver) Open(string) (driver.Conn, error) { return brokenConn{}, nil }

type brokenConn struct{}

func (brokenConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no such table") }
func (brokenConn) Close() error                        { return nil }
func (brokenConn) Begin() (driver.Tx, error)           { return nil, errors.New("no") }

func openBrokenDB(t *testing.T) *sql.DB {
	t.Helper()
	name := "botguard_broken_" + t.Name()
	sql.Register(name, brokenDriver{})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	return db
}
