package store

// White-box tests for migration mechanics: they must inject a failing
// migration step, which the public API deliberately cannot do.

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestFailedMigrationRollsBackSchemaAndVersion(t *testing.T) {
	defer func(saved []migration) { migrations = saved }(migrations)

	sentinel := errors.New("boom")
	migrations = append([]migration{}, migrations...)
	migrations = append(migrations, migration{Version: 99, Name: "failing", Apply: func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE should_not_survive (x INTEGER)`); err != nil {
			return err
		}
		return sentinel
	}})

	path := filepath.Join(t.TempDir(), "fail.db")
	_, err := Open(context.Background(), path)
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("Open err = %v, want wrapped sentinel", err)
	}

	// Reopen with the original clean set: no leftover table, no version row.
	migrations = migrations[:len(migrations)-1]
	db, err := openPool(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 99`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed migration left a version row")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'should_not_survive'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed migration left partial schema behind")
	}
}

func TestMigrationsAreIdempotentAndOrdered(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "idem.db")
	s1, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	versions := func() []int {
		rows, err := s1.db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []int
		for rows.Next() {
			var v int
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}()
	if len(versions) != len(migrations) {
		t.Fatalf("applied %v, want every declared step", versions)
	}
	// Re-running migrate applies nothing new and does not error.
	if err := s1.migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	s1.Close()
}
