package coldfire_test

import (
	"os"
	"testing"

	"github.com/google/uuid"
	coldfire "github.com/redcode-labs/Coldfire"
)

func TestIsRoot(t *testing.T) {
	r := coldfire.IsRoot()
	t.Logf("%v", r)
}

func TestExists(t *testing.T) {
	fname := uuid.NewString()
	f, err := os.Create(fname)
	if err != nil {
		t.Errorf("failed to create test file: %s", err.Error())
	}
	f.Close()

	if b := coldfire.Exists(fname); !b {
		t.Errorf("coldfire.Exists: check failed: got %v, wanted %v", b, true)
	}

	if err := os.Remove(fname); err != nil {
		t.Errorf("failed to remove test file: %s", err.Error())
	}
}

func TestFilePermissions(t *testing.T) {
	fname := uuid.NewString()
	f, err := os.Create(fname)
	if err != nil {
		t.Errorf("failed to create test file: %s", err.Error())
	}
	f.Close()

	if r, w := coldfire.FilePermissions(fname); !r || !w {
		t.Errorf("coldfire.Exists: check failed: got %v %v, wanted %v %v", r, w, true, true)
	}

	if err := os.Remove(fname); err != nil {
		t.Errorf("failed to remove test file: %s", err.Error())
	}
}
