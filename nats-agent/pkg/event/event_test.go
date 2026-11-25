package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func input() Input {
	return Input{
		BackupSessionName:       "bs-1",
		BackupSessionNamespace:  "demo",
		BackupConfigurationName: "bc-1",
		Message:                 "backup done",
		Phase:                   "Succeeded",
	}
}

func TestValidate(t *testing.T) {
	if err := input().Validate(); err != nil {
		t.Fatal(err)
	}
	in := input()
	in.BackupSessionName = ""
	in.Phase = "   "
	err := in.Validate()
	if err == nil || err.Error() != "empty value for: backupSessionName, phase" {
		t.Fatalf("Validate = %v", err)
	}
}

func TestNewBackupJSON(t *testing.T) {
	at := time.Date(2026, 11, 25, 19, 4, 5, 6, time.FixedZone("BDT", 6*3600))
	ev, err := NewBackup(input(), "backup", "uuid-1", at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"backupSessionName":"bs-1","backupSessionNamespace":"demo","backupConfigurationName":"bc-1",` +
		`"message":"backup done","phase":"Succeeded","kind":"backup","uuid":"uuid-1","time":"2026-11-25T13:04:05.000000006Z"}`
	if string(b) != want {
		t.Fatalf("json =\n%s\nwant\n%s", b, want)
	}
}

func TestNewBackupErrors(t *testing.T) {
	if _, err := NewBackup(Input{}, "backup", "u", time.Now()); err == nil || !strings.Contains(err.Error(), "backupSessionName") {
		t.Fatalf("want validation error, got %v", err)
	}
	if _, err := NewBackup(input(), "", "u", time.Now()); err == nil {
		t.Fatal("want error for empty kind")
	}
	if _, err := NewBackup(input(), "backup", "", time.Now()); err == nil {
		t.Fatal("want error for empty uuid")
	}
}

func TestSubject(t *testing.T) {
	if got := Subject("abc", "backup"); got != "abc.backup.events" {
		t.Fatalf("Subject = %q", got)
	}
}
