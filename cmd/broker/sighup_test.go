package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// hupSurvivedMarker is printed by the child process below only if it is still
// running after sending itself a SIGHUP.
const hupSurvivedMarker = "BROKER-SURVIVED-SIGHUP"

// childEnv makes the test re-invoke itself as the process under test.
const childEnv = "OIDC_BROKER_SIGHUP_CHILD"

// A SIGHUP must not kill the broker.
//
// Go's default disposition for SIGHUP is to terminate, and the broker has no reload,
// so a `systemctl reload` or a logrotate postrotate stanza used to take the host's
// authentication down for RestartSec=10s — daily, at whatever hour logrotate runs,
// with nothing in the journal that reads as an error (#224).
//
// This has to run in a child process: the assertion is that the process is still
// alive, which cannot be made about a test binary that has already been killed. The
// child sends the signal to itself, so delivery is not racy — kill(2) delivers an
// unblocked pending signal before it returns, which means an unhandled SIGHUP would
// have terminated the child before it could print anything.
func TestSIGHUPDoesNotKillTheBroker(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		runSIGHUPChild()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSIGHUPDoesNotKillTheBroker$") // #nosec G204 -- re-executes this test binary
	cmd.Env = append(os.Environ(), childEnv+"=1")
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("the broker installs no SIGHUP handler, so SIGHUP killed it (%v). "+
			"`systemctl reload`, or any logrotate postrotate stanza that reloads the "+
			"service, is then a ten-second authentication outage for the whole host "+
			"(#224).\nchild output:\n%s", err, output)
	}
	if !strings.Contains(string(output), hupSurvivedMarker) {
		t.Fatalf("child exited 0 but never reported surviving SIGHUP; the test proved "+
			"nothing.\nchild output:\n%s", output)
	}
}

// runSIGHUPChild is the process under test: it installs the broker's real signal
// handling and then sends itself the signal.
func runSIGHUPChild() {
	ignoreSIGHUP()

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		_, _ = os.Stderr.WriteString("failed to send SIGHUP: " + err.Error() + "\n")
		os.Exit(3)
	}

	// Belt and braces: if nothing is handling SIGHUP the kernel has already killed
	// us by now, so reaching the print below is the result.
	time.Sleep(100 * time.Millisecond)

	_, _ = os.Stdout.WriteString(hupSurvivedMarker + "\n")
	os.Exit(0)
}
