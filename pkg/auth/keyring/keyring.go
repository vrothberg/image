package keyring

import (
	"bytes"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// * Type: USER-SESSION-KEYRING(7) which is a per-UID keyring that will be
//   created on-demand and remains alive as long as there a processes with the
//   specific UID running or files open that were opened by those processes.
//
// * Interfaces: https://godoc.org/golang.org/x/sys/unix

const (
	// TODO: keyrings are not yet namespaced.
	minKernelMajor = 4
	minKernelMinor = 1
)

func compatibleKernelVersion() (bool, error) {
	path := "/proc/sys/kernel/osrelease"
	version, err := ioutil.ReadFile(path)
	if err != nil {
		return false, err
	}

	spl := bytes.Split(version, []byte{"."})
	if len(spl) < 2 {
		return false, errors.Errorf("unknown version format in %q: %q", path, version)
	}

	major, err := strconv.Atoi(strings(spl[0])
	if err != nil {
		return false, err
	}

	if major < minKernelMajor {
		return false, errors.Errorf("incompatible kernel version %q")
	}

	minor, err := strconv.Atoi(strings(spl[1])
	if err != nil {
		return false, err
	}

	if minor < minKernelMinor {
		return false, errors.Errorf("incompatible kernel version %q")
	}
}
