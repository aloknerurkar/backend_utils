package backend_utils

import (
	"io"
	"fmt"
	r "math/rand"
	"bytes"
	"time"
	"runtime"
	"crypto/rand"
	"net"
	"errors"
	"os/exec"
)

// Generic Errors
const NOENT = "Did not find entry."
const INVALID_REQ = "Invalid request."
const FATAL_ERROR = "Unrecoverable error."
const SERIALIZATION_ERROR = "Error while serializing/de-serializing messages."

// For generating random strings
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// NewUUID generates a random UUID according to RFC 4122
func NewUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40

	uuid_str := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])

	return uuid_str, err
}

// MyCaller returns the caller of the function that called it :)
func MyCaller() string {

	// we get the callers as uintptrs - but we just need 1
	fpcs := make([]uintptr, 1)

	// skip 3 levels to get to the caller of whoever called Caller()
	n := runtime.Callers(3, fpcs)
	if n == 0 {
		return "n/a" // proper error her would be better
	}

	// get the info of the actual function that's in the pointer
	fun := runtime.FuncForPC(fpcs[0]-1)
	if fun == nil {
		return "n/a"
	}

	// return its name
	return fun.Name()
}

func BufferStrings(args ...string) string {
	var buffer bytes.Buffer
	for _, str := range args {
		buffer.WriteString(str)
	}
	return buffer.String()
}

func RandStringBytes(n int) string {
	r.Seed(time.Now().Unix() + time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[r.Int63() % int64(len(letterBytes))]
	}
	return string(b)
}

func ExternalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags & net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags & net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

type CmdResult struct {
	Err error
	StdOut string
	StdErr string
}

func (c *CmdResult) String() string {
	var result string
	if c.Err != nil {
		result += fmt.Sprintf("ERR:%s ", c.Err.Error())
	}
	result += fmt.Sprintf("StdOut:%s ", c.StdOut)
	result += fmt.Sprintf("StdErr:%s ", c.StdErr)
	return result
}

func ExecCommand(name string, args... string) (result *CmdResult) {

	result = new(CmdResult)
	cmd := exec.Command(name, args...)

	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr

	result.Err = cmd.Run()
	if result.Err != nil {
		return
	}

	result.StdOut = stdOut.String()
	result.StdErr = stdErr.String()
	return
}