package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func persistUserPath(_ string, dir string, dry bool, out io.Writer) error {
	if strings.Contains(dir, ";") {
		return errors.New("install directory cannot contain a PATH separator")
	}
	if dry {
		fmt.Fprintf(out, "would add to user PATH: %s\n", dir)
		return nil
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, "Environment", registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	value, kind, err := k.GetStringValue("Path")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	oldValue := value
	parts := []string{dir}
	for _, part := range strings.Split(value, ";") {
		expanded, expandErr := registry.ExpandString(part)
		if expandErr == nil && strings.EqualFold(strings.TrimRight(expanded, `\/`), strings.TrimRight(dir, `\/`)) {
			continue
		}
		if part != "" {
			parts = append(parts, part)
		}
	}
	// Put this installation first, preserving the existing user entries and
	// registry type. System PATH entries are managed separately by Windows.
	value = strings.Join(parts, ";")
	if value == oldValue {
		fmt.Fprintln(out, "ok   PATH: user environment")
		return nil
	}
	if kind == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", value)
	} else {
		err = k.SetStringValue("Path", value)
	}
	if err != nil {
		return err
	}
	// Notify Explorer so newly launched terminals inherit the user PATH.
	name, _ := windows.UTF16PtrFromString("Environment")
	proc := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	if err := proc.Find(); err == nil {
		var result uintptr
		_, _, _ = proc.Call(0xffff, 0x001a, 0, uintptr(unsafe.Pointer(name)), 2, 5000, uintptr(unsafe.Pointer(&result)))
	}
	fmt.Fprintln(out, "ok   PATH: user environment (restart terminals and agent applications)")
	return nil
}
