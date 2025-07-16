// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// Some instances of the Windows Console (e.g., cmd.exe and Windows PowerShell)
// do not have the virtual terminal processing enabled, which is necessary to
// make terminal escape sequences work. For this reason the clearLine function
// may not properly work. Here we enable the virtual terminal processing, if
// possible.
//
// See https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences.
func init() {
	const (
		ENABLE_PROCESSED_OUTPUT            uint32 = 0x1
		ENABLE_VIRTUAL_TERMINAL_PROCESSING uint32 = 0x4
	)

	kernel32DLL := windows.NewLazySystemDLL("Kernel32.dll")
	setConsoleMode := kernel32DLL.NewProc("SetConsoleMode")

	var mode uint32
	err := syscall.GetConsoleMode(syscall.Stdout, &mode)
	if err != nil {
		// Terminal escape sequences may work at this point, but we can't know.
		avoidTerminalEscapeSequences = true
		return
	}

	mode |= ENABLE_PROCESSED_OUTPUT
	mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING
	ret, _, _ := setConsoleMode.Call(uintptr(syscall.Stdout), uintptr(mode))
	// If the SetConsoleMode function fails, the return value is zero.
	// See https://learn.microsoft.com/en-us/windows/console/setconsolemode#return-value.
	if ret == 0 {
		avoidTerminalEscapeSequences = true
	}
}
