// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package term

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func init() {
	enableVirtualTerminalProcessing = func(out *os.File) error {
		// Some instances of the Windows Console (e.g., cmd.exe and Windows PowerShell)
		// do not have the virtual terminal processing enabled, which is necessary to
		// make terminal escape sequences work. For this reason the clearLine function
		// may not properly work. Here we enable the virtual terminal processing, if
		// possible.
		//
		// See https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences.

		const (
			ENABLE_PROCESSED_OUTPUT            uint32 = 0x1
			ENABLE_VIRTUAL_TERMINAL_PROCESSING uint32 = 0x4
		)

		kernel32DLL := windows.NewLazySystemDLL("Kernel32.dll")
		setConsoleMode := kernel32DLL.NewProc("SetConsoleMode")

		var mode uint32
		if err := syscall.GetConsoleMode(syscall.Handle(out.Fd()), &mode); err != nil {
			return err
		}

		mode |= ENABLE_PROCESSED_OUTPUT
		mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING

		// If the SetConsoleMode function fails, the return value is zero.
		// See https://learn.microsoft.com/en-us/windows/console/setconsolemode#return-value.
		if ret, _, _ := setConsoleMode.Call(out.Fd(), uintptr(mode)); ret == 0 {
			return errors.New("SetConsoleMode failed")
		}
		return nil
	}
}
