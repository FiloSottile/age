// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logger

import (
	"log"
	"os"
)

type Logger struct {
	ll *log.Logger
	// If TestOnlyPanicInsteadOfExit is true, exit will set testOnlyDidExit and
	// panic instead of calling os.Exit. This way, the wrapper in TestMain can
	// recover the panic and return the exit code only if it was originated in exit.
	TestOnlyPanicInsteadOfExit bool
	TestOnlyDidExit            bool
}

var Global = &Logger{ll: log.New(os.Stderr, "", 0)}

func (l *Logger) Exit(code int) {
	if l.TestOnlyPanicInsteadOfExit {
		l.TestOnlyDidExit = true
		panic(code)
	}
	os.Exit(code)
}

func (l *Logger) Printf(format string, v ...interface{}) {
	l.ll.Printf("age: "+format, v...)
}

func (l *Logger) Errorf(format string, v ...interface{}) {
	l.Printf("error: "+format, v...)
	l.Printf("report unexpected or unhelpful errors at https://filippo.io/age/report")
	l.Exit(1)
}

func (l *Logger) Warningf(format string, v ...interface{}) {
	l.Printf("warning: "+format, v...)
}

func (l *Logger) ErrorWithHint(error string, hints ...string) {
	l.Printf("error: %s", error)
	for _, hint := range hints {
		l.Printf("hint: %s", hint)
	}
	l.Printf("report unexpected or unhelpful errors at https://filippo.io/age/report")
	l.Exit(1)
}
