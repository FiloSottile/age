// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package mlockall

import (
	"log"
	"syscall"
)

func init() {
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		log.Println(err)
		log.Fatal("Can't lock memory pages in RAM, it's unsafe to run age")
	}
}
