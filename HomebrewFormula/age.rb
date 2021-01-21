# Copyright 2019 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

class Age < Formula
  desc "Simple, modern, secure file encryption"
  homepage "https://filippo.io/age"
  url "https://github.com/FiloSottile/age/archive/v1.0.0-beta6.zip"
  sha256 "6ffa23aee0f03c3e00707915e4300591847a2b0c5157ca7a696eb39bfeb7359c"

  depends_on "go" => :build

  def install
    mkdir bin
    system "go", "build", "-trimpath", "-o", bin, "-ldflags", "-X main.Version=v#{version}", "filippo.io/age/cmd/..."
    prefix.install_metafiles
  end
end
