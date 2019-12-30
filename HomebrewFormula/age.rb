# Copyright 2019 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

class Age < Formula
  desc "Simple, modern, secure file encryption"
  homepage "https://filippo.io/age"
  url "https://github.com/FiloSottile/age/archive/v1.0.0-beta2.zip"
  sha256 "b7417e94c32c7e9356e441815f814073009c4a6455da96bde1536fae8cb0edbf"

  depends_on "go" => :build

  def install
    mkdir bin
    system "go", "build", "-trimpath", "-o", bin, "filippo.io/age/cmd/..."
    prefix.install_metafiles
  end
end
