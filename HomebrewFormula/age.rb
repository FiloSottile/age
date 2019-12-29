# Copyright 2019 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

class Age < Formula
  desc "Simple, modern, secure file encryption"
  homepage "https://filippo.io/age"
  url "https://github.com/FiloSottile/age/archive/v1.0.0-beta1.zip"
  sha256 "6c7b1de0f312bc6e17e6b26ec27598672d1064e0287f202da5ab7efa9a1bb9d8"

  depends_on "go" => :build

  def install
    mkdir bin
    system "go", "build", "-trimpath", "-o", bin, "filippo.io/age/cmd/..."
    prefix.install_metafiles
  end
end
