# Copyright 2019 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

class Age < Formula
  desc "Simple, modern, secure file encryption"
  homepage "https://filippo.io/age"
  url "https://github.com/FiloSottile/age/archive/v1.0.0-rc.1.zip"
  sha256 "b9269bc3533fefb1dbbc90cb3683be4d4fa3ea41c1a8e7a3265415b2de26f007"

  depends_on "go" => :build

  def install
    mkdir bin
    system "go", "build", "-trimpath", "-o", bin, "-ldflags", "-X main.Version=v#{version}", "filippo.io/age/cmd/..."
    prefix.install_metafiles
  end
end
