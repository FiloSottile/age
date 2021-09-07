# Copyright 2019 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

class Age < Formula
  desc "Simple, modern, secure file encryption"
  homepage "https://filippo.io/age"
  url "https://github.com/FiloSottile/age/archive/refs/tags/v1.0.0.zip"
  sha256 "d926766e52a160ed20afd76c5271d182ad4790f7b573e627cd33b44a66510c0d"
  head "https://github.com/FiloSottile/age.git"

  depends_on "go" => :build

  def install
    mkdir bin
    system "go", "build", "-trimpath", "-o", bin, "-ldflags", "-X main.Version=v#{version}", "filippo.io/age/cmd/..."
    prefix.install_metafiles
    man1.install "doc/age.1"
    man1.install "doc/age-keygen.1"
  end
end
