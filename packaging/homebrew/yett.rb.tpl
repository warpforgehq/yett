class Yett < Formula
  desc "Deliver secrets to a process environment from committed SOPS files"
  homepage "https://github.com/__REPO__"
  version "__VERSION__"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/__REPO__/releases/download/v__VERSION__/yett-v__VERSION__-aarch64-apple-darwin.tar.gz"
      sha256 "__SHA_DARWIN_ARM64__"
    end
    on_intel do
      url "https://github.com/__REPO__/releases/download/v__VERSION__/yett-v__VERSION__-x86_64-apple-darwin.tar.gz"
      sha256 "__SHA_DARWIN_X64__"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/__REPO__/releases/download/v__VERSION__/yett-v__VERSION__-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "__SHA_LINUX_ARM64__"
    end
    on_intel do
      url "https://github.com/__REPO__/releases/download/v__VERSION__/yett-v__VERSION__-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "__SHA_LINUX_X64__"
    end
  end

  def install
    bin.install "yett"
  end
end
