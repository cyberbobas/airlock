# Homebrew formula for Airlock.
#
# TEMPLATE — fill in the two sha256 values and the release tag before tapping:
#   1. cut a GitHub release v<version>, then:  brew fetch --build-from-source ...
#      or:  shasum -a 256 <the archive tarball>
#   2. refresh the PyYAML resource:  brew update-python-resources Formula/airlock.rb
#
# Once airlock-agent/homebrew-tap exists:
#   brew tap airlock-agent/tap && brew install airlock
class Airlock < Formula
  include Language::Python::Virtualenv

  desc "Runtime firewall for AI coding agents — gate every tool, MCP and skill call"
  homepage "https://github.com/airlock-agent/airlock"
  url "https://github.com/airlock-agent/airlock/archive/refs/tags/v0.4.6.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_TARBALL_SHA256"
  license "Apache-2.0"

  depends_on "python@3.12"

  resource "PyYAML" do
    url "https://files.pythonhosted.org/packages/source/P/PyYAML/PyYAML-6.0.2.tar.gz"
    sha256 "REPLACE_WITH_PYYAML_SDIST_SHA256"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "airlock #{version}", shell_output("#{bin}/airlock --version")
    # doctor runs without a config and exits cleanly enough to prove the wiring
    system bin/"airlock", "--help"
  end
end
