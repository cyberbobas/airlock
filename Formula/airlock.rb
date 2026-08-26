# Homebrew formula for Airlock.  Tap: brew tap cyberbobas/tap && brew install airlock
class Airlock < Formula
  include Language::Python::Virtualenv

  desc "Runtime firewall for AI coding agents — gate every tool, MCP and skill call"
  homepage "https://github.com/cyberbobas/airlock"
  url "https://github.com/cyberbobas/airlock/archive/refs/tags/v0.4.6.tar.gz"
  sha256 "d599f8a7ed58310497f2ef65fd0cffbdf9b2282eee8e237edea15ae61596c353"
  license "Apache-2.0"

  depends_on "python@3.12"

  resource "PyYAML" do
    url "https://files.pythonhosted.org/packages/05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz"
    sha256 "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"
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
