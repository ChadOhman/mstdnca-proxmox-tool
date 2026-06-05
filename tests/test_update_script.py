"""Static checks for scripts/update.sh."""
import os
import subprocess
import sys

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "update.sh")


def _read():
    with open(SCRIPT, encoding="utf-8") as f:
        return f.read()


def _bash_syntax_check(script_path):
    """Run `bash -n` on the script, handling Windows paths and CRLF line endings."""
    if sys.platform != "win32":
        return subprocess.run(["bash", "-n", script_path], capture_output=True, text=True)

    # On Windows, Python subprocess uses WSL bash which needs /mnt/c/... paths.
    # The script may have CRLF line endings; strip them via `tr` to avoid
    # spurious "syntax error near unexpected token" failures in the checker.
    wsl_path_result = subprocess.run(
        ["bash", "-c", f'wslpath "{script_path.replace(chr(92), "/")}"'],
        capture_output=True,
        text=True,
    )
    if wsl_path_result.returncode != 0:
        # Fall back to raw path
        posix_path = script_path.replace("\\", "/")
    else:
        posix_path = wsl_path_result.stdout.strip()

    return subprocess.run(
        ["bash", "-c", f'bash -n <(cat "{posix_path}" | tr -d "\\r")'],
        capture_output=True,
        text=True,
    )


def test_script_syntax_is_valid():
    result = _bash_syntax_check(SCRIPT)
    assert result.returncode == 0, result.stderr


def test_fetch_uses_token_extraheader_when_present():
    content = _read()
    assert 'GITHUB_TOKEN' in content
    assert 'http.extraheader=' in content
    # token is passed via -c extraheader, never embedded in a remote URL
    assert '@github.com' not in content


def test_fetch_uses_basic_auth_not_bearer():
    # GitHub git-over-HTTPS accepts Basic auth (token as password), not Bearer.
    # Bearer authenticates the REST API only; using it for git transport 401s.
    content = _read()
    assert 'Authorization: Basic' in content
    assert 'x-access-token' in content
    # guard against the broken command form (Bearer in the actual fetch header),
    # not prose: the comment may legitimately mention Bearer to explain the choice
    assert 'extraheader="authorization: bearer' not in content.lower()
