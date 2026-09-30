"""The unattended apt command shared by every apply path.

Two production failures shaped it: a dpkg conffile prompt (pgbouncer.ini on
an Ubuntu guest) hung a bulk update until the job timeout, and the guest that
timeout killed then refused every later run with "dpkg was interrupted, you
must manually run 'dpkg --configure -a'".
"""

import shlex

from core.scanner import apt_upgrade_command


class TestAptUpgradeCommand:
    def test_conffile_prompts_are_answered_for_dpkg(self):
        cmd = apt_upgrade_command()
        assert "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y" in cmd
        # DEBIAN_FRONTEND only silences debconf; dpkg's own conffile question
        # needs the force-conf options or it blocks on stdin.
        assert "-o Dpkg::Options::=--force-confdef" in cmd
        assert "-o Dpkg::Options::=--force-confold" in cmd

    def test_dist_upgrade_variant(self):
        cmd = apt_upgrade_command(dist_upgrade=True)
        assert "apt-get dist-upgrade -y" in cmd
        assert "apt-get upgrade -y" not in cmd

    def test_interrupted_dpkg_is_repaired_before_upgrading(self):
        cmd = apt_upgrade_command()
        repair, upgrade = cmd.split(" && ")
        assert repair.startswith("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
        assert "--force-confdef" in repair and "--force-confold" in repair
        assert upgrade.startswith("DEBIAN_FRONTEND=noninteractive apt-get ")

    def test_safe_inside_single_quoted_sh_c(self):
        # routes/api.py wraps it in sudo -n sh -c '...' and the guest-agent
        # path in sh -c via shlex.quote; a quote in the command would break both.
        cmd = apt_upgrade_command(dist_upgrade=True)
        assert "'" not in cmd and '"' not in cmd
        assert shlex.split(shlex.quote(cmd)) == [cmd]
