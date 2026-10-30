# Runbook: move news.mstdn.ca's Ghost database from MariaDB to MySQL 8.4

Written 2026-10-30. Every command below changes production state and must be
run by a human; the auto-mode classifier blocks remote writes from Claude.

## Why

Ghost 6.73 added pattern-validated columns (`members_metafields.namespace` and
`.key`). On a MySQL-family database Ghost emits knex `checkRegex`, which is an
inline `CONSTRAINT name CHECK (col REGEXP ...)` in `CREATE TABLE` and
`ALTER TABLE ... ADD COLUMN`. MariaDB only accepts an unnamed column-level
`CHECK (...)`, so migration
`6.73/2026-10-20-21-48-55-store-metafield-namespaces.js` dies with a syntax
error. Ghost supports MySQL 8 only, and the same code path runs for any future
pattern column, so this will recur with every release.

## State found on 2026-10-30

| Item | Value |
| --- | --- |
| Guest | CT 202 `news`, TurnKey Linux on Debian 11 (bullseye), 1 GB RAM, 1 GB swap, 23 GB free on `/` |
| Ghost | `/opt/ghost`, CLI user `ghost_user` (home `/opt/ghost`), service user `ghost`, unit `ghost_news-mstdn-ca`, port 2370 |
| Versions on disk | 6.46.0, 6.64.0, 6.73.0; `current` points at 6.73.0 (broken), ghost-cli `previous-version` is 6.64.0 |
| Database | MariaDB 10.5.29, `ghost` DB, 98 tables, 22 MB, user `ghost`@`localhost` with ALL PRIVILEGES, `mysql_native_password` |
| Migrations table | last row is 6.64 (id 764). Nothing from 6.65 to 6.73 is recorded and no 6.65+ tables exist, so the DB is a clean 6.64 baseline |
| Ghost config | `database.connection.host` is `localhost`; `url` is `https://news.mstdn.ca` |
| Oracle apt repo for bullseye | frozen at `mysql-server 8.0.37` and `8.4.0` (2024). For bookworm it is `8.4.13`. |
| Debian 11 | LTS support ended 2026-08-31 |

Why the 6.73 update also left the site down: ghost-cli 1.34.0 ran its automatic
`ghost update --rollback`, but the rollback re-runs the doctor checks and the
file-permissions check failed on 451 files under `/opt/ghost/.cache/node/corepack/`
that corepack downloaded during the update. Fixing their mode first lets the
rollback through.

## Decision: where MySQL 8.4 runs

**Recommended: a new Debian 12 LXC dedicated to MySQL 8.4 LTS.** Reasons:
Oracle's Debian 11 builds are frozen at 8.4.0, the Ghost guest's OS is past
end of life, and the guest has 1 GB of RAM, which is tight for Ghost plus a
MySQL 8 server. Ghost then connects over the LAN.

Alternative (not recommended): install `mysql-community-server` 8.4.0 from
Oracle's bullseye repo on the Ghost guest itself, after stopping MariaDB. It
works, but it is a frozen 2024 build on an EOL OS. The steps are the same as
below with `host` left at `localhost`, `--bind-address` left alone, and the
user created as `'ghost'@'localhost'`.

Longer term the Ghost guest itself should be rebuilt on Debian 12. That is a
separate task.

## Phase 0: restore the site now (rollback to 6.64.0)

**Done 2026-10-30 04:45 MDT.** `ghost update --rollback --no-prompt` failed
here: ghost-cli runs `knex-migrator-rollback` through sudo, the tool's sudoers
grant covers only systemctl and nginx, and with prompts disabled ghost-cli
died on the password prompt. The database never left 6.64, so the manual
relink below was the whole rollback. Ghost returns 503 for a few seconds
while booting, then 301.

Run on the Ghost guest as root:

```bash
ssh -o IdentitiesOnly=yes -i ~/.ssh/mstdnca_maintenance root@10.0.4.118
```

```bash
mkdir -p /root/ghost-db-backups && mysqldump --single-transaction --routines --triggers --quick ghost | gzip > /root/ghost-db-backups/ghost-mariadb-$(date +%Y%m%d-%H%M%S).sql.gz && ls -la /root/ghost-db-backups/
```

```bash
find /opt/ghost/.cache -type f ! -perm 664 -exec chmod 664 {} +
```

```bash
su - ghost_user -c 'cd /opt/ghost && ghost update --rollback --no-prompt'
```

```bash
readlink /opt/ghost/current; systemctl is-active ghost_news-mstdn-ca; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:2370/
```

Expect `/opt/ghost/versions/6.64.0`, `active`, and `301` (Ghost redirects to
its https URL). Then check https://news.mstdn.ca in a browser.

If the rollback refuses for any other reason, the manual equivalent is:

```bash
ln -sfn /opt/ghost/versions/6.64.0 /opt/ghost/current && systemctl restart ghost_news-mstdn-ca && sleep 5 && systemctl is-active ghost_news-mstdn-ca
```

and then fix `active-version` in `/opt/ghost/.ghost-cli` to `6.64.0`.

## Phase 1: prepare

1. **Snapshot CT 202** on the PVE host (lola, 10.0.0.26) or in the Proxmox UI:

   ```bash
   pct snapshot 202 pre-mysql8-$(date +%Y%m%d)
   ```

2. **Create the database LXC** (Proxmox UI or `pct create`): Debian 12
   template, 2 GB RAM, 1 GB swap, 2 cores, 8 GB disk, static IP on the
   10.0.4.0/24 VLAN. This runbook uses `10.0.4.119`; substitute the address you
   pick everywhere below. Hostname `news-db`.

## Phase 2: install MySQL 8.4 LTS on the new LXC

Run on `news-db` as root:

```bash
apt-get update && apt-get install -y wget gnupg lsb-release
```

```bash
wget -O /tmp/mysql-apt-config.deb https://dev.mysql.com/get/mysql-apt-config_0.8.40-1_all.deb && DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/mysql-apt-config.deb
```

The package writes `/etc/apt/sources.list.d/mysql.list`. Make sure it selects
the LTS track, then install:

```bash
sed -i 's/ mysql-8\.0$/ mysql-8.4-lts/; s/ mysql-innovation$/ mysql-8.4-lts/' /etc/apt/sources.list.d/mysql.list && grep -v '^#' /etc/apt/sources.list.d/mysql.list
```

```bash
apt-get update && apt-get install -y mysql-server && mysql --version
```

Expect `8.4.13` or newer. Set a root password when the installer asks
(keep the default `caching_sha2_password`), or run `mysql_secure_installation`
afterwards.

Bind to the LAN address and keep memory modest:

```bash
cat > /etc/mysql/mysql.conf.d/news-db.cnf <<'EOF'
[mysqld]
bind-address = 10.0.4.119
character-set-server = utf8mb4
collation-server = utf8mb4_general_ci
innodb_buffer_pool_size = 256M
max_connections = 60
EOF
systemctl restart mysql && ss -ltn | grep 3306
```

Create the database and the Ghost user. The password is the one in
`/opt/ghost/config.production.json` on the Ghost guest (`database.connection.password`);
read it there with `python3 -c 'import json;print(json.load(open("/opt/ghost/config.production.json"))["database"]["connection"]["password"])'`
and paste it in place of `PASSWORD_FROM_CONFIG`:

```bash
mysql -u root -p -e "CREATE DATABASE ghost CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; CREATE USER 'ghost'@'10.0.4.118' IDENTIFIED BY 'PASSWORD_FROM_CONFIG'; GRANT ALL PRIVILEGES ON ghost.* TO 'ghost'@'10.0.4.118'; FLUSH PRIVILEGES;"
```

If the PVE firewall is enabled on either container, allow TCP 3306 from
10.0.4.118 to 10.0.4.119.

Test from the Ghost guest (MariaDB's client speaks caching_sha2_password):

```bash
mysql -h 10.0.4.119 -u ghost -p ghost -e 'SELECT VERSION();'
```

## Phase 3: trial import (site stays up)

On the Ghost guest, take a fresh dump and copy it over:

```bash
mysqldump --single-transaction --routines --triggers --quick ghost | gzip > /root/ghost-db-backups/ghost-trial.sql.gz && scp /root/ghost-db-backups/ghost-trial.sql.gz root@10.0.4.119:/root/
```

On `news-db`:

```bash
zcat /root/ghost-trial.sql.gz | grep -c 'M!999999'
```

MariaDB 10.5.29's mysqldump prefixes the file with a `/*M!999999 ...*/`
sandbox line; MySQL treats `/*M!` as a plain comment, so it is harmless. The
dump is otherwise MySQL-compatible: utf8mb4_general_ci, InnoDB, DYNAMIC rows,
no JSON columns, no MariaDB-only types.

```bash
zcat /root/ghost-trial.sql.gz | mysql -u root -p ghost && mysql -u root -p ghost -e 'SELECT COUNT(*) tables FROM information_schema.tables WHERE table_schema="ghost"; SELECT COUNT(*) posts FROM posts; SELECT COUNT(*) members FROM members; SELECT version, name FROM migrations ORDER BY id DESC LIMIT 1;'
```

Expect 98 tables, 18 posts, 37 members, and the last migration at version 6.64.
If the import prints any error, stop here and report it before continuing.

## Phase 4: switch Ghost over (short downtime)

On the Ghost guest:

```bash
su - ghost_user -c 'cd /opt/ghost && ghost stop'
```

```bash
mysqldump --single-transaction --routines --triggers --quick ghost | gzip > /root/ghost-db-backups/ghost-final.sql.gz && scp /root/ghost-db-backups/ghost-final.sql.gz root@10.0.4.119:/root/
```

On `news-db`, replace the trial import with the final one:

```bash
mysql -u root -p -e 'DROP DATABASE ghost; CREATE DATABASE ghost CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;' && zcat /root/ghost-final.sql.gz | mysql -u root -p ghost && mysql -u root -p ghost -e 'SELECT COUNT(*) posts FROM posts; SELECT COUNT(*) members FROM members;'
```

Back on the Ghost guest, point Ghost at the new server (only `host` changes):

```bash
cp /opt/ghost/config.production.json /root/config.production.json.pre-mysql8 && python3 - <<'EOF'
import json
p = "/opt/ghost/config.production.json"
c = json.load(open(p))
c["database"]["connection"]["host"] = "10.0.4.119"
json.dump(c, open(p, "w"), indent=2)
print(c["database"])
EOF
```

```bash
chown ghost_user:node /opt/ghost/config.production.json && su - ghost_user -c 'cd /opt/ghost && ghost start' && sleep 5 && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:2370/
```

Expect `301`. Check https://news.mstdn.ca, log in to the admin, open a post.

Now run the 6.73 upgrade, either through the lambnet tool (Apps, Ghost,
Upgrade) or by hand:

```bash
su - ghost_user -c 'cd /opt/ghost && ghost update --no-prompt'
```

Verify:

```bash
readlink /opt/ghost/current; systemctl is-active ghost_news-mstdn-ca; mysql -h 10.0.4.119 -u ghost -p ghost -e 'SELECT version, name FROM migrations ORDER BY id DESC LIMIT 3;'
```

Expect `6.73.0`, `active`, and 6.73 migration rows including
`2026-10-20-21-48-55-store-metafield-namespaces.js`.

## Phase 5: afterwards

On the Ghost guest, stop MariaDB but keep it installed for a week:

```bash
systemctl disable --now mariadb && systemctl is-active mariadb
```

Keep `/root/ghost-db-backups/` and the CT 202 snapshot until you are
satisfied, then delete the snapshot. The MariaDB client package stays: the
lambnet tool's upgrade pre-flights (`_ensure_ghost_db_privileges`,
`_check_ghost_db_engine`) read `database.connection.host` and skip their
local `mysql -u root` checks with an informational line when the host is
remote. The same change made the tool grant ghost-cli's
`knex-migrator-rollback` in sudoers and retry the rollback itself after a
failed update, so the Phase 0 manual relink should not be needed again.

Roll back at any point before Phase 5 by restoring
`/root/config.production.json.pre-mysql8` and running `ghost restart`; MariaDB
is untouched until Phase 5.

## Files

- Dumps: `/root/ghost-db-backups/` on the Ghost guest.
- Config backup: `/root/config.production.json.pre-mysql8`.
- Snapshot: `pre-mysql8-<date>` on CT 202.
