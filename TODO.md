# Opsfix TODO

## MVP Blocker (önce bunlar)

- [ ] `mcp-server/server.go` — response formatı kırık: `PendingApproval`, `PreFlight`, `Risk` Claude'a iletilmiyor; sadece `Output` dönüyor. Approval flow sessiz çalışmaz.
- [ ] `.claude/mcp.json` oluştur — Claude Code opsfix'i bulamazsa hiçbir şey çalışmaz
- [ ] Gerçek `config.yaml` + `policy.yaml` yaz (sunucu IP, user, key_path, stack)
- [ ] Audit log dizini: `/var/log/opsfix/` create + yazma izni

---

## Güvenlik & Doğruluk

- [ ] **Probe → Execute adaptasyonu**: `supervisorctl` yoksa `systemctl` üzerinden queue restart dene. `Probe()` sonucu şu an hiçbir Execute tarafından kullanılmıyor.
- [ ] **Queue verify düzelt**: `laravel_queue_restart` Verify şu an her zaman `Success: true` döndürüyor. Worker gerçekten kalktı mı sorgulanmalı (`supervisorctl status worker-name`).
- [ ] **Rollback false-positive**: Deploy sırasında DB bağlantısı yoksa migrate başlamadan hata verir — rollback gerekmez ama şu an tetikleniyor. Rollback kararını migrate adımının başarısına göre ver.
- [ ] **known_hosts enforcement**: Production build tag'ında `InsecureIgnoreHostKey` derleme hatası vermeli (FSD §5.2).
- [ ] **Bastion/jump host SSH dial**: `pool.go`'da `BastionConfig` var ama dial implementasyonu eksik.
- [ ] `OPSFIX_AUDIT_HMAC_KEY` olmadan mutating op'ları uyarı değil blocker yap (opsiyonel, production-only flag ile).

---

## Semantic Validation

Tek dokunulan yer: `adapter/community/laravel/laravel.go` → `PreFlight()`.
Diğer katmanlar hazır (`exec.ReadFile()`, `Blocker` field, `CurrentState` map).

### Deploy PreFlight zenginleştirmesi

- [ ] **Commit diff**: `git log --oneline HEAD..origin/<branch>` → `incoming_commits` alanına ekle
- [ ] **Dosya değişim özeti**: `git diff --stat HEAD..origin/<branch>` → `changed_files` alanına ekle
- [ ] **Pending migration listesi**: `php artisan migrate:status` → `pending_migrations` alanına ekle
- [ ] **Migration içerik tarama**: Bekleyen migration dosyalarını `exec.ReadFile()` ile oku, `containsDestructive()` ile tara:
  ```
  DROP TABLE, TRUNCATE TABLE, Schema::drop(, $table->dropColumn → Blocker set et
  ```
- [ ] **Composer script audit**: `exec.ReadFile(appPath+"/composer.json")` → `post-install-cmd` script'lerini parse edip `CurrentState["composer_scripts"]` olarak göster

### Örnek Claude çıktısı (safe deploy)
```json
{
  "incoming_commits": ["a1b2c3 Fix user auth", "d4e5f6 Add payment table"],
  "changed_files": ["app/Models/Payment.php (+45)", "database/migrations/2026_add_payments.php (+30)"],
  "pending_migrations": ["2026_add_payments_table"],
  "migration_risk": "new table only — safe",
  "composer_scripts": ["php artisan key:generate"]
}
```

### Örnek Claude çıktısı (blocker)
```json
{
  "blocker": "migration contains DROP TABLE: users_backup",
  "incoming_commits": ["x9y8z7 Cleanup old tables"],
  "pending_migrations": ["2026_drop_users_backup"]
}
```

### Rollback semantic check
- [ ] `attemptRollback()` içinde `git log --oneline <sha>..HEAD` çalıştır → "X commit geri alınacak, şu dosyalar etkilenecek" logu yaz, sonra checkout et

---

## Gözlemlenebilirlik

- [ ] Prometheus metrics — Unix socket `/run/opsfix/metrics.sock` üzerinden
- [ ] Self-health endpoint — Unix socket `/run/opsfix/health.sock`
- [ ] SIGHUP ile config + policy hot-reload
- [ ] `opsfix verify-audit` CLI subcommand — HMAC zinciri doğrulama

---

## Testler

- [ ] `internal/policy/engine_test.go` — block rules, risk threshold, condition matching, default-deny
- [ ] `internal/secret/redactor_test.go` — builtin patterns, literal redaction
- [ ] `internal/ssh/keymgr_test.go` — 0600 ok, 0644 fail, 0400 ok, 0640 fail
- [ ] `internal/audit/logger_test.go` — HMAC chain verify, tamper detection, missing key degrade
- [ ] `internal/ratelimit/limiter_test.go` — burst allowed, steady rate enforced, per-server isolation
- [ ] `internal/ssh/executor_test.go` — allowlist check, path traversal guard, injection strings

---

## Nice-to-have

- [ ] `scan_server` comprehensive tool geri ekle — tek çağrıyla sunucunun tam resmini döndür
- [ ] `opsfix rotate-key` CLI subcommand
- [ ] Docker image (`FROM scratch` multi-stage)
- [ ] `scripts/setup-agent-user.sh` — ai-agent user + sudoers setup
- [ ] Adapter başına manifest.yaml allowlist (şu an builtinAllowlist hardcoded)
- [ ] Binary signing (cosign + Rekor)
