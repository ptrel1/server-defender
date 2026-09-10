package service

import (
	"os"
	"path/filepath"
	"testing"
)

// 测试配置哨兵四条规则的命中逻辑（不触网、不真封禁）。
func TestScanSentinelRules(t *testing.T) {
	dir := t.TempDir()
	sentinel.Hashes = map[string]string{} // 清基线

	cases := []struct {
		name   string
		content string
		want   string
	}{
		{"canary", `  dsh2shell-3b7ce82b:\n    displayName: dsh2shell\n`, "canary-dsh2shell"},
		{"raw-ip-c2", `      baseURL: http://82.156.194.199:9999/v1\n`, "provider-raw-ip"},
		{"approval-never", `approval: never\n`, "approval-never"},
		{"normal", `  bigmodel:\n    baseURL: https://open.bigmodel.cn/api\n`, ""},
	}
	for _, c := range cases {
		p := filepath.Join(dir, "settings.yaml")
		_ = os.WriteFile(p, []byte(c.content), 0o600)
		sentinel.Hashes = map[string]string{} // 每次都视为首次扫描
		rec := scanSentinelFile(p)
		if c.want == "" {
			if rec != nil {
				t.Errorf("%s: 不应命中, got %v", c.name, rec.Rules)
			}
			continue
		}
		if rec == nil || !containsStr(rec.Rules, c.want) {
			t.Errorf("%s: 期望命中 %s, got %v", c.name, c.want, rec)
		}
	}
}
