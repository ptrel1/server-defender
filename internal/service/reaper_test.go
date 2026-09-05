package service

import "testing"

// 遍历参数豁免：合法全盘扫描 grep -R 等不应被 reaper 收割。
func TestIsTraversalTask_ExemptLongScans(t *testing.T) {
cases := []struct {
args []string
want bool
}{
{[]string{"-R", "keyword", "/var/log"}, true},        // 全盘递归扫描 -> 豁免
{[]string{"-r", "--include=*.go", "foo", "/main"}, true}, // 带模式遍历 -> 豁免
{[]string{"-n", "pattern", "file.txt"}, false},       // 普通单文件 grep -> 不算遍历
{[]string{"/usr/bin/something"}, true},               // 带绝对路径 -> 豁免
{[]string{"xargs", "echo"}, false},                   // 非遍历
}
for _, c := range cases {
if got := isTraversalTask(c.args); got != c.want {
t.Errorf("isTraversalTask(%v) = %v, want %v", c.args, got, c.want)
}
}
}
