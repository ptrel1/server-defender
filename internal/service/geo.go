package service

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// GeoInfo 与 Python netmon/geo 返回结构对齐。
type GeoInfo struct {
	IP       string `json:"ip"`
	IsCN     bool   `json:"is_cn"`
	Country  string `json:"country"`
	Location string `json:"location"`
	ISP      string `json:"isp"`
}

var (
	geoCacheFile = filepath.Join(dataDir(), "geo_cache.json")
	geoMu        sync.Mutex
	geoClient    = &http.Client{Timeout: 3 * time.Second}
)

// dataDir 返回运行时数据目录。
// 标准化：优先取环境变量 DEFENDER_DATA_DIR 覆盖；否则默认取「运行工作目录/data」
// （即 postsup bin/ 胶囊顶层 data/，不再跟随二进制所在位置，消除 bin/data vs data/ 二义性）。
// 注：supervisor 已把 directory 指向 app 根目录，故默认落到 apps/<app>/data。
func dataDir() string {
	if d := os.Getenv("DEFENDER_DATA_DIR"); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		return "data"
	}
	return filepath.Join(wd, "data")
}

// isPrivateOrLoopback 判断是否为私网/回环/保留地址。
func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	// 链路本地 169.254.0.0/16 与 fe80::/10
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 169 && v4[1] == 254
	}
	if v6 := ip.To16(); v6 != nil {
		return v6[0] == 0xfe && (v6[1]&0xc0) == 0x80
	}
	return false
}

// QueryGeo 解析 IP 归属地：内存缓存 → 磁盘缓存 → 远程多源降级。
func QueryGeo(ip string) GeoInfo {
	if isPrivateOrLoopback(ip) {
		return GeoInfo{IP: ip, IsCN: true, Country: "局域网/回环", Location: "本地", ISP: "Local"}
	}
	if e, ok := geoMem.Load(ip); ok {
		if en := e.(geoEntry); time.Now().Before(en.exp) {
			return en.info
		}
	}
	info := queryGeoDisk(ip)
	geoMem.Store(ip, geoEntry{info: info, exp: time.Now().Add(time.Duration(Conf().GeoMemTTLH) * time.Hour)})
	return info
}

// QueryGeoFast 非阻塞取归属地（面板展示用）：命中缓存直接返回；
// 未命中返回 false 并触发后台预取，下次刷新即可见。
func QueryGeoFast(ip string) (string, bool) {
	if isPrivateOrLoopback(ip) {
		return "本地", true
	}
	if e, ok := geoMem.Load(ip); ok {
		if en := e.(geoEntry); time.Now().Before(en.exp) {
			return en.info.Location, true
		}
	}
	go func() { _ = QueryGeo(ip) }()
	return "", false
}

type geoEntry struct {
	info GeoInfo
	exp  time.Time
}

var geoMem sync.Map

func queryGeoDisk(ip string) GeoInfo {
	// 读共享的单例缓存
	info, ok := readGeoCache(ip)
	if ok {
		return info
	}
	result := queryGeoRemote(ip)
	saveGeoCache(ip, result)
	return result
}

func readGeoCache(ip string) (GeoInfo, bool) {
	geoMu.Lock()
	defer geoMu.Unlock()
	data, err := os.ReadFile(geoCacheFile)
	if err != nil {
		return GeoInfo{}, false
	}
	var cache map[string]GeoInfo
	if json.Unmarshal(data, &cache) != nil {
		return GeoInfo{}, false
	}
	g, ok := cache[ip]
	return g, ok
}

func saveGeoCache(ip string, g GeoInfo) {
	geoMu.Lock()
	defer geoMu.Unlock()
	cache := map[string]GeoInfo{}
	if data, err := os.ReadFile(geoCacheFile); err == nil {
		_ = json.Unmarshal(data, &cache)
	}
	cache[ip] = g
	if b, err := json.Marshal(cache); err == nil {
		_ = os.WriteFile(geoCacheFile, b, 0o644)
	}
}

// queryGeoRemote 依次尝试多个归属地接口，全部失败时保守判定为中国(不误伤)。
func queryGeoRemote(ip string) GeoInfo {
	// 1. pconline (whois.pconline.com.cn, GBK 编码, 国内快)
	if txt, err := httpGet("https://whois.pconline.com.cn/ipJson.jsp?ip=" + ip + "&json=true"); err == nil {
		if g, ok := parsePconline(ip, txt); ok {
			return g
		}
	}
	// 2. ip-api.com (中文)
	if txt, err := httpGet("http://ip-api.com/json/" + ip + "?lang=zh-CN"); err == nil {
		if g, ok := parseIPAPI(ip, txt); ok {
			return g
		}
	}
	// 3. 兜底：fail-close——查询失败按未知境外处理（封禁场景宁严勿漏；白名单IP在调用方已提前豁免）
	return GeoInfo{IP: ip, IsCN: false, Country: "未知", Location: "归属地未识别", ISP: ""}
}

func httpGet(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "curl/7.68.0")
	resp, err := geoClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// func parsePconline 解析 GBK 编码的 pconline JSON。
func parsePconline(ip, raw string) (GeoInfo, bool) {
	// 接口返回 GBK；此处按字节替换常见编码后再解析（简化处理：若含非法 UTF-8 则做拉丁回退）
	var d struct {
		ProCode string `json:"proCode"`
		Pro     string `json:"pro"`
		City    string `json:"city"`
		Addr    string `json:"addr"`
	}
	decoded := gbkToUTF8([]byte(raw))
	if json.Unmarshal([]byte(decoded), &d) != nil {
		return GeoInfo{}, false
	}
	pro := strings.TrimSpace(d.Pro)
	city := strings.TrimSpace(d.City)
	addr := strings.TrimSpace(d.Addr)
	if d.ProCode != "" && d.ProCode != "999999" {
		loc := strings.TrimSpace(pro + " " + city)
		if loc == "" {
			loc = "中国"
		}
		return GeoInfo{IP: ip, IsCN: true, Country: "中国", Location: loc, ISP: addr}, true
	}
	return GeoInfo{IP: ip, IsCN: false, Country: "境外", Location: normalizeForeignRegion(addr), ISP: addr}, true
}

// normalizeForeignRegion 将境外归属地压缩为「国家（一级行政区）」粒度。
// pconline 境外格式杂糅 ISP/城市/机构名，导致聚合 chip 粒度不齐（如“瑞士洛桑联邦理工学院”）。
// 这里提取已知国家/地区名作为归一化结果，ISP 细节保留在 ISP 字段供表格 hover。
func normalizeForeignRegion(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "未知"
	}
	// 常见国家/地区词表（长词优先匹配）
	countries := []string{
		"美国", "英国", "法国", "德国", "意大利", "西班牙", "荷兰", "比利时", "瑞典", "瑞士",
		"挪威", "芬兰", "丹麦", "波兰", "奥地利", "希腊", "葡萄牙", "爱尔兰", "捷克", "匈牙利",
		"罗马尼亚", "保加利亚", "俄罗斯", "乌克兰", "土耳其", "以色列", "阿联酋", "沙特阿拉伯",
		"印度", "日本", "韩国", "越南", "泰国", "新加坡", "马来西亚", "印度尼西亚", "菲律宾",
		"巴西", "阿根廷", "智利", "哥伦比亚", "墨西哥", "加拿大", "澳大利亚", "新西兰",
		"南非", "埃及", "尼日利亚", "蒙古", "哈萨克斯坦", "亚太地区",
	}
	for _, c := range countries {
		if strings.Contains(s, c) {
			// 抓到国家后再尝试带上紧随的省州信息（如"美国得克萨斯州"），限制总长
			idx := strings.Index(s, c) + len([]rune(c))
			runes := []rune(s)
			tail := ""
			for j := idx; j < len(runes) && len([]rune(tail)) < 5; j++ {
				r := runes[j]
				if r == ' ' || r == '(' || isASCII(r) {
					break
				}
				tail += string(r)
			}
			if tail != "" && strings.HasSuffix(tail, "州") || tail == "地区" || strings.HasSuffix(tail, "省") {
				return c + tail
			}
			return c
		}
	}
	// 未识别的境外地名：截断到 8 字符，避免机构名撑爆聚合条
	runes := []rune(s)
	if len(runes) > 8 {
		return string(runes[:8])
	}
	return s
}

func isASCII(r rune) bool { return r < 128 }

func parseIPAPI(ip, raw string) (GeoInfo, bool) {
	var d struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if json.Unmarshal([]byte(raw), &d) != nil || d.Status != "success" {
		return GeoInfo{}, false
	}
	isCN := d.CountryCode == "CN" || d.CountryCode == "HK" || d.CountryCode == "MO" || d.CountryCode == "TW"
	loc := strings.TrimSpace(d.Country)
	if loc == "" {
		loc = strings.TrimSpace(d.Country + " " + d.RegionName + " " + d.City)
	}
	return GeoInfo{IP: ip, IsCN: isCN, Country: d.Country, Location: loc, ISP: d.ISP}, true
}

// gbkToUTF8 真正的 GBK→UTF-8 转换（x/text GBK 解码器）。
// pconline 归属地接口返回 GBK 编码；若输入已是合法 UTF-8 则原样返回避免二次损坏。
// 解码失败时回退为"替换非法字节"（不 crash，仅个别字符丢失，不影响 is_cn 判定）。
func gbkToUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	decoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), b)
	if err != nil {
		return strings.ToValidUTF8(string(b), "�")
	}
	return string(decoded)
}
