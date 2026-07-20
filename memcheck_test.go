package main

import (
	"net"
	"testing"
)

func TestMatchKnownMalware(t *testing.T) {
	cases := map[string]bool{
		"org.apache.PlasmodesmaFilter": true,
		"EdwardsiidaeServlet":          true,
		"com.evil.Zygosporangium":      true,
		"Prepupa":                      true,
		"org.springframework.web.filter.CharacterEncodingFilter": false,
		"com.business.MyFilter":                                  false,
	}
	for in, want := range cases {
		_, got := matchKnownMalware(in)
		if got != want {
			t.Errorf("matchKnownMalware(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLooksSuspiciousClassName(t *testing.T) {
	suspicious := []string{
		"CmdFilter",                       // 无包名 Filter
		"evil.ShellServlet",               // 单段异常包名
		"com.x.Foo$$Lambda$12/0x00Filter", // Lambda 伪装
	}
	for _, s := range suspicious {
		if _, ok := looksSuspiciousClassName(s); !ok {
			t.Errorf("looksSuspiciousClassName(%q) = false, want true", s)
		}
	}
	safe := []string{
		"org.springframework.web.filter.CharacterEncodingFilter",
		"org.apache.catalina.filters.CorsFilter",
		"com.alibaba.druid.support.http.WebStatFilter",
		"com.business.service.UserService", // 非组件后缀
	}
	for _, s := range safe {
		if reason, ok := looksSuspiciousClassName(s); ok {
			t.Errorf("looksSuspiciousClassName(%q) = true (%s), want false", s, reason)
		}
	}
}

func TestIsWhitelistedFilter(t *testing.T) {
	if !isWhitelistedFilter("CorsFilter") {
		t.Error("CorsFilter should be whitelisted (simple name)")
	}
	if !isWhitelistedFilter("org.springframework.boot.web.servlet.filter.OrderedFormContentFilter") {
		t.Error("spring prefix should be whitelisted")
	}
	if isWhitelistedFilter("com.evil.PlasmodesmaFilter") {
		t.Error("malware class must not be whitelisted")
	}
}

func TestLooksRandomFileName(t *testing.T) {
	random := []string{"aB3xK.jsp", "Zk9Qp2.jspx", "xY7mN.jsp"}
	for _, n := range random {
		if !looksRandomFileName(n) {
			t.Errorf("looksRandomFileName(%q) = false, want true", n)
		}
	}
	normal := []string{"index.jsp", "login.jsp", "user_list.jsp", "main.jsp", "error.jsp"}
	for _, n := range normal {
		if looksRandomFileName(n) {
			t.Errorf("looksRandomFileName(%q) = true, want false", n)
		}
	}
}

func TestParseHexAddr(t *testing.T) {
	// 0100007F:1F90 => 127.0.0.1:8080 (小端)
	ip, port, ok := parseHexAddr("0100007F:1F90")
	if !ok || !ip.Equal(net.ParseIP("127.0.0.1")) || port != 8080 {
		t.Errorf("parseHexAddr IPv4 = %v:%d ok=%v, want 127.0.0.1:8080", ip, port, ok)
	}
	// 0.0.0.0:80  => 00000000:0050
	ip2, port2, ok2 := parseHexAddr("00000000:0050")
	if !ok2 || !ip2.Equal(net.ParseIP("0.0.0.0")) || port2 != 80 {
		t.Errorf("parseHexAddr = %v:%d, want 0.0.0.0:80", ip2, port2)
	}
}

func TestScanFileKeywordsAndFirstMatch(t *testing.T) {
	if kw, ok := firstMatch("run /dev/tcp/1.1.1.1/4444", cronStrongKeywords); !ok || kw != "/dev/tcp/" {
		t.Errorf("firstMatch strong = %q ok=%v", kw, ok)
	}
	if _, ok := firstMatch("eval $(apt-config shell x)", cronStrongKeywords); ok {
		t.Error("legit apt-config eval must not match strong cron keywords")
	}
}
