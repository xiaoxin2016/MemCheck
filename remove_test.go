package main

import (
	"encoding/json"
	"testing"
)

func TestLooksLikeClassName(t *testing.T) {
	valid := []string{"com.evil.EvilServlet", "CmdFilter", "com.x.Foo$Bar", "_x"}
	for _, s := range valid {
		if !looksLikeClassName(s) {
			t.Errorf("looksLikeClassName(%q) = false, want true", s)
		}
	}
	// 内存马常把 servletClass 伪造成 URL 等非类名字符串
	invalid := []string{"/favicondemo.ico", "", "/", "a b", "http://x/y", "中文类"}
	for _, s := range invalid {
		if looksLikeClassName(s) {
			t.Errorf("looksLikeClassName(%q) = true, want false", s)
		}
	}
}

// 复现真机场景：servletClass 被伪造成 URL，真实类从运行实例取得。
func TestClassifyForgedServletClass(t *testing.T) {
	it := invItem{
		Kind: "servlet", Name: "/favicondemo.ico",
		Class: "com.evil.EvilServlet", Declared: "/favicondemo.ico",
		CodeSource: "", Resolved: true,
	}
	sev, reason, cand := classifyComponent(it)
	if !cand || sev != SevCritical {
		t.Errorf("伪造 servletClass 应判严重候选，得到 sev=%v cand=%v reason=%q", sev, cand, reason)
	}
}

// 未解析到类且非框架组件：不得被静默放过（此前的漏检点）。
func TestClassifyUnresolvedNotSilentlyDropped(t *testing.T) {
	it := invItem{Kind: "servlet", Name: "x", Declared: "com.unknown.Thing", Resolved: false}
	sev, _, cand := classifyComponent(it)
	if !cand || sev < SevHigh {
		t.Errorf("未解析的非框架组件应成为候选(>=High)，得到 sev=%v cand=%v", sev, cand)
	}
	// 框架组件未实例化则不应误报
	fw := invItem{Kind: "filter", Declared: "org.springframework.web.filter.CharacterEncodingFilter", Resolved: false}
	if _, _, c := classifyComponent(fw); c {
		t.Error("框架组件未实例化不应列为候选")
	}
}

// 声明类名与实际实例类名不符 → 伪装。
func TestClassifyDeclaredActualMismatch(t *testing.T) {
	it := invItem{
		Kind: "filter", Name: "f",
		Declared: "org.springframework.web.filter.CharacterEncodingFilter",
		Class:    "com.evil.Backdoor", CodeSource: "file:/app.jar", Resolved: true,
	}
	if _, _, cand := classifyComponent(it); !cand {
		t.Error("声明类名与实际实例类不符应判为可疑")
	}
}

// Valve 型内存马（此前完全未枚举）。
func TestClassifyInjectedValve(t *testing.T) {
	evil := invItem{Kind: "valve", Class: "com.evil.EvilValve", CodeSource: "", Resolved: true}
	if _, _, cand := classifyComponent(evil); !cand {
		t.Error("codeSource 为空的 Valve 应判为可疑")
	}
	ok := invItem{Kind: "valve", Class: "org.apache.catalina.core.StandardContextValve",
		CodeSource: "file:/tomcat.jar", Resolved: true}
	if _, _, cand := classifyComponent(ok); cand {
		t.Error("Tomcat 自带 Valve 不应误报")
	}
}

func TestInvItemRefFallback(t *testing.T) {
	// 类名伪造时应回退到注册名，保证卸载能定位
	if got := (invItem{Name: "/x.ico", Declared: "/x.ico"}).ref(); got != "/x.ico" {
		t.Errorf("ref() = %q", got)
	}
	if got := (invItem{Name: "n", Declared: "d", Class: "c"}).ref(); got != "c" {
		t.Errorf("ref() 应优先真实类名，得到 %q", got)
	}
}

func TestClassifyComponent(t *testing.T) {
	cases := []struct {
		name      string
		it        invItem
		candidate bool
	}{
		{"内存注入(codeSource空)", invItem{Kind: "filter", Name: "evil", Class: "com.company.web.InjectedFilter", CodeSource: "", Resolved: true}, true},
		{"正常应用过滤器(有codeSource)", invItem{Kind: "filter", Name: "auth", Class: "com.company.web.AuthFilter", CodeSource: "file:/app/app.jar", Resolved: true}, false},
		{"框架过滤器", invItem{Kind: "filter", Name: "enc", Class: "org.springframework.web.filter.CharacterEncodingFilter", CodeSource: "", Resolved: true}, false},
		{"已知内存马", invItem{Kind: "filter", Name: "x", Class: "org.apache.PlasmodesmaFilter", CodeSource: "file:/x.jar", Resolved: true}, true},
		{"codeSource指向JSP", invItem{Kind: "filter", Name: "y", Class: "com.app.ShellFilter", CodeSource: "file:/webapps/ROOT/shell.jsp", Resolved: true}, true},
		{"无包名组件", invItem{Kind: "filter", Name: "z", Class: "CmdFilter", CodeSource: "file:/x.jar", Resolved: true}, true},
	}
	for _, c := range cases {
		_, reason, cand := classifyComponent(c.it)
		if cand != c.candidate {
			t.Errorf("%s: classifyComponent candidate=%v want %v (reason=%q)", c.name, cand, c.candidate, reason)
		}
	}
}

func TestTrustedLambdaNotSuspicious(t *testing.T) {
	// JDK 内部 lambda 不应被判为可疑（修复 sun.misc.ObjectInputFilter$Config$$Lambda 误报）
	jdk := []string{
		"sun.misc.ObjectInputFilter$Config$$Lambda$500/767648390",
		"java.util.stream.Collectors$$Lambda$1/0x0000",
		"org.springframework.boot.web.filter.OrderedFormContentFilter$$Lambda$2",
	}
	for _, s := range jdk {
		if _, ok := looksSuspiciousClassName(s); ok {
			t.Errorf("looksSuspiciousClassName(%q) = true, want false (JDK/framework internal)", s)
		}
	}
	// 但业务包下的 Lambda 伪装 Filter 仍应可疑
	if _, ok := looksSuspiciousClassName("com.evil.Shell$$Lambda$1"); !ok {
		// looksSuspiciousClassName 对 $$Lambda$ 直接判可疑（非受信包）
		t.Errorf("com.evil lambda should be suspicious")
	}
}

func TestParseAgentResult(t *testing.T) {
	// 与 MemCheckAgent 实际回写格式一致的样本
	sample := `{"contextsFound":1,"action":"remove","results":[` +
		`{"class":"PlasmodesmaFilter","status":"removed","registeredAs":"filter:evilFilter -> org.apache.PlasmodesmaFilter","detail":"已移除 FilterDef，FilterMap x1，已释放 filterConfig"},` +
		`{"class":"Prepupa","status":"not_found","registeredAs":"","detail":"未在当前 JVM 中发现该类"}]}`
	var res agentResult
	if err := json.Unmarshal([]byte(sample), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.ContextsFound != 1 || res.Action != "remove" || len(res.Results) != 2 {
		t.Fatalf("unexpected parse: %+v", res)
	}
	if res.Results[0].Status != "removed" || res.Results[0].Class != "PlasmodesmaFilter" {
		t.Errorf("item0 wrong: %+v", res.Results[0])
	}
	if res.Results[1].Status != "not_found" {
		t.Errorf("item1 wrong: %+v", res.Results[1])
	}
}

func TestExtractJSON(t *testing.T) {
	in := "[MemCheckAgent] {\"contextsFound\":2,\"results\":[]}\nreturn code: 0"
	got := extractJSON(in)
	want := `{"contextsFound":2,"results":[]}`
	if got != want {
		t.Errorf("extractJSON = %q, want %q", got, want)
	}
	if extractJSON("no json here") != "" {
		t.Error("expected empty for no-json input")
	}
}

func TestDedupStrings(t *testing.T) {
	got := dedupStrings([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("dedupStrings len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedupStrings[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestKnownMalwareNamesCoversSignatures(t *testing.T) {
	names := knownMalwareNames()
	if len(names) != len(KnownMalwareClasses) {
		t.Fatalf("knownMalwareNames len = %d, want %d", len(names), len(KnownMalwareClasses))
	}
	// 每个名字都应能被 matchKnownMalware 识别
	for _, n := range names {
		if _, ok := matchKnownMalware(n); !ok {
			t.Errorf("known name %q not matched by matchKnownMalware", n)
		}
	}
}

func TestAgentJarEmbedded(t *testing.T) {
	// 内嵌的 agent.jar 必须存在且看起来是个 zip(jar)（PK 魔数）
	if len(agentJar) < 200 {
		t.Fatalf("embedded agent.jar too small: %d bytes", len(agentJar))
	}
	if agentJar[0] != 'P' || agentJar[1] != 'K' {
		t.Errorf("embedded agent.jar missing PK zip magic: %x %x", agentJar[0], agentJar[1])
	}
}
