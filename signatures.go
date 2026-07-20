package main

import "strings"

// 已知内存马特征库（来源: 内存马应急排查手册 v2.0 一、已知内存马特征速查表）
// 说明: 这些是公开工具生成的默认/已知类名，命中即高度可疑。

// KnownMalwareClasses 已知恶意类名 -> 描述（工具/类型）
var KnownMalwareClasses = map[string]string{
	// 冰蝎 Behinder
	"EdwardsiidaeFilter":  "冰蝎 Filter 型内存马",
	"EdwardsiidaeServlet": "冰蝎 Servlet 型内存马",
	// 哥斯拉 Godzilla
	"PlasmodesmaFilter":          "哥斯拉 WebSocket Filter 型内存马",
	"Alginv8I58akMMnCA7T0A":      "哥斯拉载荷组件(随机类名变种)",
	"Eutropic":                   "哥斯拉载荷组件",
	"Poliorcetic":                "哥斯拉载荷组件",
	"LithoprintxCVIGnPE53kMja9q": "哥斯拉载荷组件",
	"Zygosporangium":             "哥斯拉载荷组件",
	// 代理隧道马
	"Prepupa": "代理隧道马(Runnable 代理线程)",
}

// SuspiciousInjectorKeywords 注入器磁盘特征关键词（JSP/源码中出现即可疑）
// 来源: 手册「注入器磁盘特征关键词」与第 9/10 条
var SuspiciousInjectorKeywords = []string{
	"defineClass",
	"Unsafe",
	"Base64.decode",
	"decodeBuffer",
	"Runtime.getRuntime",
	"ProcessBuilder",
	"ScriptEngine",
	"ClassLoader",
	"getFilterDefs",
	"addFilterDef",
	"StandardContext",
	"getServletContext",
}

// FrameworkFilterWhitelist 常见框架正常注册的 Filter/Servlet 白名单（防误判）
// 来源: 手册「二、常见框架Filter/Listener白名单」
var FrameworkFilterWhitelist = []string{
	// Spring
	"CharacterEncodingFilter", "hiddenHttpMethodFilter", "httpPutFormContentFilter",
	"requestContextFilter", "DelegatingFilterProxy", "FilterChainProxy",
	"SpringSecurityFilterChain", "MultipartFilter", "OrderedCharacterEncodingFilter",
	"OrderedRequestContextFilter", "OrderedFormContentFilter", "OrderedHiddenHttpMethodFilter",
	"WebMvcMetricsFilter", "ServerHttpObservationFilter", "FormContentFilter",
	// Shiro
	"SpringShiroFilter", "InvalidRequestFilter", "ShiroFilterFactoryBean",
	// Druid
	"DruidWebStatFilter", "DruidStatViewServlet", "WebStatFilter", "StatViewServlet",
	// Tomcat
	"CorsFilter", "CsrfPreventionFilter", "ExpiresFilter", "RemoteAddrFilter",
	"RemoteHostFilter", "RemoteIpFilter", "SetCharacterEncodingFilter", "WebdavFixFilter",
	"RequestDumperFilter", "FailedRequestFilter", "RestCsrfPreventionFilter",
	// Resin
	"ServletConfigImpl", "WebApp", "ConfigContext",
	// 其他常见
	"CasFilter", "XssFilter", "LogFilter", "UrlRewriteFilter", "Slf4jMDCFilter",
	"OpenEntityManagerInViewFilter", "OpenSessionInViewFilter",
}

// FrameworkStackPrefixes 框架自身类的包前缀（堆栈顶部全是这些 -> 大概率误报）
var FrameworkStackPrefixes = []string{
	"org.apache.catalina", "org.apache.coyote", "org.apache.tomcat",
	"org.springframework", "com.caucho", "org.apache.shiro",
	"org.eclipse.jetty", "io.undertow", "com.alibaba.druid",
	"org.apache.jasper", "javax.servlet", "jakarta.servlet",
}

// 常见业务端口（网络排查时排除）
var CommonBusinessPorts = map[int]bool{
	80: true, 443: true, 8080: true, 8443: true, 22: true,
	3306: true, 6379: true, 5432: true, 1521: true, 9200: true,
	8005: true, 8009: true, 8000: true, 8081: true, 2181: true,
	27017: true, 11211: true, 53: true,
}

// 国产化 OA / 常见中间件根目录线索（用于自动定位）
var AppRootHints = []string{
	"/opt/tomcat", "/usr/local/tomcat", "/opt/apache-tomcat",
	"/opt/seeyon", "/usr/local/seeyon", // 致远
	"/opt/weaver", "/usr/local/weaver", // 泛微
	"/opt/landray", "/usr/local/landray", // 蓝凌
	"/srv", "/opt", "/usr/local", "/app", "/data", "/home",
	"/var/lib/tomcat", "/var/lib/tomcat9", "/var/lib/tomcat8",
}

// matchKnownMalware 判断类名/字符串是否命中已知恶意特征，返回描述。
func matchKnownMalware(s string) (string, bool) {
	for cls, desc := range KnownMalwareClasses {
		if strings.Contains(s, cls) {
			return desc, true
		}
	}
	return "", false
}

// isWhitelistedFilter 判断（简单类名或全限定名）是否属于框架白名单。
func isWhitelistedFilter(name string) bool {
	simple := name
	if i := strings.LastIndex(simple, "."); i >= 0 {
		simple = simple[i+1:]
	}
	for _, w := range FrameworkWhitelistSet() {
		if strings.EqualFold(simple, w) {
			return true
		}
	}
	// 框架包前缀也视为可信
	for _, p := range FrameworkStackPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var frameworkWhitelistCache []string

func FrameworkWhitelistSet() []string {
	if frameworkWhitelistCache == nil {
		frameworkWhitelistCache = FrameworkFilterWhitelist
	}
	return frameworkWhitelistCache
}

// looksSuspiciousClassName 通用启发式: 无包名 / Lambda 伪装 / 生僻词 + 组件后缀。
func looksSuspiciousClassName(fqcn string) (reason string, suspicious bool) {
	name := fqcn
	pkg := ""
	if i := strings.LastIndex(fqcn, "."); i >= 0 {
		pkg = fqcn[:i]
		name = fqcn[i+1:]
	}
	if isWhitelistedFilter(fqcn) {
		return "", false
	}
	if strings.Contains(fqcn, "$$Lambda$") {
		return "$$Lambda$ 结尾，疑似 Lambda 表达式伪装的 Filter", true
	}
	isComponent := strings.HasSuffix(name, "Filter") || strings.HasSuffix(name, "Servlet") ||
		strings.HasSuffix(name, "Listener") || strings.HasSuffix(name, "Valve")
	if !isComponent {
		return "", false
	}
	// 无包名的组件类高度可疑
	if pkg == "" {
		return "无包名的 " + componentKind(name) + "，动态注册型内存马典型特征", true
	}
	// 包名异常（顶层单段且非常见）
	if !strings.Contains(pkg, ".") && !isCommonTopPkg(pkg) {
		return "包名异常(" + pkg + ")的 " + componentKind(name), true
	}
	return "", false
}

func componentKind(name string) string {
	switch {
	case strings.HasSuffix(name, "Filter"):
		return "Filter"
	case strings.HasSuffix(name, "Servlet"):
		return "Servlet"
	case strings.HasSuffix(name, "Listener"):
		return "Listener"
	case strings.HasSuffix(name, "Valve"):
		return "Valve"
	}
	return "组件"
}

func isCommonTopPkg(pkg string) bool {
	switch pkg {
	case "java", "javax", "jakarta", "sun", "com", "org", "net", "cn", "io":
		return true
	}
	return false
}
