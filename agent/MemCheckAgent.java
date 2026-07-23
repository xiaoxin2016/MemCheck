import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * MemCheckAgent —— 由 MemCheck 通过 JVM attach 加载的内存马枚举/卸载 agent。
 *
 * 设计要点：
 *   - action=list  ：枚举所有 Tomcat 上下文中已注册的 Filter/Servlet/Listener（名称+类名），
 *                     不做任何判断，交由 Go 侧用统一启发式判定是否可疑。这样即使内存马类名未知，
 *                     也能通过“它出现在过滤器链里”被发现（应对反序列化一次性注入的内存马）。
 *   - action=remove：按传入的类名/名称匹配，移除对应注册项。
 *
 * 上下文发现：遍历 Instrumentation.getAllLoadedClasses() 收集所有 ClassLoader，找出 WebappClassLoaderBase
 * （含 Spring Boot 内嵌 Tomcat 的 TomcatEmbeddedWebappClassLoader），经 getResources().getContext()
 * 拿到 StandardContext——不依赖是否有活跃请求线程，兼容独立 Tomcat 与 Spring Boot 内嵌 Tomcat。
 *
 * 全程反射操作、编译期不依赖 servlet/Tomcat；任何一步失败都被捕获且不影响其它项。
 *
 * agentArgs: action=list|remove;result=/tmp/xx.json;classes=a,b,c
 */
public class MemCheckAgent {

    public static void agentmain(String agentArgs, Instrumentation inst) {
        Map<String, String> opts = parseArgs(agentArgs);
        String action = opts.getOrDefault("action", "list");
        String resultPath = opts.get("result");
        List<String> targets = splitList(opts.get("classes"));

        StringBuilder json = new StringBuilder();
        String err = null;
        int contextsFound = 0;
        List<String> inventory = new ArrayList<>();
        List<String> results = new ArrayList<>();

        try {
            Set<Object> contexts = findStandardContexts(inst);
            contextsFound = contexts.size();

            if ("remove".equalsIgnoreCase(action)) {
                Map<String, String> handled = new LinkedHashMap<>();
                for (Object ctx : contexts) {
                    handleFilters(ctx, targets, handled, results);
                    handleServlets(ctx, targets, handled, results);
                    handleListeners(ctx, targets, handled, results);
                }
                Map<String, Boolean> loaded = loadedClasses(inst, targets);
                for (String t : targets) {
                    if (!handled.containsKey(t)) {
                        boolean isLoaded = Boolean.TRUE.equals(loaded.get(t));
                        results.add(resultItem(t, isLoaded ? "loaded_not_registered" : "not_found", "",
                                isLoaded ? "类已加载但未在注册表中找到；重启可清除，务必排查磁盘注入器/漏洞入口"
                                         : "未在当前 JVM 中发现该类"));
                    }
                }
            } else {
                // list：枚举所有已注册组件
                for (Object ctx : contexts) {
                    enumerate(ctx, inventory);
                }
            }
        } catch (Throwable t) {
            err = t.getClass().getName() + ": " + String.valueOf(t.getMessage());
        }

        json.append("{\"contextsFound\":").append(contextsFound)
            .append(",\"action\":\"").append(esc(action)).append("\"");
        if (err != null) json.append(",\"error\":\"").append(esc(err)).append("\"");
        json.append(",\"inventory\":[").append(join(inventory)).append("]");
        json.append(",\"results\":[").append(join(results)).append("]}");

        String out = json.toString();
        if (resultPath != null) {
            try {
                Files.write(Paths.get(resultPath), out.getBytes(StandardCharsets.UTF_8));
            } catch (Throwable ignore) {
            }
        }
        System.out.println("[MemCheckAgent] " + out);
    }

    // ---- 上下文发现（兼容独立/内嵌 Tomcat）----

    private static Set<Object> findStandardContexts(Instrumentation inst) {
        Set<Object> ctxs = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
        Set<ClassLoader> loaders = Collections.newSetFromMap(new IdentityHashMap<ClassLoader, Boolean>());

        // 1) 从所有已加载类的 ClassLoader 中找 webapp 加载器（最稳，不依赖活跃线程）
        try {
            for (Class<?> c : inst.getAllLoadedClasses()) {
                ClassLoader cl = c.getClassLoader();
                if (cl != null) loaders.add(cl);
            }
        } catch (Throwable ignore) {
        }
        // 2) 线程 contextClassLoader 兜底
        try {
            for (Thread th : Thread.getAllStackTraces().keySet()) {
                ClassLoader cl = th.getContextClassLoader();
                if (cl != null) loaders.add(cl);
            }
        } catch (Throwable ignore) {
        }

        for (ClassLoader cl : loaders) {
            collectFromLoader(cl, ctxs);
        }
        return ctxs;
    }

    private static void collectFromLoader(ClassLoader cl, Set<Object> set) {
        int guard = 0;
        while (cl != null && guard++ < 50) {
            if (isWebappLoader(cl.getClass())) {
                try {
                    Object resources = invoke(cl, "getResources");
                    if (resources != null) {
                        Object ctx = invoke(resources, "getContext");
                        if (ctx != null && isStandardContext(ctx.getClass())) {
                            set.add(ctx);
                        }
                    }
                } catch (Throwable ignore) {
                }
            }
            cl = cl.getParent();
        }
    }

    private static boolean isWebappLoader(Class<?> c) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            if (k.getName().endsWith("WebappClassLoaderBase")) return true;
        }
        return false;
    }

    private static boolean isStandardContext(Class<?> c) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            String n = k.getName();
            if (n.endsWith("StandardContext")) return true;
        }
        return hasMethod(c, "findFilterDefs") && hasMethod(c, "removeFilterDef");
    }

    // ---- 枚举（list）----

    private static void enumerate(Object ctx, List<String> out) {
        ClassLoader webappCl = webappLoaderOf(ctx);
        // Filter
        try {
            Object defs = invoke(ctx, "findFilterDefs");
            if (defs instanceof Object[]) {
                for (Object def : (Object[]) defs) {
                    String cls = str(invoke(def, "getFilterClass"));
                    Class<?> k = resolveClass(webappCl, cls, filterInstance(ctx, str(invoke(def, "getFilterName"))));
                    out.add(invItem("filter", str(invoke(def, "getFilterName")), cls, k));
                }
            }
        } catch (Throwable ignore) {
        }
        // Servlet（Wrapper 子容器）
        try {
            Object children = invoke(ctx, "findChildren");
            if (children instanceof Object[]) {
                for (Object w : (Object[]) children) {
                    if (!hasMethod(w.getClass(), "getServletClass")) continue;
                    String scls = str(invoke(w, "getServletClass"));
                    if (scls == null) continue;
                    out.add(invItem("servlet", str(invoke(w, "getName")), scls, resolveClass(webappCl, scls, null)));
                }
            }
        } catch (Throwable ignore) {
        }
        // Listener
        enumerateListeners(ctx, "getApplicationEventListeners", out);
        enumerateListeners(ctx, "getApplicationLifecycleListeners", out);
    }

    private static void enumerateListeners(Object ctx, String getter, List<String> out) {
        try {
            Object arr = invoke(ctx, getter);
            if (arr instanceof Object[]) {
                for (Object l : (Object[]) arr) {
                    if (l != null) out.add(invItem("listener", "", l.getClass().getName(), l.getClass()));
                }
            }
        } catch (Throwable ignore) {
        }
    }

    // webappLoaderOf 取上下文的 webapp 类加载器（用于按类名解析组件 Class 以获取 codeSource）。
    private static ClassLoader webappLoaderOf(Object ctx) {
        try {
            Object loader = invoke(ctx, "getLoader");
            if (loader != null) {
                Object cl = invoke(loader, "getClassLoader");
                if (cl instanceof ClassLoader) return (ClassLoader) cl;
            }
        } catch (Throwable ignore) {
        }
        return ctx.getClass().getClassLoader();
    }

    // filterInstance 从 filterConfigs 里取已实例化的 filter（不触发新实例化），拿不到返回 null。
    private static Object filterInstance(Object ctx, String fname) {
        try {
            Field f = findField(ctx.getClass(), "filterConfigs");
            if (f == null) return null;
            f.setAccessible(true);
            Object m = f.get(ctx);
            if (m instanceof Map) {
                Object cfg = ((Map) m).get(fname);
                if (cfg != null) {
                    Field ff = findField(cfg.getClass(), "filter");
                    if (ff != null) {
                        ff.setAccessible(true);
                        return ff.get(cfg);
                    }
                }
            }
        } catch (Throwable ignore) {
        }
        return null;
    }

    private static Class<?> resolveClass(ClassLoader cl, String className, Object instance) {
        if (instance != null) return instance.getClass();
        if (className == null || cl == null) return null;
        try {
            return Class.forName(className, false, cl); // 已加载则直接返回，不触发静态初始化
        } catch (Throwable e) {
            return null;
        }
    }

    // codeSourceOf 返回类的 codeSource 位置；内存注入(defineClass 无 ProtectionDomain)通常为空。
    private static String codeSourceOf(Class<?> k) {
        if (k == null) return "";
        try {
            java.security.ProtectionDomain pd = k.getProtectionDomain();
            if (pd == null) return "";
            java.security.CodeSource cs = pd.getCodeSource();
            if (cs == null || cs.getLocation() == null) return "";
            return cs.getLocation().toString();
        } catch (Throwable e) {
            return "";
        }
    }

    private static String loaderNameOf(Class<?> k) {
        if (k == null) return "";
        try {
            ClassLoader cl = k.getClassLoader();
            return cl == null ? "bootstrap" : cl.getClass().getName();
        } catch (Throwable e) {
            return "";
        }
    }

    // ---- 移除（remove）----

    private static void handleFilters(Object ctx, List<String> targets,
                                      Map<String, String> handled, List<String> items) {
        try {
            Object defsObj = invoke(ctx, "findFilterDefs");
            if (!(defsObj instanceof Object[])) return;
            for (Object def : (Object[]) defsObj) {
                String fclass = str(invoke(def, "getFilterClass"));
                String fname = str(invoke(def, "getFilterName"));
                String match = matchAny(targets, fclass, fname);
                if (match == null) continue;

                String registeredAs = "filter:" + fname + " -> " + fclass;
                String status = "removed";
                String detail;
                try {
                    ClassLoader ccl = ctx.getClass().getClassLoader();
                    Class<?> filterDefCls = ccl.loadClass("org.apache.tomcat.util.descriptor.web.FilterDef");
                    invoke1(ctx, "removeFilterDef", filterDefCls, def);
                    int mapsRemoved = 0;
                    Object mapsObj = invoke(ctx, "findFilterMaps");
                    if (mapsObj instanceof Object[]) {
                        Class<?> filterMapCls = ccl.loadClass("org.apache.tomcat.util.descriptor.web.FilterMap");
                        for (Object fm : (Object[]) mapsObj) {
                            if (fname != null && fname.equals(str(invoke(fm, "getFilterName")))) {
                                invoke1(ctx, "removeFilterMap", filterMapCls, fm);
                                mapsRemoved++;
                            }
                        }
                    }
                    boolean cfgReleased = releaseFilterConfig(ctx, fname);
                    detail = "已移除 FilterDef，FilterMap x" + mapsRemoved + (cfgReleased ? "，已释放 filterConfig" : "");
                } catch (Throwable e) {
                    status = "error";
                    detail = "移除 Filter 失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                }
                items.add(resultItem(match, status, registeredAs, detail));
                handled.put(match, status);
            }
        } catch (Throwable ignore) {
        }
    }

    private static boolean releaseFilterConfig(Object ctx, String fname) {
        try {
            Field f = findField(ctx.getClass(), "filterConfigs");
            if (f == null) return false;
            f.setAccessible(true);
            Object m = f.get(ctx);
            if (m instanceof Map) {
                Object cfg = ((Map) m).remove(fname);
                if (cfg != null) {
                    try { invoke(cfg, "release"); } catch (Throwable ignore) {}
                    return true;
                }
            }
        } catch (Throwable ignore) {
        }
        return false;
    }

    private static void handleServlets(Object ctx, List<String> targets,
                                       Map<String, String> handled, List<String> items) {
        try {
            Object childrenObj = invoke(ctx, "findChildren");
            if (!(childrenObj instanceof Object[])) return;
            for (Object w : (Object[]) childrenObj) {
                if (!hasMethod(w.getClass(), "getServletClass")) continue;
                String sclass = str(invoke(w, "getServletClass"));
                String sname = str(invoke(w, "getName"));
                String match = matchAny(targets, sclass);
                if (match == null) continue;
                String registeredAs = "servlet:" + sname + " -> " + sclass;
                String status = "removed";
                String detail;
                try {
                    ClassLoader ccl = ctx.getClass().getClassLoader();
                    Class<?> containerCls = ccl.loadClass("org.apache.catalina.Container");
                    int mapRemoved = 0;
                    Object patternsObj = invoke(ctx, "findServletMappings");
                    if (patternsObj instanceof String[]) {
                        for (String p : (String[]) patternsObj) {
                            Object mapped = invoke1(ctx, "findServletMapping", String.class, p);
                            if (sname != null && sname.equals(str(mapped))) {
                                invoke1(ctx, "removeServletMapping", String.class, p);
                                mapRemoved++;
                            }
                        }
                    }
                    invoke1(ctx, "removeChild", containerCls, w);
                    detail = "已移除 Servlet(Wrapper)，映射 x" + mapRemoved;
                } catch (Throwable e) {
                    status = "error";
                    detail = "移除 Servlet 失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                }
                items.add(resultItem(match, status, registeredAs, detail));
                handled.put(match, status);
            }
        } catch (Throwable ignore) {
        }
    }

    private static void handleListeners(Object ctx, List<String> targets,
                                        Map<String, String> handled, List<String> items) {
        handleListenerArray(ctx, targets, handled, items,
                "getApplicationEventListeners", "setApplicationEventListeners", "event");
        handleListenerArray(ctx, targets, handled, items,
                "getApplicationLifecycleListeners", "setApplicationLifecycleListeners", "lifecycle");
    }

    private static void handleListenerArray(Object ctx, List<String> targets,
                                            Map<String, String> handled, List<String> items,
                                            String getter, String setter, String kind) {
        try {
            Object arrObj = invoke(ctx, getter);
            if (!(arrObj instanceof Object[])) return;
            Object[] arr = (Object[]) arrObj;
            List<Object> keep = new ArrayList<>();
            List<String[]> removed = new ArrayList<>();
            for (Object l : arr) {
                if (l == null) continue;
                String cn = l.getClass().getName();
                String match = matchAny(targets, cn);
                if (match != null) {
                    removed.add(new String[]{match, cn});
                } else {
                    keep.add(l);
                }
            }
            if (!removed.isEmpty()) {
                String status = "removed";
                String detail = "已从 " + kind + " Listener 列表移除";
                try {
                    invoke1(ctx, setter, Object[].class, keep.toArray());
                } catch (Throwable e) {
                    status = "error";
                    detail = "移除 Listener 失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                }
                for (String[] rc : removed) {
                    items.add(resultItem(rc[0], status, "listener(" + kind + "):" + rc[1], detail));
                    handled.put(rc[0], status);
                }
            }
        } catch (Throwable ignore) {
        }
    }

    // ---- 反射与工具 ----

    private static Map<String, Boolean> loadedClasses(Instrumentation inst, List<String> targets) {
        Map<String, Boolean> res = new LinkedHashMap<>();
        try {
            for (Class<?> c : inst.getAllLoadedClasses()) {
                String n = c.getName();
                for (String t : targets) {
                    if (contains(n, t)) res.put(t, Boolean.TRUE);
                }
            }
        } catch (Throwable ignore) {
        }
        return res;
    }

    private static String matchAny(List<String> targets, String... candidates) {
        for (String c : candidates) {
            if (c == null) continue;
            for (String t : targets) {
                if (contains(c, t) || contains(t, c)) return t;
            }
        }
        return null;
    }

    private static boolean contains(String a, String b) {
        if (a == null || b == null || b.isEmpty()) return false;
        return a.contains(b);
    }

    private static Object invoke(Object o, String method) throws Exception {
        Method m = findMethod(o.getClass(), method, 0);
        if (m == null) throw new NoSuchMethodException(method);
        m.setAccessible(true);
        return m.invoke(o);
    }

    private static Object invoke1(Object o, String method, Class<?> paramType, Object arg) throws Exception {
        Method m = null;
        for (Class<?> k = o.getClass(); k != null && m == null; k = k.getSuperclass()) {
            try {
                m = k.getDeclaredMethod(method, paramType);
            } catch (NoSuchMethodException e) {
                for (Method cand : k.getDeclaredMethods()) {
                    if (cand.getParameterCount() == 1 && cand.getName().equals(method)
                            && cand.getParameterTypes()[0].isAssignableFrom(paramType)) {
                        m = cand;
                        break;
                    }
                }
            }
        }
        if (m == null) throw new NoSuchMethodException(method);
        m.setAccessible(true);
        return m.invoke(o, arg);
    }

    private static Method findMethod(Class<?> c, String name, int argc) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            for (Method m : k.getDeclaredMethods()) {
                if (m.getName().equals(name) && m.getParameterCount() == argc) return m;
            }
        }
        return null;
    }

    private static boolean hasMethod(Class<?> c, String name) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            for (Method m : k.getDeclaredMethods()) {
                if (m.getName().equals(name)) return true;
            }
        }
        return false;
    }

    private static Field findField(Class<?> c, String name) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            try {
                return k.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                // continue
            }
        }
        return null;
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }

    private static Map<String, String> parseArgs(String args) {
        Map<String, String> m = new LinkedHashMap<>();
        if (args == null) return m;
        for (String kv : args.split(";")) {
            int i = kv.indexOf('=');
            if (i > 0) m.put(kv.substring(0, i).trim(), kv.substring(i + 1).trim());
        }
        return m;
    }

    private static List<String> splitList(String s) {
        List<String> out = new ArrayList<>();
        if (s == null) return out;
        for (String p : s.split(",")) {
            String t = p.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    private static String invItem(String kind, String name, String cls, Class<?> k) {
        return "{\"kind\":\"" + esc(kind) + "\",\"name\":\"" + esc(name) + "\",\"class\":\"" + esc(cls)
                + "\",\"codeSource\":\"" + esc(codeSourceOf(k)) + "\",\"loader\":\"" + esc(loaderNameOf(k))
                + "\",\"resolved\":" + (k != null) + "}";
    }

    private static String resultItem(String cls, String status, String registeredAs, String detail) {
        return "{\"class\":\"" + esc(cls) + "\",\"status\":\"" + esc(status)
                + "\",\"registeredAs\":\"" + esc(registeredAs) + "\",\"detail\":\"" + esc(detail) + "\"}";
    }

    private static String join(List<String> items) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) b.append(",");
            b.append(items.get(i));
        }
        return b.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }
}
