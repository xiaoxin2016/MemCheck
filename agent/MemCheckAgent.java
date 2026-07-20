import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * MemCheckAgent —— 由 MemCheck 通过 JVM attach 加载的内存马卸载 agent。
 *
 * 只在内存中移除恶意组件的注册（Filter/Servlet/Listener），不删除磁盘文件、不重启服务，
 * 对应《内存马应急排查手册 v2.0》第[62][63]条 Arthas OGNL 热清除的自动化版本。
 *
 * agentArgs 形如: action=scan|remove;result=/tmp/xx.json;classes=EdwardsiidaeFilter,PlasmodesmaFilter
 *   action  scan=仅报告命中；remove=报告并尝试移除
 *   result  结果 JSON 写入路径（供 Go 侧读取）
 *   classes 逗号分隔的目标类名（简单名或全限定名，子串匹配）
 *
 * 通过反射操作 Tomcat 内部类，不在编译期依赖 servlet/Tomcat，任何一步失败都被捕获且不影响其它类。
 */
public class MemCheckAgent {

    public static void agentmain(String agentArgs, Instrumentation inst) {
        Map<String, String> opts = parseArgs(agentArgs);
        String action = opts.getOrDefault("action", "scan");
        String resultPath = opts.get("result");
        List<String> targets = splitList(opts.get("classes"));

        StringBuilder json = new StringBuilder();
        List<String> items = new ArrayList<>();
        int contextsFound = 0;
        String err = null;

        try {
            boolean remove = "remove".equalsIgnoreCase(action);
            Set<Object> contexts = findStandardContexts();
            contextsFound = contexts.size();

            // 逐个目标类，统计其加载状态（是否已加载到 JVM）
            Map<String, Boolean> loaded = loadedClasses(inst, targets);

            // 对每个 Tomcat context 处理 filter/servlet/listener
            Map<String, String> handled = new LinkedHashMap<>(); // 已在注册表中处理的目标 -> 结果描述
            for (Object ctx : contexts) {
                handleFilters(ctx, targets, remove, handled, items);
                handleServlets(ctx, targets, remove, handled, items);
                handleListeners(ctx, targets, remove, handled, items);
            }

            // 目标类已加载但未在任何注册表中命中：属载荷类/其它容器，建议重启
            for (String t : targets) {
                if (!handledContains(handled, t)) {
                    boolean isLoaded = anyLoaded(loaded, t);
                    String status = isLoaded ? "loaded_not_registered" : "not_found";
                    String detail = isLoaded
                            ? "类已加载但未在 Tomcat Filter/Servlet/Listener 注册表中找到；可能是载荷类或非 Tomcat 容器，重启可清除"
                            : "未在当前 JVM 中发现该类";
                    items.add(resultItem(t, status, "", detail));
                }
            }
        } catch (Throwable t) {
            err = t.getClass().getName() + ": " + String.valueOf(t.getMessage());
        }

        json.append("{\"contextsFound\":").append(contextsFound)
            .append(",\"action\":\"").append(esc(action)).append("\"");
        if (err != null) {
            json.append(",\"error\":\"").append(esc(err)).append("\"");
        }
        json.append(",\"results\":[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) json.append(",");
            json.append(items.get(i));
        }
        json.append("]}");

        String out = json.toString();
        if (resultPath != null) {
            try {
                Files.write(Paths.get(resultPath), out.getBytes(StandardCharsets.UTF_8));
            } catch (Throwable ignore) {
            }
        }
        System.out.println("[MemCheckAgent] " + out);
    }

    // ---- Tomcat context 发现 ----

    private static Set<Object> findStandardContexts() {
        Set<Object> set = java.util.Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread th : threads) {
            try {
                collectFromLoader(th.getContextClassLoader(), set);
            } catch (Throwable ignore) {
            }
        }
        return set;
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
            if (n.endsWith("StandardContext") || n.equals("org.apache.catalina.core.StandardContext")) return true;
        }
        // 通过是否具备关键方法判断（兼容不同版本/包装）
        return hasMethod(c, "findFilterDefs") && hasMethod(c, "removeFilterDef");
    }

    // ---- Filter ----

    private static void handleFilters(Object ctx, List<String> targets, boolean remove,
                                      Map<String, String> handled, List<String> items) {
        try {
            Object defsObj = invoke(ctx, "findFilterDefs");
            if (!(defsObj instanceof Object[])) return;
            Object[] defs = (Object[]) defsObj;
            for (Object def : defs) {
                String fclass = str(invoke(def, "getFilterClass"));
                String fname = str(invoke(def, "getFilterName"));
                String match = matchAny(targets, fclass, fname);
                if (match == null) continue;

                String registeredAs = "filter:" + fname + " -> " + fclass;
                if (!remove) {
                    items.add(resultItem(match, "found", registeredAs, "命中 Filter 注册（scan 模式未移除）"));
                    handled.put(match, "found");
                    continue;
                }
                String detail;
                String status = "removed";
                try {
                    ClassLoader ccl = ctx.getClass().getClassLoader();
                    // 移除 FilterDef
                    Class<?> filterDefCls = ccl.loadClass("org.apache.tomcat.util.descriptor.web.FilterDef");
                    invoke1(ctx, "removeFilterDef", filterDefCls, def);
                    // 移除对应 FilterMap
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
                    // 移除并释放 filterConfigs 缓存
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

    // ---- Servlet ----

    private static void handleServlets(Object ctx, List<String> targets, boolean remove,
                                       Map<String, String> handled, List<String> items) {
        try {
            Object childrenObj = invoke(ctx, "findChildren");
            if (!(childrenObj instanceof Object[])) return;
            for (Object w : (Object[]) childrenObj) {
                String sclass = str(invoke(w, "getServletClass"));
                String sname = str(invoke(w, "getName"));
                String match = matchAny(targets, sclass);
                if (match == null) continue;
                String registeredAs = "servlet:" + sname + " -> " + sclass;
                if (!remove) {
                    items.add(resultItem(match, "found", registeredAs, "命中 Servlet 注册（scan 模式未移除）"));
                    handled.put(match, "found");
                    continue;
                }
                String status = "removed";
                String detail;
                try {
                    ClassLoader ccl = ctx.getClass().getClassLoader();
                    Class<?> containerCls = ccl.loadClass("org.apache.catalina.Container");
                    // 先移除 servlet 映射
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

    // ---- Listener ----

    private static void handleListeners(Object ctx, List<String> targets, boolean remove,
                                        Map<String, String> handled, List<String> items) {
        handleListenerArray(ctx, targets, remove, handled, items,
                "getApplicationEventListeners", "setApplicationEventListeners", "event");
        handleListenerArray(ctx, targets, remove, handled, items,
                "getApplicationLifecycleListeners", "setApplicationLifecycleListeners", "lifecycle");
    }

    private static void handleListenerArray(Object ctx, List<String> targets, boolean remove,
                                            Map<String, String> handled, List<String> items,
                                            String getter, String setter, String kind) {
        try {
            Object arrObj = invoke(ctx, getter);
            if (!(arrObj instanceof Object[])) return;
            Object[] arr = (Object[]) arrObj;
            List<Object> keep = new ArrayList<>();
            List<String> removedClasses = new ArrayList<>();
            for (Object l : arr) {
                if (l == null) { continue; }
                String cn = l.getClass().getName();
                String match = matchAny(targets, cn);
                if (match != null) {
                    if (!remove) {
                        items.add(resultItem(match, "found", "listener(" + kind + "):" + cn,
                                "命中 Listener 注册（scan 模式未移除）"));
                        handled.put(match, "found");
                        keep.add(l);
                    } else {
                        removedClasses.add(match + "|" + cn);
                    }
                } else {
                    keep.add(l);
                }
            }
            if (remove && !removedClasses.isEmpty()) {
                String status = "removed";
                String detail = "已从 " + kind + " Listener 列表移除";
                try {
                    invoke1(ctx, setter, Object[].class, keep.toArray());
                } catch (Throwable e) {
                    status = "error";
                    detail = "移除 Listener 失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                }
                for (String rc : removedClasses) {
                    String m = rc.substring(0, rc.indexOf('|'));
                    String cn = rc.substring(rc.indexOf('|') + 1);
                    items.add(resultItem(m, status, "listener(" + kind + "):" + cn, detail));
                    handled.put(m, status);
                }
            }
        } catch (Throwable ignore) {
        }
    }

    // ---- 反射与工具 ----

    private static Map<String, Boolean> loadedClasses(Instrumentation inst, List<String> targets) {
        Map<String, Boolean> res = new LinkedHashMap<>();
        try {
            Class<?>[] all = inst.getAllLoadedClasses();
            for (Class<?> c : all) {
                String n = c.getName();
                for (String t : targets) {
                    if (contains(n, t)) res.put(t, Boolean.TRUE);
                }
            }
        } catch (Throwable ignore) {
        }
        return res;
    }

    private static boolean anyLoaded(Map<String, Boolean> loaded, String t) {
        Boolean b = loaded.get(t);
        return b != null && b;
    }

    private static boolean handledContains(Map<String, String> handled, String t) {
        return handled.containsKey(t);
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
        for (Class<?> k = o.getClass(); k != null; k = k.getSuperclass()) {
            try {
                m = k.getDeclaredMethod(method, paramType);
                break;
            } catch (NoSuchMethodException e) {
                // try assignable param
                for (Method cand : k.getDeclaredMethods()) {
                    if (cand.getParameterCount() == 1 && cand.getName().equals(method)
                            && cand.getParameterTypes()[0].isAssignableFrom(paramType)) {
                        m = cand;
                        break;
                    }
                }
                if (m != null) break;
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

    private static String resultItem(String cls, String status, String registeredAs, String detail) {
        return "{\"class\":\"" + esc(cls) + "\",\"status\":\"" + esc(status)
                + "\",\"registeredAs\":\"" + esc(registeredAs) + "\",\"detail\":\"" + esc(detail) + "\"}";
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
