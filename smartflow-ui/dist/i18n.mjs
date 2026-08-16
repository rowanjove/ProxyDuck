const STORAGE_KEY = "proxyduck-language";
const PREVIOUS_STORAGE_KEY = "proxydock-language";
const DEFAULT_LANGUAGE = "zh-CN";

const messages = {
  "zh-CN": {
    app: { tagline: "应用流量路由器" },
    nav: {
      overview: "概览",
      rules: "规则",
      proxies: "代理",
      processes: "进程",
      launch: "快捷启动",
      settings: "设置",
      workspace: "工作区"
    },
    page: {
      overview: { title: "概览", subtitle: "正在同步路由状态" },
      rules: { title: "规则", subtitle: "决定哪些进程通过哪个代理端点" },
      proxies: { title: "代理", subtitle: "集中维护本机可用的代理连接" },
      processes: { title: "进程", subtitle: "从当前运行进程快速创建规则" },
      launch: { title: "快捷启动", subtitle: "一键启动应用并绑定路由规则" },
      settings: { title: "设置", subtitle: "配置界面、路由引擎、防泄漏策略与诊断" }
    },
    common: {
      refresh: "刷新",
      retry: "立即重试",
      cancel: "取消",
      delete: "删除",
      edit: "编辑",
      duplicate: "复制",
      save: "保存",
      enabled: "已启用",
      disabled: "已停用",
      paused: "已暂停",
      routing: "路由中",
      routed: "已路由",
      direct: "直连",
      rule: "规则",
      addRule: "添加规则",
      addApplication: "添加应用",
      addProxy: "添加代理",
      saveSettings: "保存设置",
      browse: "浏览",
      close: "关闭"
    },
    core: {
      connecting: "正在连接核心",
      online: "核心服务在线",
      offline: "核心服务离线"
    },
    connection: {
      title: "核心服务暂时不可用",
      retrying: "正在重试连接…",
      starting: "正在启动并连接核心服务（{attempt}/24）"
    },
    runtime: {
      label: "路由",
      enable: "启用应用路由",
      pause: "暂停应用路由",
      enabledToast: "应用路由已启用",
      pausedToast: "应用路由已暂停"
    },
    runtimePhase: {
      stopped: "已停止",
      paused: "已暂停",
      starting: "启动中",
      running: "运行中",
      degraded: "异常降级",
      error: "启动失败"
    },
    theme: { dark: "切换到深色主题", light: "切换到浅色主题" },
    contextMenu: { refresh: "刷新数据", addRule: "新建路由规则", overview: "返回概览", settings: "打开设置" },
    onboarding: {
      title: "首次路由向导",
      description: "完成以下步骤即可开始按应用分流",
      dismiss: "暂时隐藏",
      configureProxy: "配置代理",
      core: "确认本地核心在线",
      prerequisites: "确认桌面桥接、WebView2 与管理员权限可用",
      proxy: "测试并验证一个已启用的代理端点",
      rule: "创建至少一条应用规则",
      runtime: "启用路由并确认数据平面运行"
    },
    overview: {
      summary: "{rules} 条启用规则 · {proxies} 个代理 · 本次运行 {hits} 次命中",
      ruleSingular: "规则",
      rulePlural: "规则",
      proxySingular: "代理",
      proxyPlural: "代理",
      activeRules: "活动规则",
      activeRulesDescription: "当前启用并参与匹配的应用路由",
      recentActivity: "最近活动",
      recentActivityDescription: "最近命中规则的进程",
      viewAll: "查看全部"
    },
    table: {
      application: "应用",
      proxy: "代理",
      status: "状态",
      lastHit: "最近命中",
      time: "时间",
      process: "进程",
      route: "路由",
      result: "结果",
      rule: "规则",
      target: "匹配目标",
      endpoint: "端点",
      protocols: "协议",
      type: "类型",
      pid: "PID",
      executable: "可执行文件",
      mode: "模式",
      path: "路径"
    },
    rules: {
      search: "搜索规则、进程或代理",
      template: "导入 AI 开发预设",
      create: "新建规则",
      childProcesses: "子进程继承",
      currentProcess: "仅当前进程",
      conflict: "存在匹配冲突",
      moveUp: "上移规则",
      moveDown: "下移规则"
    },
    proxies: {
      lead: "维护 SOCKS5 或直连端点；规则通过端点 ID 绑定。",
      directDescription: "不使用代理，直接连接",
      test: "测试代理握手",
      testSucceeded: "代理测试成功",
      testFailed: "代理测试失败",
      testLatency: "SOCKS5 完整探测耗时 {latency} ms",
      tcpAvailable: "TCP CONNECT 可用",
      tcpUnavailable: "TCP 不可用：{error}",
      tcpRejected: "代理拒绝 TCP CONNECT",
      udpAvailable: "UDP ASSOCIATE 可用",
      udpUnavailable: "UDP 不可用：{error}",
      udpRejected: "代理拒绝 UDP ASSOCIATE"
    },
    processes: {
      search: "按进程名、路径或 PID 搜索",
      waiting: "尚未加载",
      count: "显示 {shown} / {total} 个进程",
      createRule: "创建规则",
      systemPath: "系统进程，路径不可见",
      evaluate: "试运行",
      evaluationMatched: "规则试运行已命中",
      evaluationNoMatch: "没有规则命中",
      evaluationNoMatchDescription: "该进程将不会被 ProxyDuck 路由"
    },
    launch: {
      lead: "从指定代理通道启动常用应用，或只绑定已运行进程。",
      childProcesses: "子进程继承",
      mainProcessOnly: "仅主进程",
      start: "启动"
    },
    settings: {
      interface: "界面",
      interfaceDescription: "选择 ProxyDuck 的显示语言",
      language: "界面语言",
      languageDescription: "更改会立即生效，并仅保存在本机。",
      chinese: "简体中文",
      english: "English",
      routingEngine: "路由引擎",
      routingEngineDescription: "模式切换会重新加载当前规则",
      engineMode: "引擎模式",
      dataPlane: "仅显示核心当前可用的数据平面能力。",
      engineReady: "{engine} 已就绪；选择其他可用引擎会立即切换。",
      engineSingle: "当前只有 {engine} 可用；安装其他引擎运行时后刷新即可切换。",
      engineUnavailable: "该引擎当前不可用",
      logLevel: "日志级别",
      protection: "防泄漏保护",
      protectionDescription: "仅对命中规则的可执行文件生效",
      leakMode: "代理故障策略",
      leakModeDescription: "隐私优先要求规则使用完整可执行文件路径，并在代理不可达时阻断应用",
      availabilityMode: "可用性优先",
      strictMode: "隐私优先（严格阻断）",
      dns: "强制 DNS 策略",
      dnsDescription: "阻止应用绕过代理直连 53 端口",
      ipv6: "阻止 IPv6 直连",
      ipv6Description: "避免双栈应用从 IPv6 泄漏流量",
      doh: "阻止常见 DoH",
      dohDescription: "拦截已知 DoH 提供商的 443 连接",
      localCore: "本地核心",
      localCoreDescription: "桌面端通过仅限本机的令牌鉴权 API 管理流量",
      coreAddress: "核心地址",
      configVersion: "配置版本",
      dataPlaneStatus: "数据平面状态",
      firewallRuleUnit: "条防火墙规则",
      proxyReachable: "代理可达",
      proxyUnreachable: "代理不可达",
      proxyUnknown: "代理未检测",
      failClosedActive: "严格阻断生效",
      authentication: "认证方式",
      exportConfig: "导出配置",
      importConfig: "导入配置",
      exportDiagnostics: "导出诊断包",
      diagnostics: "诊断",
      diagnosticsDescription: "规则命中、代理使用量与核心日志",
      ruleRanking: "规则命中排行",
      proxyUsage: "代理使用量",
      liveLogs: "实时日志",
      refreshLogs: "刷新日志",
      saveHint: "修改后点击保存应用"
    },
    modal: {
      proxyKicker: "代理端点",
      addProxy: "添加代理",
      name: "名称",
      proxyNamePlaceholder: "例如 Clash Verge",
      type: "类型",
      endpoint: "端点",
      directPlaceholder: "直连无需填写",
      saveProxy: "保存代理",
      ruleKicker: "应用规则",
      createRule: "新建路由规则",
      editRule: "编辑路由规则",
      activityKicker: "路由记录",
      allActivity: "全部最近活动",
      activityDescription: "查看本次核心运行期间记录的全部路由命中。",
      ruleName: "规则名称",
      ruleNamePlaceholder: "例如 Cursor 走开发代理",
      matchType: "匹配方式",
      matchValue: "匹配值",
      processName: "进程名",
      executablePath: "可执行文件路径",
      keyword: "通配模式（* / ?）",
      proxyEndpoint: "代理端点",
      childInheritance: "子进程继承",
      quickKicker: "快捷启动",
      addApplication: "添加应用",
      applicationName: "应用名称",
      applicationNamePlaceholder: "例如 Cursor",
      executable: "可执行文件",
      startMode: "启动模式",
      startAndBind: "启动并绑定",
      startOnly: "仅启动",
      bindOnly: "仅绑定",
      runAsAdmin: "管理员权限启动",
      confirmTitle: "确认操作",
      confirmDelete: "确认删除"
    },
    empty: {
      noActiveRules: "没有启用的规则",
      noActiveRulesDescription: "添加或启用规则后会显示在这里",
      noActivity: "暂无路由记录",
      noActivityDescription: "新启动且命中规则的进程会显示在这里",
      noMatchingRules: "没有匹配的规则",
      noRules: "尚未创建规则",
      changeSearch: "尝试更换搜索关键词",
      createFirstRule: "创建第一条应用路由规则",
      noProxies: "尚未添加代理",
      noProxiesDescription: "至少添加一个端点后才能创建规则",
      noLaunches: "快捷启动栏为空",
      noLaunchesDescription: "添加常用应用后可一键启动并绑定代理",
      noMatchingProcesses: "没有匹配的进程",
      noProcesses: "尚未发现在线进程",
      waitForScan: "等待核心完成第一次进程扫描",
      noStats: "暂无命中数据",
      noStatsDescription: "运行匹配规则的应用后将生成统计",
      noLogs: "暂无日志",
      noLogsDescription: "核心事件会实时显示在这里"
    },
    loading: {
      rules: "正在加载规则…",
      activity: "正在加载活动…",
      proxies: "正在加载代理…",
      processes: "选择此页面后加载在线进程",
      applications: "正在加载应用…",
      statistics: "正在加载统计…",
      logs: "正在加载日志…"
    },
    toast: {
      operationFailed: "操作失败",
      refreshed: "已刷新",
      refreshedDescription: "配置与运行状态已同步",
      refreshFailed: "刷新失败",
      processFailed: "进程加载失败",
      logsFailed: "日志刷新失败",
      bridgeFailed: "桌面桥接初始化失败",
      initFailed: "应用初始化失败",
      coreFailed: "无法启动核心服务",
      proxyRequired: "需要可用代理",
      proxyRequiredDescription: "请先添加或启用一个代理端点",
      proxyAdded: "代理已添加",
      ruleCreated: "规则已创建",
      ruleUpdated: "规则已更新",
      ruleDuplicated: "规则副本已创建",
      ruleReordered: "规则顺序已更新",
      configExported: "脱敏配置已导出",
      configImported: "配置已导入并应用",
      diagnosticsExported: "诊断包已导出",
      launchAdded: "应用已加入快捷启动",
      launchSent: "启动请求已发送",
      ruleEnabled: "规则已启用",
      rulePaused: "规则已暂停",
      proxyEnabled: "代理已启用",
      proxyDisabled: "代理已停用",
      deleted: "已删除",
      settingsSaved: "设置已保存",
      settingsSavedDescription: "核心引擎已重新加载当前配置",
      engineSwitched: "路由引擎已切换",
      engineSwitchedDescription: "当前使用 {engine}",
      templateImported: "AI 开发预设已导入",
      templateResult: "新增 {added} 条，更新 {updated} 条",
      filePickerDesktopOnly: "文件选择仅在桌面应用中可用"
    },
    validation: {
      endpoint: "代理端点必须使用 host:port 格式，端口范围为 1–65535",
      pid: "PID 必须是大于 0 的整数",
      protocol: "至少选择一种协议",
      configFile: "文件不是有效的 ProxyDuck 配置",
      addProxyFirst: "请先添加或启用一个代理端点"
    },
    confirm: {
      deleteRule: "删除规则？",
      deleteRuleDescription: "删除后对应应用将不再通过该规则路由。",
      deleteProxy: "删除代理端点？",
      deleteProxyDescription: "仅当没有规则或快捷启动引用它时才能删除。",
      deleteLaunch: "移除快捷启动？",
      deleteLaunchDescription: "关联的托管规则也会一并移除。",
      importConfig: "导入配置？",
      importConfigDescription: "当前配置会被导入内容替换；上一版本仍保存在自动备份中。"
    },
    source: { user: "用户规则", quick_bar: "快捷启动托管", template: "模板规则" },
    matchKind: { pid: "PID", exe_path: "可执行路径", app_name: "进程名", wildcard: "通配模式", hash: "文件哈希" },
    proxyKind: { socks5: "SOCKS5", http: "HTTP", direct: "直连", interface: "网络接口", vpn: "VPN" },
    startMode: { start_and_bind: "启动并绑定", start_only: "仅启动", bind_only: "仅绑定" },
    protocol: { tcp: "TCP", udp: "UDP", dns: "DNS" }
  },
  en: {
    app: { tagline: "Application Traffic Router" },
    nav: {
      overview: "Overview",
      rules: "Rules",
      proxies: "Proxies",
      processes: "Processes",
      launch: "Quick Launch",
      settings: "Settings",
      workspace: "Workspace"
    },
    page: {
      overview: { title: "Overview", subtitle: "Syncing routing status" },
      rules: { title: "Rules", subtitle: "Choose which processes use each proxy endpoint" },
      proxies: { title: "Proxies", subtitle: "Manage the proxy connections available on this device" },
      processes: { title: "Processes", subtitle: "Create rules from currently running processes" },
      launch: { title: "Quick Launch", subtitle: "Start applications and bind routing rules" },
      settings: { title: "Settings", subtitle: "Configure appearance, routing, protection, and diagnostics" }
    },
    common: {
      refresh: "Refresh",
      retry: "Retry now",
      cancel: "Cancel",
      delete: "Delete",
      edit: "Edit",
      duplicate: "Duplicate",
      save: "Save",
      enabled: "Enabled",
      disabled: "Disabled",
      paused: "Paused",
      routing: "Routing",
      routed: "Routed",
      direct: "Direct",
      rule: "Rule",
      addRule: "Add rule",
      addApplication: "Add application",
      addProxy: "Add proxy",
      saveSettings: "Save settings",
      browse: "Browse",
      close: "Close"
    },
    core: {
      connecting: "Connecting to core",
      online: "Core service online",
      offline: "Core service offline"
    },
    connection: {
      title: "Core service is unavailable",
      retrying: "Retrying connection…",
      starting: "Starting and connecting to the core service ({attempt}/24)"
    },
    runtime: {
      label: "Routing",
      enable: "Enable application routing",
      pause: "Pause application routing",
      enabledToast: "Application routing enabled",
      pausedToast: "Application routing paused"
    },
    runtimePhase: {
      stopped: "Stopped",
      paused: "Paused",
      starting: "Starting",
      running: "Running",
      degraded: "Degraded",
      error: "Failed"
    },
    theme: { dark: "Switch to dark theme", light: "Switch to light theme" },
    contextMenu: { refresh: "Refresh data", addRule: "New routing rule", overview: "Back to overview", settings: "Open settings" },
    onboarding: {
      title: "First routing setup",
      description: "Complete these steps to start per-application routing",
      dismiss: "Hide for now",
      configureProxy: "Configure proxy",
      core: "Confirm the local core is online",
      prerequisites: "Confirm the desktop bridge, WebView2, and administrator access",
      proxy: "Test and verify an enabled proxy endpoint",
      rule: "Create at least one application rule",
      runtime: "Enable routing and confirm the data plane is running"
    },
    overview: {
      summary: "{rules} active {ruleLabel} · {proxies} {proxyLabel} · {hits} hits this session",
      ruleSingular: "rule",
      rulePlural: "rules",
      proxySingular: "proxy",
      proxyPlural: "proxies",
      activeRules: "Active Rules",
      activeRulesDescription: "Enabled application routes participating in matching",
      recentActivity: "Recent Activity",
      recentActivityDescription: "Processes that recently matched a rule",
      viewAll: "View all"
    },
    table: {
      application: "Application",
      proxy: "Proxy",
      status: "Status",
      lastHit: "Last Hit",
      time: "Time",
      process: "Process",
      route: "Route",
      result: "Result",
      rule: "Rule",
      target: "Target",
      endpoint: "Endpoint",
      protocols: "Protocols",
      type: "Type",
      pid: "PID",
      executable: "Executable",
      mode: "Mode",
      path: "Path"
    },
    rules: {
      search: "Search rules, processes, or proxies",
      template: "Import AI development preset",
      create: "New rule",
      childProcesses: "Include child processes",
      currentProcess: "Current process only",
      conflict: "Matching conflict",
      moveUp: "Move rule up",
      moveDown: "Move rule down"
    },
    proxies: {
      lead: "Manage SOCKS5 or direct endpoints. Rules bind to endpoint IDs.",
      directDescription: "Connect directly without a proxy",
      test: "Test proxy handshake",
      testSucceeded: "Proxy test succeeded",
      testFailed: "Proxy test failed",
      testLatency: "SOCKS5 probe completed in {latency} ms",
      tcpAvailable: "TCP CONNECT is available",
      tcpUnavailable: "TCP unavailable: {error}",
      tcpRejected: "The proxy rejected TCP CONNECT",
      udpAvailable: "UDP ASSOCIATE is available",
      udpUnavailable: "UDP unavailable: {error}",
      udpRejected: "The proxy rejected UDP ASSOCIATE"
    },
    processes: {
      search: "Search by process name, path, or PID",
      waiting: "Not loaded",
      count: "Showing {shown} of {total} processes",
      createRule: "Create rule",
      systemPath: "System process; path unavailable",
      evaluate: "Dry run",
      evaluationMatched: "Rule dry run matched",
      evaluationNoMatch: "No rule matched",
      evaluationNoMatchDescription: "This process will not be routed by ProxyDuck"
    },
    launch: {
      lead: "Start applications through a selected proxy, or bind an existing process.",
      childProcesses: "Include child processes",
      mainProcessOnly: "Main process only",
      start: "Start"
    },
    settings: {
      interface: "Interface",
      interfaceDescription: "Choose the language used by ProxyDuck",
      language: "Display language",
      languageDescription: "Changes take effect immediately and are stored only on this device.",
      chinese: "简体中文",
      english: "English",
      routingEngine: "Routing Engine",
      routingEngineDescription: "Changing modes reloads the current rules",
      engineMode: "Engine mode",
      dataPlane: "Only data-plane capabilities currently available in the core are selectable.",
      engineReady: "{engine} is ready. Selecting another available engine switches immediately.",
      engineSingle: "Only {engine} is currently available. Install another engine runtime and refresh to switch.",
      engineUnavailable: "This engine is currently unavailable",
      logLevel: "Log level",
      protection: "Leak Protection",
      protectionDescription: "Applies only to executables matched by a rule",
      leakMode: "Proxy failure policy",
      leakModeDescription: "Privacy-first mode requires full executable paths and blocks matched apps while the proxy is unreachable",
      availabilityMode: "Availability first",
      strictMode: "Privacy first (fail closed)",
      dns: "Enforce DNS policy",
      dnsDescription: "Prevent applications from bypassing the proxy on port 53",
      ipv6: "Block direct IPv6",
      ipv6Description: "Prevent dual-stack applications from leaking over IPv6",
      doh: "Block common DoH",
      dohDescription: "Block port 443 connections to known DoH providers",
      localCore: "Local Core",
      localCoreDescription: "The desktop app manages traffic through a token-authenticated local API",
      coreAddress: "Core address",
      configVersion: "Configuration version",
      dataPlaneStatus: "Data-plane status",
      firewallRuleUnit: "firewall rules",
      proxyReachable: "proxy reachable",
      proxyUnreachable: "proxy unreachable",
      proxyUnknown: "proxy not checked",
      failClosedActive: "fail-closed active",
      authentication: "Authentication",
      exportConfig: "Export config",
      importConfig: "Import config",
      exportDiagnostics: "Export diagnostics",
      diagnostics: "Diagnostics",
      diagnosticsDescription: "Rule matches, proxy usage, and core logs",
      ruleRanking: "Rule match ranking",
      proxyUsage: "Proxy usage",
      liveLogs: "Live logs",
      refreshLogs: "Refresh logs",
      saveHint: "Save to apply configuration changes"
    },
    modal: {
      proxyKicker: "Proxy Endpoint",
      addProxy: "Add Proxy",
      name: "Name",
      proxyNamePlaceholder: "For example, Clash Verge",
      type: "Type",
      endpoint: "Endpoint",
      directPlaceholder: "Not required for direct connections",
      saveProxy: "Save proxy",
      ruleKicker: "Application Rule",
      createRule: "Create Routing Rule",
      editRule: "Edit Routing Rule",
      activityKicker: "Routing history",
      allActivity: "All recent activity",
      activityDescription: "All routing matches recorded during this core session.",
      ruleName: "Rule name",
      ruleNamePlaceholder: "For example, Route Cursor through Dev Proxy",
      matchType: "Match type",
      matchValue: "Match value",
      processName: "Process name",
      executablePath: "Executable path",
      keyword: "Glob pattern (* / ?)",
      proxyEndpoint: "Proxy endpoint",
      childInheritance: "Include child processes",
      quickKicker: "Quick Launch",
      addApplication: "Add Application",
      applicationName: "Application name",
      applicationNamePlaceholder: "For example, Cursor",
      executable: "Executable",
      startMode: "Start mode",
      startAndBind: "Start and bind",
      startOnly: "Start only",
      bindOnly: "Bind only",
      runAsAdmin: "Run as administrator",
      confirmTitle: "Confirm action",
      confirmDelete: "Confirm delete"
    },
    empty: {
      noActiveRules: "No active rules",
      noActiveRulesDescription: "Add or enable a rule to see it here",
      noActivity: "No routing activity",
      noActivityDescription: "New processes that match a rule will appear here",
      noMatchingRules: "No matching rules",
      noRules: "No rules yet",
      changeSearch: "Try another search term",
      createFirstRule: "Create your first application routing rule",
      noProxies: "No proxies yet",
      noProxiesDescription: "Add at least one endpoint before creating a rule",
      noLaunches: "Quick Launch is empty",
      noLaunchesDescription: "Add a frequently used application to start it with a proxy",
      noMatchingProcesses: "No matching processes",
      noProcesses: "No running processes found",
      waitForScan: "Waiting for the first process scan",
      noStats: "No match data",
      noStatsDescription: "Statistics appear after an application matches a rule",
      noLogs: "No logs",
      noLogsDescription: "Core events will appear here"
    },
    loading: {
      rules: "Loading rules…",
      activity: "Loading activity…",
      proxies: "Loading proxies…",
      processes: "Open this page to load running processes",
      applications: "Loading applications…",
      statistics: "Loading statistics…",
      logs: "Loading logs…"
    },
    toast: {
      operationFailed: "Operation failed",
      refreshed: "Refreshed",
      refreshedDescription: "Configuration and runtime status are synchronized",
      refreshFailed: "Refresh failed",
      processFailed: "Failed to load processes",
      logsFailed: "Failed to refresh logs",
      bridgeFailed: "Failed to initialize the desktop bridge",
      initFailed: "Application initialization failed",
      coreFailed: "Unable to start the core service",
      proxyRequired: "An enabled proxy is required",
      proxyRequiredDescription: "Add or enable a proxy endpoint first",
      proxyAdded: "Proxy added",
      ruleCreated: "Rule created",
      ruleUpdated: "Rule updated",
      ruleDuplicated: "Rule copy created",
      ruleReordered: "Rule order updated",
      configExported: "Redacted config exported",
      configImported: "Configuration imported and applied",
      diagnosticsExported: "Diagnostics bundle exported",
      launchAdded: "Application added to Quick Launch",
      launchSent: "Launch request sent",
      ruleEnabled: "Rule enabled",
      rulePaused: "Rule paused",
      proxyEnabled: "Proxy enabled",
      proxyDisabled: "Proxy disabled",
      deleted: "Deleted",
      settingsSaved: "Settings saved",
      settingsSavedDescription: "The core engine reloaded the current configuration",
      engineSwitched: "Routing engine switched",
      engineSwitchedDescription: "Now using {engine}",
      templateImported: "AI development preset imported",
      templateResult: "Added {added}, updated {updated}",
      filePickerDesktopOnly: "File selection is available only in the desktop application"
    },
    validation: {
      endpoint: "Proxy endpoints must use host:port with a port between 1 and 65535",
      pid: "PID must be a positive integer",
      protocol: "Select at least one protocol",
      configFile: "This file is not a valid ProxyDuck configuration",
      addProxyFirst: "Add or enable a proxy endpoint first"
    },
    confirm: {
      deleteRule: "Delete rule?",
      deleteRuleDescription: "The matching application will no longer use this route.",
      deleteProxy: "Delete proxy endpoint?",
      deleteProxyDescription: "A proxy can be deleted only when no rule or Quick Launch item references it.",
      deleteLaunch: "Remove Quick Launch item?",
      deleteLaunchDescription: "Its managed rule will also be removed.",
      importConfig: "Import configuration?",
      importConfigDescription: "The imported content will replace the current configuration. The previous version remains in the automatic backup."
    },
    source: { user: "User rule", quick_bar: "Managed by Quick Launch", template: "Template rule" },
    matchKind: { pid: "PID", exe_path: "Executable path", app_name: "Process name", wildcard: "Glob pattern", hash: "File hash" },
    proxyKind: { socks5: "SOCKS5", http: "HTTP", direct: "Direct", interface: "Network Interface", vpn: "VPN" },
    startMode: { start_and_bind: "Start and bind", start_only: "Start only", bind_only: "Bind only" },
    protocol: { tcp: "TCP", udp: "UDP", dns: "DNS" }
  }
};

let currentLanguage = DEFAULT_LANGUAGE;

function lookup(object, path) {
  return path.split(".").reduce((value, segment) => value?.[segment], object);
}

function format(template, variables) {
  return String(template).replace(/\{(\w+)\}/g, (_, key) => String(variables[key] ?? ""));
}

export function initializeLanguage() {
  const saved = globalThis.localStorage?.getItem(STORAGE_KEY) ?? globalThis.localStorage?.getItem(PREVIOUS_STORAGE_KEY);
  currentLanguage = saved === "en" ? "en" : DEFAULT_LANGUAGE;
  if (globalThis.document) document.documentElement.lang = currentLanguage;
  return currentLanguage;
}

export function getLanguage() {
  return currentLanguage;
}

export function setLanguage(language) {
  currentLanguage = language === "en" ? "en" : DEFAULT_LANGUAGE;
  globalThis.localStorage?.setItem(STORAGE_KEY, currentLanguage);
  if (globalThis.document) document.documentElement.lang = currentLanguage;
  return currentLanguage;
}

export function t(key, variables = {}) {
  const value = lookup(messages[currentLanguage], key) ?? lookup(messages[DEFAULT_LANGUAGE], key) ?? key;
  return format(value, variables);
}

export function applyTranslations(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  root.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder));
  });
  root.querySelectorAll("[data-i18n-title]").forEach((node) => {
    node.setAttribute("title", t(node.dataset.i18nTitle));
  });
  root.querySelectorAll("[data-i18n-aria-label]").forEach((node) => {
    node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel));
  });
}
