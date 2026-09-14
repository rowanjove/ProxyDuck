use chrono::Utc;
use tracing::info;

use crate::state::CoreState;

use super::{
    adapter::AdapterCollector,
    dns::DnsCollector,
    dual_path::DualPathCollector,
    gateway::GatewayCollector,
    hosts::HostsCollector,
    internet::InternetCollector,
    model::{Confidence, NetworkDiagnosis, NetworkIssue, OverallStatus, Severity},
    ncsi::NcsiCollector,
    proxy::ProxyCollector,
    proxyduck_self::ProxyDuckCollector,
    route::RouteCollector,
    winsock::WinsockCollector,
};

pub struct DiagnosticOrchestrator;

impl DiagnosticOrchestrator {
    pub async fn run_diagnostics(state: Option<&CoreState>) -> NetworkDiagnosis {
        let started_at = Utc::now().to_rfc3339();
        info!("starting full 10-layer network diagnostics...");

        // Layer 1: Adapter
        let adapters = tokio::task::spawn_blocking(AdapterCollector::collect)
            .await
            .unwrap_or_default();

        // Layer 2: Routes
        let routes = tokio::task::spawn_blocking(RouteCollector::collect)
            .await
            .unwrap_or_default();

        // Determine default gateway IP to probe
        let gw_ip = routes.default_ipv4_gateway.as_deref().or_else(|| {
            adapters
                .active_adapters
                .iter()
                .find_map(|a| a.gateway.as_deref())
        });

        // Layer 3: Gateway
        let gateway = GatewayCollector::check_gateway(gw_ip).await;

        // Layer 4: Internet IP Connectivity
        let internet = InternetCollector::check_internet().await;

        // Determine DNS servers to probe
        let mut dns_servers = Vec::new();
        for adapter in &adapters.active_adapters {
            for dns in &adapter.dns_servers {
                if !dns_servers.contains(dns) {
                    dns_servers.push(dns.clone());
                }
            }
        }

        // Layer 5: DNS
        let dns = DnsCollector::check_dns(dns_servers).await;

        // Layer 6: NCSI & Captive Portal
        let ncsi = NcsiCollector::check_ncsi().await;

        // Layer 7: System Proxy
        let proxy = ProxyCollector::check_proxy().await;

        // Layer 8: Dual Path Analysis
        let dual_path =
            DualPathCollector::check_dual_path(internet.ip_level_connected, &proxy).await;

        // Layer 9: Winsock
        let winsock = tokio::task::spawn_blocking(WinsockCollector::check_winsock)
            .await
            .unwrap_or_default();

        // Layer 10: Hosts
        let hosts = tokio::task::spawn_blocking(HostsCollector::check_hosts)
            .await
            .unwrap_or_default();

        // Layer 10b: ProxyDuck Self-Diagnosis
        let proxyduck = ProxyDuckCollector::check(state);

        // Analyze all layers to produce structured issues
        let mut issues = Vec::new();

        // 1. Adapter & DHCP Issues
        if !adapters.has_connected_adapter {
            issues.push(NetworkIssue {
                id: "adapter_disconnected".to_string(),
                layer: "Layer 1: 网络接口".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "未检测到已连接的网络适配器".to_string(),
                explanation:
                    "本机所有物理与虚拟网卡均未连接或处于禁用状态，无法建立局域网或公网通信。"
                        .to_string(),
                evidence: vec!["有效网卡数量: 0".to_string()],
                suggested_actions: vec![
                    "检查网线是否插紧或 Wi-Fi 是否已连接".to_string(),
                    "在 Windows 网络设置中启用网络适配器".to_string(),
                ],
            });
        } else if adapters.apipa_found {
            issues.push(NetworkIssue {
                id: "dhcp_apipa_failure".to_string(),
                layer: "Layer 1: 网络接口 (DHCP)".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "DHCP 获取 IP 地址失败 (APIPA 自动专用 IP)".to_string(),
                explanation: "网卡分配到了 169.254.x.x 保留地址，表明路由器或 DHCP 服务器未能及时响应 IP 租约请求。".to_string(),
                evidence: vec!["检测到 169.254.x.x 自分配地址".to_string()],
                suggested_actions: vec![
                    "执行 DHCP 重新获取 (ipconfig /renew)".to_string(),
                    "重启局域网路由器或检查 DHCP 服务".to_string(),
                ],
            });
        }

        // 2. Default Route Issues
        if !routes.has_default_route {
            issues.push(NetworkIssue {
                id: "missing_default_route".to_string(),
                layer: "Layer 2: 默认路由".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "缺少默认路由 (0.0.0.0/0)".to_string(),
                explanation:
                    "路由表中没有通往外部网络的默认网关条目，系统不知道如何向公网发送数据包。"
                        .to_string(),
                evidence: vec!["路由表未发现 0.0.0.0/0 下一跳".to_string()],
                suggested_actions: vec![
                    "重新连接网络以刷新默认路由".to_string(),
                    "检查网卡默认网关配置".to_string(),
                ],
            });
        } else if routes.rival_routes_count > 0 {
            issues.push(NetworkIssue {
                id: "route_metric_rivalry".to_string(),
                layer: "Layer 2: 默认路由".to_string(),
                severity: Severity::Info,
                confidence: Confidence::Medium,
                title: "检测到多个竞争默认路由".to_string(),
                explanation: format!(
                    "系统中同时存在 {} 条默认网关路由（例如有线与 Wi-Fi 同时在线），可能导致流量出口漂移或分流混乱。",
                    routes.rival_routes_count + 1
                ),
                evidence: vec![format!("当前活动默认出口: {:?}", routes.default_ipv4_interface)],
                suggested_actions: vec!["如遇网络卡顿，可断开冗余网络连接".to_string()],
            });
        }

        // 3. Gateway Reachability
        if routes.has_default_route && !gateway.reachable {
            issues.push(NetworkIssue {
                id: "gateway_unreachable".to_string(),
                layer: "Layer 3: 局域网网关".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "默认网关无法访问".to_string(),
                explanation: format!(
                    "无法与默认网关 ({:?}) 通信，ARP 解析未完成且 ICMP 无响应，局域网通信中断。",
                    gateway.target
                ),
                evidence: vec![
                    format!("网关 IP: {:?}", gateway.target),
                    "ARP 解析失败".to_string(),
                ],
                suggested_actions: vec![
                    "检查本机与路由器/交换机之间的物理网线或 Wi-Fi 信号".to_string(),
                    "重启路由器".to_string(),
                ],
            });
        }

        // 4. System Proxy Dead Port Issue (The most common cause of broken web!)
        if proxy.wininet_enabled {
            if let Some(port_ok) = proxy.proxy_port_reachable {
                if !port_ok {
                    issues.push(NetworkIssue {
                        id: "proxy_dead_port".to_string(),
                        layer: "Layer 7: 系统代理".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        title: "系统代理指向不可访问的本地端口".to_string(),
                        explanation: format!(
                            "系统代理当前已启用并指向 {:?}，但该端口未被任何程序监听。这通常是因为代理软件意外退出或未启动，导致所有浏览器无法上网。",
                            proxy.wininet_server
                        ),
                        evidence: vec![
                            format!("WinINET 代理服务器: {:?}", proxy.wininet_server),
                            "端口连通性探测: 拒绝连接 / 超时".to_string(),
                        ],
                        suggested_actions: vec![
                            "关闭系统代理开关以恢复直连模式".to_string(),
                            "重新启动对应的本地代理客户端软件".to_string(),
                        ],
                    });
                }
            }
        }

        // 5. Dual Path Contrast (Direct vs Proxy)
        if proxy.wininet_enabled && internet.ip_level_connected {
            if let Some(port_ok) = proxy.proxy_port_reachable {
                if !port_ok && !dual_path.proxy_internet_ok {
                    // Confirmed: Direct is OK, but Proxy is blocking user!
                    issues.push(NetworkIssue {
                        id: "proxy_blocking_traffic".to_string(),
                        layer: "Layer 8: 链路对比 (双路径)".to_string(),
                        severity: Severity::Warning,
                        confidence: Confidence::High,
                        title: "底层公网连通正常，但系统代理阻断了网络访问".to_string(),
                        explanation: "直连公网 IP 能够成功握手，但通过系统代理访问失败，确认当前网络故障由本地代理配置引起。".to_string(),
                        evidence: vec![
                            "直连公网 IP: 连通正常".to_string(),
                            "通过代理链路: 失败".to_string(),
                        ],
                        suggested_actions: vec!["重置系统代理配置至直连模式".to_string()],
                    });
                }
            }
        }

        // 6. Internet IP Level Failure
        if gateway.reachable && !internet.ip_level_connected {
            issues.push(NetworkIssue {
                id: "internet_ip_unreachable".to_string(),
                layer: "Layer 4: 互联网 IP 层".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "互联网 IP 层连通中断".to_string(),
                explanation: "局域网网关正常，但所有多维公网目标 (TCP 80/443/53) 均无法连通，可能宽带已欠费、光猫断纤或上级 ISP 故障。".to_string(),
                evidence: vec![format!("公网探测失败率: {}/{}", internet.total_count - internet.success_count, internet.total_count)],
                suggested_actions: vec![
                    "检查宽带光猫指示灯 (LOS/光信号是否正常)".to_string(),
                    "联系网络服务运营商 (ISP)".to_string(),
                ],
            });
        }

        // 7. DNS Failure
        if internet.ip_level_connected && !dns.all_resolves_succeeded {
            let failed_count = dns.resolve_results.iter().filter(|r| !r.success).count();
            if failed_count == dns.resolve_results.len() {
                issues.push(NetworkIssue {
                    id: "dns_resolution_failed".to_string(),
                    layer: "Layer 5: DNS 诊断".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    title: "DNS 域名解析全部失败".to_string(),
                    explanation: "公网 IP 层连通正常，但所有测试域名均无法解析为 IP，导致应用和浏览器显示“找不到服务器”。".to_string(),
                    evidence: vec![
                        format!("已配置 DNS: {:?}", dns.configured_servers),
                        "公网 IP: 正常".to_string(),
                        "域名解析失败率: 100%".to_string(),
                    ],
                    suggested_actions: vec![
                        "清空 Windows DNS 缓存 (ipconfig /flushdns)".to_string(),
                        "将网卡 DNS 调整为公共可用 DNS (如 223.5.5.5 或 119.29.29.29)".to_string(),
                    ],
                });
            } else {
                issues.push(NetworkIssue {
                    id: "dns_resolution_partial_failure".to_string(),
                    layer: "Layer 5: DNS 诊断".to_string(),
                    severity: Severity::Warning,
                    confidence: Confidence::Medium,
                    title: "部分域名解析失败或超时".to_string(),
                    explanation: "部分域名解析出现超时或异常，可能存在局部 DNS 污染、递归解析器卡顿或上游劫持。".to_string(),
                    evidence: vec![format!("失败域名数量: {}/{}", failed_count, dns.resolve_results.len())],
                    suggested_actions: vec!["清空 DNS 缓存并观察".to_string()],
                });
            }
        }

        // 8. NCSI Captive Portal
        if ncsi.captive_portal_detected {
            issues.push(NetworkIssue {
                id: "captive_portal_redirect".to_string(),
                layer: "Layer 6: NCSI / Web 认证".to_string(),
                severity: Severity::Warning,
                confidence: Confidence::High,
                title: "检测到网络强制认证门户 (Captive Portal)".to_string(),
                explanation: "HTTP 连通性测试被重定向，通常表明当前处于酒店、校园网、商场或公共 Wi-Fi 的 Web 登录认证页面。在完成认证前无法正常访问外网。".to_string(),
                evidence: vec![format!("重定向目标: {:?}", ncsi.redirect_location)],
                suggested_actions: vec!["在浏览器中打开任意网页完成 Wi-Fi 登录认证".to_string()],
            });
        }

        // 9. Winsock catalog
        if !winsock.is_healthy {
            issues.push(NetworkIssue {
                id: "winsock_catalog_anomalous".to_string(),
                layer: "Layer 9: Winsock / LSP".to_string(),
                severity: Severity::Warning,
                confidence: Confidence::Medium,
                title: "Winsock 目录可能存在异常".to_string(),
                explanation: "Winsock Catalog 协议条目数量明显偏少，可能由于第三方软件卸载残留或网络驱动损坏引起。".to_string(),
                evidence: vec![format!("检测到协议条目数: {}", winsock.catalog_entries_count)],
                suggested_actions: vec!["在必要时通过管理员权限执行 netsh winsock reset".to_string()],
            });
        }

        // 10. Hosts file loopback overrides
        if hosts.loopback_redirects_count > 0 {
            issues.push(NetworkIssue {
                id: "hosts_loopback_records".to_string(),
                layer: "Layer 10: Hosts 检查".to_string(),
                severity: Severity::Info,
                confidence: Confidence::Medium,
                title: "检测到自定义 Hosts 重定向记录".to_string(),
                explanation: format!(
                    "Hosts 文件中存在 {} 条指向 127.0.0.1 或 0.0.0.0 的自定义映射，被屏蔽的域名将无法正常连接公网。",
                    hosts.loopback_redirects_count
                ),
                evidence: vec![format!("涉及域名示例: {:?}", hosts.custom_domains.iter().take(5).collect::<Vec<_>>())],
                suggested_actions: vec!["检查 Hosts 文件是否包含需要的业务域名".to_string()],
            });
        }

        // 11. ProxyDuck Self-Diagnosis
        if proxyduck.degraded {
            issues.push(NetworkIssue {
                id: "proxyduck_data_plane_degraded".to_string(),
                layer: "Layer 10+: ProxyDuck 自检".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "ProxyDuck 路由数据平面处于异常状态".to_string(),
                explanation: format!(
                    "ProxyDuck 数据平面状态为 '{}'，分流引擎或底层驱动出现故障，请勿重置系统网络，优先检查 ProxyDuck 引擎运行状态。",
                    proxyduck.data_plane_phase
                ),
                evidence: vec![
                    format!("引擎模式: {}", proxyduck.engine_mode),
                    format!("数据平面阶段: {}", proxyduck.data_plane_phase),
                ],
                suggested_actions: vec![
                    "在 ProxyDuck 设置中重启路由引擎".to_string(),
                    "检查 WinpkFilter 或 sing-box 数据平面驱动".to_string(),
                ],
            });
        }

        // Calculate Overall Status
        let status = if issues.iter().any(|i| i.severity == Severity::Critical) {
            OverallStatus::Critical
        } else if issues.iter().any(|i| i.severity == Severity::Warning) {
            OverallStatus::Warning
        } else if !adapters.has_connected_adapter && !routes.has_default_route {
            OverallStatus::Inconclusive
        } else {
            OverallStatus::Normal
        };

        info!(
            status = ?status,
            issues_count = issues.len(),
            "10-layer network diagnostics completed"
        );

        NetworkDiagnosis {
            timestamp: started_at,
            status,
            adapters,
            routes,
            gateway,
            internet,
            dns,
            ncsi,
            proxy,
            dual_path,
            winsock,
            hosts,
            proxyduck,
            issues,
        }
    }
}
