use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::model::{DualPathStatus, ProxyStatus};

const DUAL_PATH_TIMEOUT: Duration = Duration::from_millis(1500);

pub struct DualPathCollector;

impl DualPathCollector {
    pub async fn check_dual_path(direct_ok: bool, proxy: &ProxyStatus) -> DualPathStatus {
        if !proxy.wininet_enabled || proxy.wininet_server.is_none() {
            return DualPathStatus {
                direct_internet_ok: direct_ok,
                proxy_internet_ok: false,
                proxy_evaluated: false,
                conclusion: if direct_ok {
                    "未配置系统代理，直连公网连通正常".to_string()
                } else {
                    "未配置系统代理，直连公网未连通".to_string()
                },
            };
        }

        let proxy_srv = proxy.wininet_server.as_ref().unwrap();
        let proxy_endpoint = proxy_srv
            .split(';')
            .next()
            .unwrap_or("")
            .split('=')
            .next_back()
            .unwrap_or("")
            .trim();

        let proxy_ok = Self::test_http_connect_through_proxy(proxy_endpoint).await;

        let conclusion = match (direct_ok, proxy_ok) {
            (true, false) => {
                "系统代理链路异常：直连正常但系统代理不可用，可能是代理软件未运行或端口残留"
                    .to_string()
            }
            (false, true) => "当前网络依赖代理才能访问公网目标，切勿随意重置代理配置".to_string(),
            (true, true) => "直连与系统代理链路均工作正常".to_string(),
            (false, false) => "直连与代理链路均不可用，属于底层网络链路或物理网卡断开".to_string(),
        };

        DualPathStatus {
            direct_internet_ok: direct_ok,
            proxy_internet_ok: proxy_ok,
            proxy_evaluated: true,
            conclusion,
        }
    }

    async fn test_http_connect_through_proxy(proxy_addr_str: &str) -> bool {
        let sock_addr = if let Ok(addr) = proxy_addr_str.parse::<SocketAddr>() {
            addr
        } else if let Ok(addr) = format!("127.0.0.1:{proxy_addr_str}").parse::<SocketAddr>() {
            addr
        } else {
            return false;
        };

        // Try HTTP CONNECT to 223.5.5.5:80
        let connect_res =
            tokio::time::timeout(DUAL_PATH_TIMEOUT, TcpStream::connect(sock_addr)).await;
        let mut stream = match connect_res {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let connect_req = "CONNECT 223.5.5.5:80 HTTP/1.1\r\nHost: 223.5.5.5:80\r\nProxy-Connection: Keep-Alive\r\n\r\n";
        if stream.write_all(connect_req.as_bytes()).await.is_err() {
            return false;
        }

        let mut buf = [0u8; 512];
        if let Ok(Ok(n)) = tokio::time::timeout(DUAL_PATH_TIMEOUT, stream.read(&mut buf)).await {
            let resp = String::from_utf8_lossy(&buf[..n]);
            return resp.contains("200 Connection established")
                || resp.contains("200 OK")
                || resp.contains("HTTP/1.1 200");
        }
        false
    }
}
