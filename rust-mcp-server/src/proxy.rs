use anyhow::{Result, anyhow};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs::File;
use std::sync::{Arc, Mutex};
use pcap_file::pcap::{PcapWriter, PcapHeader};
use pcap_file::DataLink;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ProxyServer {
    pcap_writer: Arc<Mutex<PcapWriter<File>>>,
}

impl ProxyServer {
    pub fn new(pcap_path: &str) -> Result<Self> {
        let file = File::create(pcap_path)?;
        // Use Ethernet datalink
        let header = PcapHeader {
            datalink: DataLink::ETHERNET,
            ..Default::default()
        };
        let writer = PcapWriter::with_header(file, header).map_err(|e| anyhow!(e))?;
        Ok(Self {
            pcap_writer: Arc::new(Mutex::new(writer)),
        })
    }

    pub async fn run(&self, port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("Proxy server listening on port {}", port);

        loop {
            let (socket, addr) = listener.accept().await?;
            let writer = self.pcap_writer.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, addr, writer).await {
                    eprintln!("Connection error from {}: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_connection(client_socket: TcpStream, client_addr: SocketAddr, pcap_writer: Arc<Mutex<PcapWriter<File>>>) -> Result<()> {
    let mut buf = [0u8; 1];
    if client_socket.peek(&mut buf).await? == 0 {
        return Ok(());
    }

    match buf[0] {
        0x04 => handle_socks4(client_socket, client_addr, pcap_writer).await,
        0x05 => handle_socks5(client_socket, client_addr, pcap_writer).await,
        _ => handle_http(client_socket, client_addr, pcap_writer).await,
    }
}

fn log_packet(writer: &Arc<Mutex<PcapWriter<File>>>, data: &[u8], _direction_client_to_target: bool) {
    let mut w = writer.lock().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    // Construct a fake Ethernet Frame
    // Dest MAC (6) | Src MAC (6) | Type (2) | Payload
    let mut packet = Vec::with_capacity(14 + data.len());

    // Fake MACs: 00:00:00:00:00:01 -> 00:00:00:00:00:02
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]); // Dest
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // Src
    packet.extend_from_slice(&[0x08, 0x00]); // IPv4 Type (Placeholder, even if data isn't IP, it makes Wireshark try)

    // We are just dumping the TCP payload as the "IP Packet" which is technically malformed
    // because it lacks the IP/TCP headers, but it preserves the data in the pcap file.
    // Ideally we'd wrap this in a fake IP/TCP header too, but that requires checksum calc.
    // For "Capturing data", dumping it into the frame is better than nothing.
    packet.extend_from_slice(data);

    // Write raw packet
    if let Err(e) = w.write_packet(&pcap_file::pcap::PcapPacket::new(now, packet.len() as u32, &packet)) {
        eprintln!("Failed to write packet to pcap: {}", e);
    } else {
        // println!("Logged {} bytes", packet.len());
    }
}

async fn handle_socks5(mut client: TcpStream, _addr: SocketAddr, pcap_writer: Arc<Mutex<PcapWriter<File>>>) -> Result<()> {
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;
    let ver = buf[0];
    let nmethods = buf[1];
    let mut methods = vec![0u8; nmethods as usize];
    client.read_exact(&mut methods).await?;

    if ver != 5 { return Ok(()); }
    client.write_all(&[0x05, 0x00]).await?;

    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let cmd = head[1];

    if cmd != 1 { return Ok(()); }

    let atyp = head[3];
    let target_addr_str = match atyp {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let port_num = u16::from_be_bytes(port);
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port_num)
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let port_num = u16::from_be_bytes(port);
            format!("{}:{}", String::from_utf8_lossy(&domain), port_num)
        }
        _ => return Ok(()),
    };

    let target = TcpStream::connect(&target_addr_str).await?;
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    tunnel(client, target, pcap_writer).await
}

async fn handle_socks4(mut client: TcpStream, _addr: SocketAddr, pcap_writer: Arc<Mutex<PcapWriter<File>>>) -> Result<()> {
    let mut head = [0u8; 8];
    client.read_exact(&mut head).await?;
    if head[0] != 4 || head[1] != 1 { return Ok(()); }

    let port = u16::from_be_bytes([head[2], head[3]]);
    let ip = format!("{}.{}.{}.{}", head[4], head[5], head[6], head[7]);

    let mut buf = [0u8; 1];
    loop {
        client.read_exact(&mut buf).await?;
        if buf[0] == 0 { break; }
    }

    let target_addr = format!("{}:{}", ip, port);
    let target = TcpStream::connect(&target_addr).await?;
    client.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
    tunnel(client, target, pcap_writer).await
}

async fn handle_http(mut client: TcpStream, _addr: SocketAddr, pcap_writer: Arc<Mutex<PcapWriter<File>>>) -> Result<()> {
    // Read request line to determine method and target
    // We need to buffer efficiently.
    let mut buf = [0u8; 4096];
    let n = client.peek(&mut buf).await?;
    if n == 0 { return Ok(()); }

    let req_str = String::from_utf8_lossy(&buf[..n]);

    // Simple parsing
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 { return Ok(()); }
    let method = parts[0];
    let target = parts[1];

    if method == "CONNECT" {
        // HTTPS Tunneling
        let target_addr = target.to_string();
        println!("HTTP CONNECT to {}", target_addr);

        let target_stream = TcpStream::connect(&target_addr).await?;

        // Respond 200 OK
        // We need to consume the CONNECT request from the stream first.
        // In this naive peek implementation, we haven't consumed it.
        // We should read until \r\n\r\n

        // Proper read:
        let mut header_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            client.read_exact(&mut byte).await?;
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if header_buf.len() > 8192 { return Ok(()); } // Limit
        }

        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        tunnel(client, target_stream, pcap_writer).await

    } else {
        // HTTP Proxying (GET, POST, etc.)
        // We need to extract Host header to know where to connect.
        // Or target might be absolute URI: GET http://example.com/ HTTP/1.1

        let host = if target.starts_with("http://") {
            let url = target.trim_start_matches("http://");
            url.split('/').next().unwrap_or("").to_string()
        } else {
             // Look for Host header
             // Naive: Just grep it from req_str (which was only peeked 4k)
             req_str.lines()
                .find(|l| l.to_lowercase().starts_with("host:"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
                .unwrap_or_default()
        };

        if host.is_empty() {
             return Ok(());
        }

        let target_addr = if host.contains(':') { host } else { format!("{}:80", host) };
        println!("HTTP Proxy Request to {}", target_addr);

        let target_stream = TcpStream::connect(&target_addr).await?;

        // We have NOT consumed the data from client yet (only peeked initially, but wait...)
        // Actually, handle_connection peeked 1 byte. That 1 byte is still in the stream?
        // No, `client_socket.peek` does not consume.
        // But `handle_http` calls `client.peek` again.
        // The data is still there. We can just tunnel everything.
        // BUT for standard HTTP proxy, we might need to rewrite the request line (remove http:// host).
        // For this naive implementation, we just forward blindly. Most servers handle absolute URI.

        tunnel(client, target_stream, pcap_writer).await
    }
}

async fn tunnel(mut client: TcpStream, mut target: TcpStream, pcap_writer: Arc<Mutex<PcapWriter<File>>>) -> Result<()> {
    let (mut cr, mut cw) = client.split();
    let (mut tr, mut tw) = target.split();

    let writer1 = pcap_writer.clone();
    let client_to_target = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 { break; }
            log_packet(&writer1, &buf[..n], true);
            tw.write_all(&buf[..n]).await?;
        }
        tw.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    let writer2 = pcap_writer.clone();
    let target_to_client = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 { break; }
            log_packet(&writer2, &buf[..n], false);
            cw.write_all(&buf[..n]).await?;
        }
        cw.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}
