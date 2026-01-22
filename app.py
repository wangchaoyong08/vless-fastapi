import base64
import json
import struct
import asyncio
import uuid
import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Response, Header
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from typing import Optional, Tuple, Dict, Any
import ipaddress
from tenacity import (
    retry,
    stop_after_attempt,  # 重试次数限制
    wait_exponential,  # 指数退避（1s→2s→4s）
    retry_if_exception_type,  # 按异常类型重试
)

app = FastAPI()

# 常量定义
WS_READY_STATE_OPEN = 1
DEFAULT_UUID = "35e209b2-53f6-4a89-b375-80c28b9adc74"
DEFAULT_CDN_IP = "www.visa.com.sg"
DEFAULT_IPS = [
    "www.visa.com", "cis.visa.com", "africa.visa.com", "www.visa.com.sg",
    "www.visaeurope.at", "www.visa.com.mt", "qa.visamiddleeast.com", "usa.visa.com",
    "myanmar.visa.com", "www.visa.com.tw", "www.visaeurope.ch", "www.visa.com.br",
    "www.visasoutheasturope.com"
]
DEFAULT_PORTS = [
    "80", "8080", "8880", "2052", "2082", "2086", "2095",
    "443", "8443", "2053", "2083", "2087", "2096"
]


# 配置类
class AppConfig:
    def __init__(self):
        self.userID = DEFAULT_UUID
        self.cdnIP = DEFAULT_CDN_IP
        self.IP = DEFAULT_IPS
        self.PT = DEFAULT_PORTS


config = AppConfig()


# UUID工具类
class UUIDUtil:
    @staticmethod
    def format(buf: bytes) -> str:
        hex_str = buf.hex()
        return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


# VLESS协议解析器
class VlessParser:
    @staticmethod
    def parse(buffer: bytes, user_id: str) -> Dict[str, Any]:
        if len(buffer) < 24:
            return {"error": "Invalid VLESS header"}

        version = buffer[0]
        uuid_buf = buffer[1:17]
        parsed_uuid = UUIDUtil.format(uuid_buf)

        if parsed_uuid != user_id:
            return {"error": "Invalid UUID"}

        opt_len = buffer[17]
        cmd_offset = 18 + opt_len
        if cmd_offset >= len(buffer):
            return {"error": "Header too short"}

        cmd = buffer[cmd_offset]
        is_UDP = cmd == 2

        offset = 19 + opt_len
        if offset + 2 > len(buffer):
            return {"error": "Port missing"}

        port = struct.unpack("!H", buffer[offset:offset + 2])[0]
        offset += 2

        if offset >= len(buffer):
            return {"error": "Address type missing"}

        addr_type = buffer[offset]
        offset += 1
        address = ""

        if addr_type == 1:  # IPv4
            if offset + 4 > len(buffer):
                return {"error": "IPv4 address missing"}
            address = ".".join(map(str, buffer[offset:offset + 4]))
            offset += 4
        elif addr_type == 2:  # 域名
            if offset >= len(buffer):
                return {"error": "Domain length missing"}
            domain_len = buffer[offset]
            offset += 1
            if offset + domain_len > len(buffer):
                return {"error": "Domain missing"}
            address = buffer[offset:offset + domain_len].decode()
            offset += domain_len
        elif addr_type == 3:  # IPv6
            if offset + 16 > len(buffer):
                return {"error": "IPv6 address missing"}
            address = str(ipaddress.IPv6Address(buffer[offset:offset + 16]))
            offset += 16

        return {
            "version": version,
            "address": address,
            "port": port,
            "isUDP": is_UDP,
            "offset": offset
        }


# NAT64解析器
class NAT64Resolver:
    @staticmethod
    async def resolve(domain: str) -> str:
        async with httpx.AsyncClient() as client:
            try:
                # 先尝试获取AAAA记录（IPv6）
                resp = await client.get(
                    f"https://1.1.1.1/dns-query?name={domain}&type=AAAA",
                    headers={"Accept": "application/dns-json"},
                    timeout=10.0
                )
                resp.raise_for_status()
                data = resp.json()
                answer = next((a for a in data.get("Answer", []) if a["type"] == 28), None)
                if answer:
                    return answer["data"]

                # 如果没有AAAA记录，尝试获取A记录并转换为NAT64格式
                resp = await client.get(
                    f"https://1.1.1.1/dns-query?name={domain}&type=A",
                    headers={"Accept": "application/dns-json"},
                    timeout=10.0
                )
                resp.raise_for_status()
                data = resp.json()
                answer = next((a for a in data.get("Answer", []) if a["type"] == 1), None)
                if not answer:
                    raise Exception("No A record found")
                ipv4 = answer["data"]
                return NAT64Resolver.to_ipv6(ipv4)
            except Exception as e:
                raise Exception(f"DNS resolve failed: {str(e)}")

    @staticmethod
    def to_ipv6(ipv4: str) -> str:
        """将IPv4转换为NAT64格式的IPv6地址"""
        try:
            parts = list(map(int, ipv4.split(".")))
            # 使用常用的NAT64前缀
            return f"64:ff9b::{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
        except Exception as e:
            raise Exception(f"Invalid IPv4 address: {ipv4}, error: {str(e)}")


# DNS UDP处理
class DNSOutbound:
    dns_index = 0
    dns_servers = [
        "1.1.1.1",
        "1.0.0.1",
        "223.5.5.5"  # 阿里云
    ]

    @classmethod
    @retry(
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.HTTPStatusError
        )),
        reraise=True  # 重试失败后抛出原异常（便于外层捕获）
    )
    async def dns_query(cls, client: httpx.AsyncClient, chunk: bytes):

        resp = await client.post(
            f"https://{cls.dns_servers[cls.dns_index]}/dns-query",
            headers={"content-type": "application/dns-message"},
            content=chunk
        )
        resp.raise_for_status()
        content = resp.content

        cls.dns_index += 1
        if cls.dns_index > len(cls.dns_servers) - 1:
            cls.dns_index = 0
        return content

    @staticmethod
    async def create(websocket: WebSocket, header: bytes):
        sent = False

        async def write(chunk: bytes):
            nonlocal sent
            async with httpx.AsyncClient(timeout=3.0) as client:
                try:
                    buf = await DNSOutbound.dns_query(client, header)
                    size = struct.pack("!H", len(buf))

                    if not sent:
                        combined = header + size + buf
                        await websocket.send_bytes(combined)
                        sent = True
                    else:
                        combined = size + buf
                        await websocket.send_bytes(combined)
                except Exception as e:
                    raise Exception(f"DNS query failed: {str(e)}")

        return {"write": write}


# 数据流管道
class Pipe:
    @staticmethod
    async def pipe(reader: asyncio.StreamReader, websocket: WebSocket, header: bytes):
        sent = False
        try:
            while True:
                chunk = await reader.read(500 * 1024)  # TODO 4096改成500k
                if not chunk:
                    break
                # 正确的WebSocket连接状态判断
                if websocket.client_state.value == WS_READY_STATE_OPEN:
                    if not sent:
                        combined = header + chunk
                        await websocket.send_bytes(combined)
                        sent = True
                    else:
                        await websocket.send_bytes(chunk)
                else:
                    raise RuntimeError("WebSocket connection is not open")
        except Exception as e:
            print(f"Pipe error: {e}")
        # finally:
        #     try:
        #         await websocket.close()
        #     except Exception as e:
        #         print(f"Safe close websocket error: {e}")


# VLESS会话处理
class VlessSession:
    def __init__(self, config: AppConfig, websocket: WebSocket):
        self.config = config
        self.websocket = websocket
        self.remote_reader: Optional[asyncio.StreamReader] = None
        self.remote_writer: Optional[asyncio.StreamWriter] = None
        self.is_DNS = False
        self.udp_writer = None

    async def on_data(self, chunk: bytes):
        print(chunk)
        if self.is_DNS and self.udp_writer:
            await self.udp_writer["write"](chunk)
            return

        if self.remote_writer:
            try:
                self.remote_writer.write(chunk)
                await self.remote_writer.drain()
            except Exception as e:
                print(f"Write to remote failed: {e}")
                await self.cleanup()
            return

        # 解析VLESS头部
        header = VlessParser.parse(chunk, self.config.userID)
        if "error" in header:
            raise Exception(header["error"])

        payload = chunk[header["offset"]:]
        resp_header = bytes([header["version"], 0])

        if header["isUDP"]:
            if header["port"] != 53:
                raise Exception("UDP only supports DNS")
            self.is_DNS = True
            self.udp_writer = await DNSOutbound.create(self.websocket, resp_header)
            await self.udp_writer["write"](payload)
            return

        # 处理TCP连接
        await self.connect_tcp(header, payload, resp_header)

    async def connect_tcp(self, header: Dict[str, Any], payload: bytes, resp_header: bytes):
        # 解析目标地址
        resolver = NAT64Resolver()
        try:
            # 尝试解析为IPv6地址
            target_ip = await resolver.resolve(header["address"])

            # 建立TCP连接
            self.remote_reader, self.remote_writer = await asyncio.open_connection(
                target_ip, header["port"], timeout=10.0
            )

            # 发送初始payload
            self.remote_writer.write(payload)
            await self.remote_writer.drain()

            # 建立双向管道
            asyncio.create_task(Pipe.pipe(self.remote_reader, self.websocket, resp_header))
        except Exception as e:
            raise Exception(f"TCP connect failed: {str(e)}")

    async def cleanup(self):
        """彻底清理所有资源"""
        # 关闭TCP连接
        if self.remote_writer:
            try:
                self.remote_writer.close()
                await self.remote_writer.wait_closed()
            except Exception:
                pass

        # 重置状态
        self.remote_reader = None
        self.remote_writer = None
        self.udp_writer = None
        self.is_DNS = False

        # 关闭WebSocket连接
        # if self.websocket.client_state.value == WS_READY_STATE_OPEN:
        #     await self.websocket.close()


# 订阅生成器
class SubscriptionGenerator:
    def __init__(self, config: AppConfig):
        self.config = config

    def get_vless_config(self, host: str) -> str:
        # 简化版HTML生成
        uid = self.config.userID
        cdn_ip = self.config.cdnIP

        # 非TLS节点
        vless_ws = f"vless://{uid}@{cdn_ip}:8880?encryption=none&security=none&type=ws&host={host}&path=%2F%3Fed%3D2560#{host}"
        # TLS节点
        vless_ws_tls = f"vless://{uid}@{cdn_ip}:8443?encryption=none&security=tls&type=ws&host={host}&sni={host}&fp=random&path=%2F%3Fed%3D2560#{host}"

        # 聚合节点（Base64编码）
        nodes = []
        for i, (ip, pt) in enumerate(zip(self.config.IP, self.config.PT)):
            security = "none" if i < 7 else "tls"
            sni = f"&sni={host}" if security == "tls" else ""
            node = f"vless://{uid}@{ip}:{pt}?encryption=none&security={security}{sni}&fp=randomized&type=ws&host={host}&path=%2F%3Fed%3D2560#CF_V{i + 1}_{ip}_{pt}"
            nodes.append(node)
        vless_share = base64.b64encode("\n".join(nodes).encode()).decode()

        # 简化版HTML
        html = f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <title>VLESS Config</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h3 {{ color: #666; margin-top: 20px; }}
                p {{ background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all; }}
            </style>
        </head>
        <body>
            <h1>Cloudflare VLESS+WS 配置</h1>
            <h3>非TLS节点</h3>
            <p>{vless_ws}</p>
            <h3>TLS节点</h3>
            <p>{vless_ws_tls}</p>
            <h3>聚合订阅(Base64)</h3>
            <p>{vless_share}</p>
        </body>
        </html>
        """
        return html

    def get_ty_config(self, host: str) -> str:
        uid = self.config.userID
        nodes = []
        for i, (ip, pt) in enumerate(zip(self.config.IP, self.config.PT)):
            security = "none" if i < 7 else "tls"
            sni = f"&sni={host}" if security == "tls" else ""
            node = f"vless://{uid}@{ip}:{pt}?encryption=none&security={security}{sni}&fp=randomized&type=ws&host={host}&path=%2F%3Fed%3D2560#CF_V{i + 1}_{ip}_{pt}"
            nodes.append(node)
        return base64.b64encode("\n".join(nodes).encode()).decode()

    def get_cl_config(self, host: str) -> str:
        # 修复Clash配置生成中的错误
        uid = self.config.userID
        config = f"""
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
proxies:
"""
        for i, (ip, pt) in enumerate(zip(self.config.IP[:6], self.config.PT[:6])):
            # 修复端口类型（字符串转整数）
            port = int(pt)
            tls = i >= 7
            config += f"""
- name: CF_V{i + 1}_{ip}_{pt}
  type: vless
  server: {ip}
  port: {port}
  uuid: {uid}
  udp: false
  tls: {tls}
  servername: {host if tls else ""}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: {host}
"""
        return config.strip()

    def get_sb_config(self, host: str) -> str:
        # 修复Sing-box配置生成
        uid = self.config.userID
        outbounds = []
        for i, (ip, pt) in enumerate(zip(self.config.IP, self.config.PT)):
            tls_config = {}
            if i >= 7:
                tls_config = {
                    "enabled": True,
                    "server_name": host,
                    "insecure": False,
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
            outbound = {
                "server": ip,
                "server_port": int(pt),  # 修复端口类型
                "tag": f"CF_V{i + 1}_{ip}_{pt}",
                "packet_encoding": "packetaddr",
                "transport": {
                    "type": "ws",
                    "path": "/?ed=2560",
                    "headers": {"Host": host}
                },
                "type": "vless",
                "uuid": uid,
                "tls": tls_config
            }
            outbounds.append(outbound)

        sb_config = {
            "log": {"disabled": False, "level": "info"},
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": 7890,
                    "tcp_fast_open": True
                }
            ],
            "outbounds": outbounds + [{"tag": "direct", "type": "direct"}],
            "route": {"final": "direct"}
        }
        return json.dumps(sb_config, indent=2, ensure_ascii=False)


@app.websocket("/ws/{path:path}")
async def websocket_endpoint2(websocket: WebSocket, path: str):
    await websocket.accept()
    while True:
        data = ""
        data = await websocket.receive()
        print(data)


# 新增：通用的 WS 消息接收函数（兼容分帧/掩码/文本/二进制）
async def receive_websocket_message(websocket: WebSocket):
    """
    接收完整的 WebSocket 消息（处理分帧、掩码）
    返回：完整的字节数据
    """
    message = await websocket.receive()
    if message["type"] == "websocket.disconnect":
        raise WebSocketDisconnect(message["code"])

    # 处理文本消息：转字节
    if "text" in message:
        return message["text"].encode("utf-8", errors="ignore")

    # 处理二进制消息（核心：自动解掩码）
    elif "bytes" in message:
        return message["bytes"]

    # 处理其他类型（如 ping/pong）
    else:
        return b""


def parse_early_data_from_header(sec_websocket_protocol: str = Header(None)) -> bytes:
    """
   解析v2rayN的sec-websocket-protocol头：
   1. 处理base64编码的早数据
   2. 过滤开头无效字节（\x00\x01等）
   3. 返回纯HTTP数据字节
   """
    early_data = b""
    if not sec_websocket_protocol:
        return early_data

    try:

        clean_str = sec_websocket_protocol.replace('-', '+').replace('_', '/')

        # 步骤3：Base64解码（此时字符数是4的倍数）
        decoded = base64.b64decode(clean_str, validate=False)

        # 步骤4：过滤无效字节（只保留可打印的HTTP字符）
        # 保留ASCII 32-126（空格到~），过滤\x00-\x1f等占位符
        valid_bytes = bytes([b for b in decoded if 32 <= b <= 126])

        return valid_bytes
    except Exception as e:
        print(f"早数据解码失败：{e}")
        return b""


# WebSocket处理端点
@app.websocket("/{path:path}")
async def websocket_endpoint(websocket: WebSocket, path: str, sec_websocket_protocol: str = Header(None)):
    # 1. 解析早数据
    early_data = parse_early_data_from_header(sec_websocket_protocol)

    # 2. 提取子协议，完成WS握手（兼容v2rayN的子协议格式）
    sub_protocol = ""
    if sec_websocket_protocol:
        sub_protocol = sec_websocket_protocol.split(";")[0].strip()

    # 3. 接受WS连接，回复子协议（关键：兼容v2ray的协议协商）
    await websocket.accept(subprotocol=sub_protocol if sub_protocol else None)
    session = VlessSession(config, websocket)
    # websocket.

    try:
        # 4. 优先处理早数据（早数据是v2rayN先发的核心数据，丢失会导致数据不全）
        if early_data:
            print(f"✅ 从sec-websocket-protocol提取早数据：长度 {len(early_data)}")
            await session.on_data(early_data)

        # 5. 处理后续WS帧数据
        while True:
            # data = await websocket.receive_bytes()  # v2rayN「分帧发送」，不是「一次性发完整帧」
            # 接收数据
            data = await websocket.receive()
            print(data)
            if data["type"] == "websocket.disconnect":
                raise WebSocketDisconnect()
            if "text" in data:
                text_data = data["text"]
                # 处理文本数据（可能是配置信息或特殊指令）
                # await handle_text_data(text_data, websocket)
            elif "bytes" in data:
                binary_data = data["bytes"]
                await session.on_data(binary_data)
    except WebSocketDisconnect:
        print("WebSocket disconnected normally")
        await session.cleanup()
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        try:
            await websocket.close(code=1011, reason=str(e))
        except:
            pass
        finally:
            await session.cleanup()


# 配置获取端点
@app.get("/{uid}", response_class=HTMLResponse)
async def get_vless_config(uid: str, request: Request):
    if uid != config.userID:
        return Response(status_code=404, content="Not Found")
    host = request.headers.get("host", "")
    if not host:
        host = request.url.netloc
    generator = SubscriptionGenerator(config)
    return generator.get_vless_config(host)


@app.get("/{uid}/ty", response_class=PlainTextResponse)
async def get_ty_config(uid: str, request: Request):
    if uid != config.userID:
        return Response(status_code=404, content="Not Found")
    host = request.headers.get("host", "")
    if not host:
        host = request.url.netloc
    generator = SubscriptionGenerator(config)
    return generator.get_ty_config(host)


@app.get("/{uid}/cl", response_class=PlainTextResponse)
async def get_cl_config(uid: str, request: Request):
    if uid != config.userID:
        return Response(status_code=404, content="Not Found")
    host = request.headers.get("host", "")
    if not host:
        host = request.url.netloc
    generator = SubscriptionGenerator(config)
    return generator.get_cl_config(host)


@app.get("/{uid}/sb", response_class=JSONResponse)
async def get_sb_config(uid: str, request: Request):
    if uid != config.userID:
        return Response(status_code=404, content="Not Found")
    host = request.headers.get("host", "")
    if not host:
        host = request.url.netloc
    generator = SubscriptionGenerator(config)
    # 直接返回字典，避免重复JSON序列化
    return json.loads(generator.get_sb_config(host))


# 404处理
@app.get("/{path:path}", response_class=Response)
async def fallback(path: str):
    return Response(status_code=404, content="Not Found")


if __name__ == "__main__":
    import uvicorn

    # 启动服务（支持WebSocket和HTTP）
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="debug",
        # 生产环境建议启用SSL
        # ssl_keyfile="key.pem",
        # ssl_certfile="cert.pem"
    )
