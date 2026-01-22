#!/usr/bin/env python3
from twisted.internet import endpoints, reactor, protocol
from twisted.protocols.portforward import ProxyFactory


# 一行代码启动端口转发！
def simple_forward():
    # 创建代理工厂
    factory = ProxyFactory('127.0.0.1', 8080)

    # 创建 TCP 端点并监听
    endpoint = endpoints.TCP4ServerEndpoint(reactor, 8079)
    endpoint.listen(factory)

    print("端口转发已启动: 8079 -> 192.168.1.100:8080")
    reactor.run()


if __name__ == "__main__":
    simple_forward()