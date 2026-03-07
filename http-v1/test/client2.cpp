// 超时连接测试1: 创建一个客户端，给服务器发送一次数据后，不动了，查看服务器是否会正常的超时关闭连接

#include <../source/server.hpp>

int main()
{
    Socket client_sock;
    client_sock.CreateClient(8088, "127.0.0.1");
    std::string req = "GET /hello HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    while(1)
    {
        assert(client_sock.Send(req.c_str(), req.size()) != -1);
        char buf[1024] = { 0 };
        assert(client_sock.Recv(buf, 1023));
        DBG_LOG("[%s]", buf);
        sleep(15); // 10s就超时，15s不发就会触发超时
    }
    client_sock.Close();

    return 0;
}