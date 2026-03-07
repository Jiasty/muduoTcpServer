// 长连接测试1: 创建一个客户端持续给服务器发数据，直到超过超时时间看看是否正常

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
        sleep(3);
    }
    client_sock.Close();

    return 0;
}