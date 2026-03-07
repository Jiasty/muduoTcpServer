// 给服务器发送一个数据，告诉服务器要发送1024字节的数据，但是实际发送的数据不足1024，查看服务器的处理结果
// 1、如果数据只发送一次，服务器得不到完整请求，就不会进行业务处理，客户端就得不到响应，最终超时关闭连接。
// 2、给服务器连续发送多次小的请求，服务器会将后边的请求当作前边请求的正文进行处理，而后边处理的时候有可能会因为处理错误而关闭连接

#include <../source/server.hpp>

int main()
{
    Socket client_sock;
    client_sock.CreateClient(8088, "127.0.0.1");
    std::string req = "GET /hello HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 100\r\n\r\nJiasty";
    while(1)
    {
        assert(client_sock.Send(req.c_str(), req.size()) != -1);
        assert(client_sock.Send(req.c_str(), req.size()) != -1);
        assert(client_sock.Send(req.c_str(), req.size()) != -1);
        assert(client_sock.Send(req.c_str(), req.size()) != -1);
        assert(client_sock.Send(req.c_str(), req.size()) != -1);
        assert(client_sock.Send(req.c_str(), req.size()) != -1);
        assert(client_sock.Send(req.c_str(), req.size()) != -1);

        char buf[1024] = { 0 };
        assert(client_sock.Recv(buf, 1023));
        DBG_LOG("[%s]", buf);
        sleep(3);
    }
    client_sock.Close();

    return 0;
}