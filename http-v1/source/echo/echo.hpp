#include "../server.hpp"

class EchoServer
{
private:
    void OnConnected(const ConnectionPtr& conn)
    {
        DBG_LOG("NEW CONNECTION:%p", conn.get());
    }

    void OnClosed(const ConnectionPtr& conn)
    {
        DBG_LOG("CLOSE CONNECTION:%p", conn.get());
    }

    void OnMessage(const ConnectionPtr& conn, Buffer* buf)
    {
        buf->MoveReadPosition(buf->GetReadableSize());
        conn->Send(buf->GetReadPosition(), buf->GetReadableSize());
        conn->Shutdown(); // 通信一次后断开连接
    }

public:
    EchoServer(int port)
        : _server(port)
    {
        _server.SetThreadCount(2);
        _server.EnableInactiveRelease(10);
        _server.SetConnectedCallBack(std::bind(&EchoServer::OnConnected, this, std::placeholders::_1));
        _server.SetMessageCallBack(std::bind(&EchoServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
        _server.SetClosedCallBack(std::bind(&EchoServer::OnClosed, this, std::placeholders::_1));
    }

    void Start()
    {
        _server.Start();
    }

private:
    TcpServer _server;
};