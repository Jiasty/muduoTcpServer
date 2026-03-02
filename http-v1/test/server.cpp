#include <../source/server.hpp>

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
    DBG_LOG("%s", buf->GetReadPosition());
    buf->MoveReadPosition(buf->GetReadableSize());

    std::string str = "Hello world!";
    conn->Send(str.c_str(), str.size());
    // conn->Shutdown(); // 通信一次后断开连接
}

int main()
{
    TcpServer server(8080);
    server.SetThreadCount(2);
    server.EnableInactiveRelease(10);
    server.SetConnectedCallBack(OnConnected); // TODO: 参数的类型?
    server.SetMessageCallBack(OnMessage);
    server.SetClosedCallBack(OnClosed);
    server.Start();

    return 0;
}