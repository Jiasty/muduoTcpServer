#include <../source/server.hpp>

std::unordered_map<uint64_t, ConnectionPtr> _conns; // 管理所有连接
uint64_t conn_id = 0;
EventLoop loop;

void ConnectionDestroy(const ConnectionPtr& conn)
{
    _conns.erase(conn->GetId());
}

void OnConnected(const ConnectionPtr& conn)
{
    DBG_LOG("NEW CONNECTION:%p", conn.get());
}

void OnMessage(const ConnectionPtr& conn, Buffer* buf)
{
    DBG_LOG("%s", buf->GetReadPosition());
    buf->MoveReadPosition(buf->GetReadableSize());

    std::string str = "Hello world!";
    conn->Send(str.c_str(), str.size());
    conn->Shutdown(); // 通信一次后断开连接
}

void NewConnection(int fd)
{
    conn_id++;
    
    ConnectionPtr connection(new Connection(conn_id, fd, &loop));
    // SetReadCallback的参数是EventCallBack(参数是空的可调用对象)
    // TODO: std::placeholders是怎么传参的?
    connection->SetMessageCallBack(std::bind(OnMessage, std::placeholders::_1, std::placeholders::_2));
    connection->SetClosedCallBack(std::bind(ConnectionDestroy, std::placeholders::_1));
    connection->SetConnectedCallBack(std::bind(OnConnected, std::placeholders::_1));
    connection->EnableInactiveRelease(10); // 启动非活跃释放
    connection->Established(); // 就绪初始化
    _conns.insert(std::make_pair(conn_id, connection)); // {conn_id, connection}
}


int main()
{
    // Poller poller; // "大堂经理揽客"
    Acceptor acceptor(&loop, 8080);
    // 回调函数中获取新链接，为新连接创建Channel并添加监控
    acceptor.SetAcceptCallBack(std::bind(NewConnection, std::placeholders::_1));
    acceptor.Listen(); // TODO: s回调后再开始监听

    while(1)
    {
        loop.Start();

        // std::vector<Channel*> actives;
        // poller.Poll(&actives);
        // for(auto& a : actives)
        // {
        //     a->HandleEvent();
        // }
    }

    return 0;
}