#include <../source/server.hpp>

void HandleClose(Channel* channel)
{
    DBG_LOG("close fd: %d", channel->GetFd());
    channel->Remove(); // 移除监控poller
    delete channel;
}
void HandleRead(Channel* channel)
{
    int fd = channel->GetFd();
    char buf[1024] = {0};

    int ret = recv(fd, buf, 1023, 0);
    if(ret <= 0)
        return HandleClose(channel); // 关闭释放
    
    DBG_LOG("%s", buf);
    channel->EnableWrite(); // 启动可写事件
}
void HandleWrite(Channel* channel)
{
    int fd = channel->GetFd();
    const char* s = "asdadasfasfa";

    int ret = send(fd, s, strlen(s), 0);
    if(ret < 0)
    {
        return HandleClose(channel);
    }
    channel->DisableWrite(); // 关闭写监控
}

void HandleError(Channel* channel)
{
    HandleClose(channel);
}
void HandleAny(EventLoop* loop, Channel* channel, uint64_t timerid)
{
    loop->TimerRefresh(timerid);
}

void Acceptor(EventLoop* loop, Channel* lst_channel)
{
    int fd = lst_channel->GetFd();
    int newfd = accept(fd, nullptr, nullptr);
    if(newfd < 0) return;

    int timerid = rand();

    Channel* channel = new Channel(loop, newfd);
    // SetReadCallback的参数是EventCallBack(参数是空的可调用对象)
    channel->SetReadCallback(std::bind(HandleRead, channel)); // 为通信套接字设置可读事件的回调函数
    channel->SetWriteCallback(std::bind(HandleWrite, channel));
    channel->SetCloseCallback(std::bind(HandleClose, channel));
    channel->SetErrorCallback(std::bind(HandleError, channel));
    channel->SetAnyCallback(std::bind(HandleAny, loop, channel, timerid));
    channel->EnableRead();

    // 非活跃连接的超时释放操作，10s后关闭连接
    // TODO: 定时销毁任务，必须在读事件之前，因为有可能启动了事件监控后，立即就有了事件，但是这时候还没有任务
    loop->TimerAdd(timerid, 10, std::bind(HandleClose, channel));
    channel->EnableRead();

}


int main()
{
    srand(time(nullptr));
    // Poller poller; // "大堂经理揽客"
    EventLoop loop;
    Socket listen_sock;
    listen_sock.CreateServer(8080);
    // 为监听套接字创建一个Channel进行事件的管理，以及事件的处理
    Channel channel(&loop, listen_sock.GetFd());
    // 回调函数中获取新链接，为新连接创建Channel并添加监控
    channel.SetReadCallback(std::bind(Acceptor, &loop, &channel));
    channel.EnableRead(); // 启动可读事件监控

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
    listen_sock.Close();

    return 0;
}