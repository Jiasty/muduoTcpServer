#include <iostream>
#include <functional>
#include <mutex>
#include <thread>
#include <memory>
#include <typeinfo>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <ctime>

#include <string>
#include <vector>
#include <unordered_map>
#include <any>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <arpa/inet.h> // htons 所在的头文件
#include <fcntl.h>



#define DEFAULT_BUFFER_SIZE 1024 // TODO: C++为何还要用宏?
#define MAX_LISTEN 128

// TODO: 日志宏
#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL DBG // 控制打印信息级别
#define LOG(level, format, ...) do{\
    if(level < LOG_LEVEL) break;\
    time_t t = time(nullptr);\
    struct tm* tm_info = localtime(&t);\
    char tmp[32] = {0};\
    strftime(tmp, 31, "%H:%M:%S", tm_info);\
    fprintf(stdout, "[%s %s--%d]: " format "\n", tmp, __FILE__, __LINE__, ##__VA_ARGS__);\
} while(0)
#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__)
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)

class Buffer
{
public:
    Buffer()
        :_buffer(DEFAULT_BUFFER_SIZE)
        ,_read_index(0)
        , _write_index(0)
    {}
    ~Buffer(){}

    // 获取起始地址
    char* Begin() const { return (char*)&*_buffer.begin(); }
    // 获取当前写位置地址
    char* GetWritePosition() const
    {
        // 起始地址 + 写偏移
        return Begin() + _write_index;
    }
    // 获取当前读位置地址
    char* GetReadPosition() const { return Begin() + _read_index; }

    // 获取可读空间大小
    uint64_t GetReadableSize() const { return _write_index - _read_index; }

    // 确保可写空间足够(移动 or 扩容)
    void EnsureWritableSize(uint64_t size)
    {
        if(size <= GetTailWritableSize())
        {
            // 末尾空间足够
            return;
        }
        if(size <= GetTailWritableSize() + GetHeadWritableSize())
        {
            // 末尾加起始空间足够，将数据移动到起始位置
            uint64_t readableSize = GetReadableSize();
            std::copy(GetReadPosition(), GetReadPosition() + readableSize, Begin()); // 范围左闭右开
            _read_index = 0;
            _write_index = readableSize;
        }
        else
        {
            // 空间不够，直接在末尾扩容
            _buffer.resize(_write_index + size); // TODO: 为何_write_index + size?
        }
    }

    // 获取前沿可写空间大小(可写位置往后的空间)
    uint64_t GetTailWritableSize() { return _buffer.size() - _write_index; }
    // 获取后沿可写空间大小(可读位置往前的空间)
    uint64_t GetHeadWritableSize() { return _read_index; }

    // 将写位置向后移动指定长度
    void MoveWritePosition(uint64_t size)
    {
        if(size > GetTailWritableSize())
        {
            std::cerr << "MoveWritePosition size exceed tail writable size" << std::endl;
            return;
        }
        _write_index += size;
    }
    // 将读位置向后移动指定长度
    void MoveReadPosition(uint64_t size)
    {
        if(size > GetReadableSize())
        {
            std::cerr << "MoveReadPosition size exceed head readable size" << std::endl;
            return;
        }
        _read_index += size;
    }

    // 写入数据
    void Write(const void* data, uint64_t size)
    {
        if(size == 0) return;
        // 保证有足够空间
        EnsureWritableSize(size);
        const char* d = (const char*)data;
        // 拷贝数据
        std::copy(d, d + size, GetWritePosition());
    }
    void WriteAndPush(const void* data, uint64_t size)
    {
        Write(data, size);
        MoveWritePosition(size);
    }

    void WriteString(const std::string& data) { Write(data.c_str(), data.size()); }
    void WriteStringAndPush(const std::string& data)
    {
        WriteString(data);
        MoveWritePosition(data.size());
    }
    void WriteBuffer(const Buffer& data) // TODO
    {
        Write(data.GetReadPosition(), data.GetReadableSize());
    }
    void WriteBufferAndPush(const Buffer& data) // TODO
    {
        WriteBuffer(data);
        MoveWritePosition(data.GetReadableSize());
    }

    // 读取数据
    void Read(void* buf, uint64_t size)
    {
        // 确保要求读取数据大小小于等于可读数据大小
        assert(size <= GetReadableSize());

        // 拷贝数据
        std::copy(GetReadPosition(), GetReadPosition() + size, (char*)buf);
    }
    void ReadAndPop(void* buf, uint64_t size)
    {
        Read(buf, size);
        MoveReadPosition(size);
    }

    std::string ReadToString(uint64_t size)
    {
        // 确保要求读取数据大小小于等于可读数据大小
        assert(size <= GetReadableSize());

        std::string str;
        str.reserve(size);
        Read(&str[0], size); // str.c_str()返回的是const char*
        return str;
    }
    std::string ReadToStringAndPop(uint64_t size)
    {
        assert(size <= GetReadableSize());
        std::string str = ReadToString(size);
        MoveReadPosition(size);
        return str;
    }

    char* FindCRLF()
    {
        char* ret = (char*)memchr(GetReadPosition(), '\n', GetReadableSize()); // TODO: memchr
        return ret;
    }
    std::string GetLine()
    {
        char* pos = FindCRLF();
        if(pos == nullptr)
        {
            return "";
        }
        // +1是为了把'\n'也取出来
        return ReadToString(pos - GetReadPosition() + 1);
    }
    std::string GetLineAndPop()
    {
        std::string str = GetLine();
        MoveReadPosition(str.size());
        return str;
    }

    // 清理(移动偏移量)
    void Clear()
    {
        _read_index = 0;
        _write_index = 0;
    }

    void Print()
    {
        for(auto e : _buffer)
        {
            std::cout << e;
        }
        std::cout << std::endl;
    }

private:
    std::vector<char> _buffer;
    uint64_t _read_index;  // 读相对偏移
    uint64_t _write_index;  // 写相对偏移
};

class Any
{
public:
    Any()
        :_content(nullptr)
    {}

    template<class T>
    Any(const T& val)
        :_content(new placeholder<T>(val))
    {}

    Any(const Any& other)
        :_content(other._content ? other._content->clone() : nullptr) // 构造新对象，不是直接复制原对象指针
    {}

    ~Any()
    {
        delete _content;
    }

    Any& Swap(Any& other)
    {
        std::swap(_content, other._content);
        return *this;
    }

    template<class T>
    T* Get()  // 返回子类对象保存的数据的指针
    {
        // TODO
        if(typeid(T) != _content->type()) // 判断请求的数据类型和保存的数据类型是否一致
            return nullptr; // 或断言直接退出程序都可
        return &((placeholder<T>*)_content)->_val;
    }

    template<class T>
    Any& operator=(const T& val)
    {
        Any(val).Swap(*this); // 先构造一个临时对象，再交换内容
        return *this;
    }

    Any& operator=(const Any& other)
    {
        Any(other).Swap(*this); // 先构造一个临时对象，再交换内容
        return *this;
    }


private:
    class holder
    {
    public:
        virtual ~holder() = default; // default显式告诉编译器使用默认实现
        virtual const std::type_info& type() = 0;
        virtual holder* clone() const = 0;
    };

    template<class T>
    class placeholder : public holder
    {
    public:
        placeholder(const T& val)
            :_val(val)
        {}

        virtual ~placeholder() = default;

        virtual const std::type_info& type()  // 获取子类对象保存的数据类型 // TODO
        {
            return typeid(T); // TODO
        }

        virtual holder* clone() const  // 针对当前对象自身克隆一个新的对象
        {
            return new placeholder<T>(_val);
        }

    public:  // 让外部类可以访问
        T _val;
    };


    holder* _content; // 指向基类，抹除类型
};


class Socket
{
public:
    Socket() : _sockfd(-1) {}
    Socket(int fd) : _sockfd(fd) {}
    ~Socket() { Close(); }
    int GetFd() const { return _sockfd; }

    // 创建套接字
    bool Create()
    {
        _sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(_sockfd < 0)
        {
            ERR_LOG("CREATE SOCKET ERROR!");
            return false;
        }
        return true;
    }
    // 绑定地址信息
    bool Bind(const std::string& ip, uint16_t port)
    {
        struct sockaddr_in addr; // TODO: sockaddr_in和sockaddr的关系(C语言的多态TODO)
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port); // 将port从主机的字节顺序转换成网络的字节顺序
        addr.sin_addr.s_addr = inet_addr(ip.c_str()); // TODO: inet_addr

        socklen_t addrlen = sizeof(struct sockaddr_in);
        int ret = bind(_sockfd, (const sockaddr*)&addr, addrlen);
        if(ret < 0)
        {
            ERR_LOG("BIND ADDRESS ERROR!");
            return false;
        }
        return true;
    }
    // 开始监听
    bool Listen(int backlog = MAX_LISTEN) // backlog排队等待被处理的连接数量的上限
    {
        // int listen(int sockfd, int backlog);
        int ret = listen(_sockfd, backlog);
        if(ret < 0)
        {
            ERR_LOG("LISTEN ERROR!");
            return false;
        }
        return true;
    }
    // 向服务器发起连接(client端)
    bool Connect(const std::string& ip, uint16_t port)
    {
        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t addrlen = sizeof(struct sockaddr_in);
        int ret = connect(_sockfd, (const struct sockaddr*)&addr, addrlen);

        if(ret < 0)
        {
            ERR_LOG("CONNECT ERROR!");
            return false;
        }
        return true;
    }
    // 获取新连接(server端)
    int Accept()
    {
        // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        int newfd = accept(_sockfd, nullptr, nullptr); // TODO
        if(newfd < 0)
        {
            ERR_LOG("ACCEPT ERROR!");
            return -1;
        }
        return newfd; // 和刚刚连进来的这个客户端进行一对一专属通信,客户有多个
    }
    // 接收数据
    ssize_t Recv(void* buf, size_t size, int flag = 0)
    {
        ssize_t ret = recv(_sockfd, buf, size, flag);
        if(ret <= 0)
        {
            // TODO: EAGAIN EINTR
            // EAGAIN: 非阻塞套接字没有数据可读了，或者对端关闭了连接
            // EINTR: 系统调用被信号中断了
            if(errno == EAGAIN || errno == EINTR)
            {
                return 0; // 没收到数据
            }
            ERR_LOG("RECV ERROR!");
            return -1;
        }
        return ret;
    }
    ssize_t NonBlockRecv(void* buf, size_t size)
    {
        return Recv(buf, size, MSG_DONTWAIT); // TODO: MSG_DONTWAIT
    }

    // 发送数据
    ssize_t Send(const void* buf, size_t size, int flag = 0)
    {
        ssize_t ret = send(_sockfd, buf, size, flag);
        if(ret < 0) // TODO: <=0?
        {
            if(errno == EAGAIN || errno == EINTR)
            {
                return 0; // 没收到数据
            }
            ERR_LOG("SEND ERROR!");
            return -1;
        }
        return ret;
    }
    ssize_t NonBlockSend(void* buf, size_t size)
    {
        if(size == 0) return 0;
        return Send(buf, size, MSG_DONTWAIT);
    }

    // 关闭套接字
    void Close()
    {
        if(_sockfd != -1)
        {
            close(_sockfd);
            _sockfd = -1;
        }
    }

    /////////////////////////////////////////////////////

    // 创建一个服务端连接
    bool CreateServer(uint16_t port, const std::string& ip = "0.0.0.0", bool block_flag = false)
    {
        // 创建套接字
        if(!Create()) return false;
        // 设置非阻塞
        if(block_flag) SetNonBlock();
        // 启动地址重用
        ReuseAddress();
        // 绑定地址信息
        if(!Bind(ip, port)) return false;
        // 开始监听
        if(!Listen()) return false;
        
        return true;
    }
    // 创建一个客户端连接 // TODO
    bool CreateClient(uint16_t port, const std::string& ip)
    {
        // 创建套接字
        if(!Create()) return false;
        // 连接服务器
        if(!Connect(ip, port)) return false;
        return true;
    }
    // 设置套接字选项 --- 开启地址端口重用(服务端能立即重用端口，跳过timewait阶段的保护)
    void ReuseAddress() // TODO
    {
        int val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&val, sizeof(val));
        val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEPORT, (const void*)&val, sizeof(val));
    }

    // 设置套接字阻塞属性--设置为非阻塞(缓冲区没有数据洛也不会阻塞)
    void SetNonBlock()
    {
        int flag = fcntl(_sockfd, F_GETFL, 0);
        fcntl(_sockfd, F_SETFL, flag | O_NONBLOCK);
    }
private:
    int _sockfd;
};


using EventCallBack = std::function<void()>; // TODO: 连接事件回调函数类型
class Poller; // TODO: 前向声明
class EventLoop;
class Channel // TODO
{
public:
    Channel(EventLoop* loop, int fd) : _loop(loop), _sockfd(fd), _events(0), _revents(0) {}
    ~Channel() {}

    int GetFd() const { return _sockfd; }
    uint32_t GetEvents() const { return _events; }
    uint32_t GetRevents() const { return _revents; }
    uint32_t GetEvent() const { return _events; } // 获取想要监控的事件
    void SetRevents(uint32_t revents) { _revents = revents; }

    void SetReadCallback(const EventCallBack& cb) { _read_callback = cb; }
    void SetWriteCallback(const EventCallBack& cb) { _write_callback = cb; }
    void SetErrorCallback(const EventCallBack& cb) { _error_callback = cb; }
    void SetCloseCallback(const EventCallBack& cb) { _close_callback = cb; }
    void SetAnyCallback(const EventCallBack& cb) { _any_callback = cb; }

    // 当前是否监控了可读
    bool ReadAble() const { return (_events & EPOLLIN); } // TODO: EPOLLIN
    // 当前是否监控了可写
    bool WriteAble() const { return _events & EPOLLOUT; }
    // 启动读事件监控
    void EnableRead() { _events |= EPOLLIN; Update(); }
    // 启动写事件监控
    void EnableWrite() { _events |= EPOLLOUT; Update(); }
    // 关闭读事件监控
    void DisableRead() { _events &= ~EPOLLIN; Update(); }
    // 关闭写事件监控
    void DisableWrite() { _events &= ~EPOLLOUT; Update(); }
    // 关闭所有事件监控
    void DisableAll() { _events = 0; Update(); }
    // 添加or移除事件监控 TODO
    void Update(); // 类外实现
    void Remove();

    // 事件处理
    void HandleEvent() 
    {
        if((_revents & EPOLLIN) || (_revents & EPOLLRDHUP) || (_revents & EPOLLPRI))
        {
            if(_read_callback) _read_callback();
        }

        // 有可能会释放连接的操作一次只处理一个
        if(_revents & EPOLLOUT)
        {
            // 不管什么事件都要调用
            if(_any_callback) _any_callback(); 
            if(_write_callback) _write_callback(); // 放any后，一旦出错就会释放连接，就调不到任意回调了
        }
        else if(_revents & EPOLLERR)
        {
            if(_any_callback) _any_callback();
            if(_error_callback) _error_callback();
        }
        else if(_revents & EPOLLHUP)
        {
            if(_any_callback) _any_callback();
            if(_close_callback) _close_callback();
        }
    }
private:
    // Poller* _poller; // TODO: 事件循环对象指针，后续会调用EventLoop接口
    EventLoop* _loop;

    int _sockfd; // 事件关联的文件描述符
    uint32_t _events; // 当前需要监控的事件
    uint32_t _revents; // 当前连接触发的事件
    EventCallBack _read_callback; // 读事件回调函数
    EventCallBack _write_callback; // 写事件回调函数
    EventCallBack _error_callback; // 错误事件回调函数
    EventCallBack _close_callback; // 连接关闭事件回调函数
    EventCallBack _any_callback; // 任意事件回调函数
};


#define MAX_EPOLLEVENTS 1024
class Poller
{
private:
    void Update(Channel* channel, int op) 
    {
        // epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
        int fd = channel->GetFd();
        struct epoll_event ev;
        ev.data.fd = fd;
        ev.events = channel->GetEvent();
        int ret = epoll_ctl(_epfd, op, fd, &ev); // TODO: epoll_ctl
        if(ret < 0)
        {
            ERR_LOG("EPOLL_CTL ERROR!");
            // abort(); // 暴力的异常终止
            // exit(-1); // 正常退出
        }
    }

    // 判断Channel是否已经添加了事件监控
    bool HasChannel(Channel* channel) const
    {
        return _channels.count(channel->GetFd()); // TODO
    }
public:
    Poller()
    {
        _epfd = epoll_create(MAX_EPOLLEVENTS/*TODO: 随意给?*/); // TODO: epoll_create
        if(_epfd < 0)
        {
            ERR_LOG("CREATE EPOLL ERROR!");
            abort();
        }
    }
    ~Poller() {}

    // 添加or修改事件监控
    void UpdateChannel(Channel* channel)
    {
        bool ret = HasChannel(channel);
        if(ret)
        {
            // 存在则修改
            return Update(channel, EPOLL_CTL_MOD);
        }
        _channels.insert(std::make_pair(channel->GetFd(), channel));
        return Update(channel, EPOLL_CTL_ADD);
    }
    // 删除事件监控
    void RemoveChannel(Channel* channel)
    {
        auto it = _channels.find(channel->GetFd());
        if(it != _channels.end()) _channels.erase(it);

        Update(channel, EPOLL_CTL_DEL);
    }

    // 开始监控，返回活跃连接
    void Poll(std::vector<Channel*>* active)
    {
        // epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
        int nfds = epoll_wait(_epfd, _events, MAX_EPOLLEVENTS, -1); // TODO: epoll_wait
        if(nfds < 0)
        {
            if(errno == EINTR)
            {
                // 被信号中断了，继续等待
                return;
            }
            ERR_LOG("EPOLL_WAIT ERROR: %s\n", strerror(errno));
            abort(); 
        }           

        for(int i = 0; i < nfds; ++i)
        {
            auto it = _channels.find(_events[i].data.fd);
            assert(it != _channels.end());
            it->second->SetRevents(_events[i].events); // TODO: 事件类型
            active->push_back(it->second); // TODO: 直接把Channel对象放到活跃连接列表中，后续EventLoop会调用Channel的事件处理函数
        }
    }

private:
    int _epfd; // epoll实例的文件描述符
    struct epoll_event _events[MAX_EPOLLEVENTS]; // epoll事件数组
    std::unordered_map<int, Channel*> _channels; // 连接fd和Channel的映射
};


using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;
class TimerTask
{
public:
    TimerTask(uint64_t id, uint32_t timeout, const TaskFunc& cbFunc)
        : _id(id)  // id由外界统一管理
        , _timeout(timeout)
        , _task(cbFunc) // 定时器对象与任务绑定
        , _isDeleted(false)
    {}

    ~TimerTask()
    {
        // _timeout时间后准备析构该定时器对象
        if(_isDeleted == false) _task();  // 执行该定时器的任务
        _release();  // 执行完后通知TimeWheel删除该任务，即哈希表_timers中删除
    }

    void SetRelease(const ReleaseFunc& cbFunc)
    {
        // 释放任务得自己写
        _release = cbFunc;
    }

    uint32_t GetTimeOut() const
    {
        return _timeout;
    }

    void Cancel()
    {
        _isDeleted = true;
    }

private:
    uint64_t _id;  // 定时器任务对象ID
    uint32_t _timeout;  // 定时器任务超时时间
    TaskFunc _task;  // 定时器任务回调函数,定时器对象真正的任务
    bool _isDeleted;  // 是否已删除 true表示已删除任务(而不是删除定时器对象)
    ReleaseFunc _release;  // 用于删除TimeWheel中的定时器对象信息
};

// 时间轮里面存放TimerTask对象"指针"，也就是一个个定时任务，统一管理
using TimerTaskPtr = std::shared_ptr<TimerTask>;
using TimerTaskWeakPtr = std::weak_ptr<TimerTask>; // hash表存weak_ptr，不应增加引用计数，只为查找
class TimeWheel
{
private:
    void RemoveTimer(uint64_t id)
    {
        auto it = _timers.find(id);
        if (it != _timers.end())
        {
            _timers.erase(it);
        }
    }

    static int CreateTimerFd()
    {
        int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if(timerfd < 0)
        {
            ERR_LOG("TIMERFD CREATE FAILED!");
            abort();
        }

        struct itimerspec itime;
        itime.it_value.tv_sec = 1; // 第一次超时的时间
        itime.it_value.tv_nsec = 0;
        itime.it_interval.tv_sec = 1; // 第一次超时后再次超时的间隔时间
        itime.it_interval.tv_nsec = 0;
        timerfd_settime(timerfd, 0, &itime, nullptr);
        return timerfd;
    }

    void ReadTimerFd()
    {
        uint64_t times;
        int ret = read(_timerfd, &times, sizeof(times));
        if(ret < 0)
        {
            ERR_LOG("READ TIMERFD FAILED!");
            abort();
        }
    }

    // 每秒执行一次
    void RunTimerTask()
    {
        _tick = (_tick + 1) % _capacity; // 指针前移一格
        _wheel[_tick].clear(); // 清空该槽位的定时任务ptr，触发析构函数执行任务
    }

    void OnTime()
    {
        ReadTimerFd();
        RunTimerTask();
    }

    void TimerAddInLoop(uint64_t id, uint32_t delay, const TaskFunc& cbFunc)
    {
        // 添加定时任务ptr
        TimerTaskPtr ptr(new TimerTask(id, delay, cbFunc));
        ptr->SetRelease(std::bind(&TimeWheel::RemoveTimer, this, id)); // 绑定成员函数时加&和::
        _timers[id] = TimerTaskWeakPtr(ptr); // 一定是weakptr，存入哈希表，方便后续查找

        _wheel[(_tick + delay) % _capacity].emplace_back(ptr);
    }

    void TimerRefreshInLoop(uint64_t id)
    {
        // 延迟(重新刷新)已存在的定时任务
        // 通过保存的定时器对象的weakPtr构造一个新的sharedPtr再添加到_wheel中
        auto it = _timers.find(id); // 迭代器查找
        if (it == _timers.end())
        {
            return; // 没有找到该定时器任务
        }

        TimerTaskPtr ptr = it->second.lock(); // 通过weakPtr构造sharedPtr
        int delay = ptr->GetTimeOut(); // 获取该定时器的超时时间
        _wheel[(_tick + delay) % _capacity].emplace_back(ptr);

        // TODO
        // 正是由于刷新延迟时间是需要，可能会创建多个Ptr指向同一个TimerTask对象，所以此处采用sharedPtr
        // 而为了管理TimerTask对象的生命周期，必须以weakPtr存入哈希表_timers中，防止引用计数增加，导致TimerTask对象无法析构
    }

    void TimerCancelInLoop(uint64_t id)
    {
        // 取消定时任务
        auto it = _timers.find(id);
        if (it == _timers.end())
        {
            return; // 没有找到该定时器任务
        }

        TimerTaskPtr ptr = it->second.lock(); // 通过weakPtr构造sharedPtr
        if(ptr)
        {
            ptr->Cancel(); // 标记该定时器任务已删除
        }
    }
public:
    TimeWheel(EventLoop* loop)
        : _tick(0)
        , _capacity(60) // 60个槽(秒级)
        , _wheel(_capacity) // 声明顺序决定初始化顺序，_capacity先于_wheel声明
        , _loop(loop)
        , _timerfd(CreateTimerFd())
        , _timer_channel(new Channel(_loop, _timerfd))
    {
        _timer_channel->SetReadCallback(std::bind(&TimeWheel::OnTime, this));
        _timer_channel->EnableRead();
    }

    // 因为很多定时任务涉及到对连接的操作，需要考虑线程安全(_timers成员)
    // 加锁影响效率，不加锁则把对定时器的所有操作弄到一个线程执行即可
    // TODO
    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cbFunc);
    void TimerRefresh(uint64_t id);
    void TimerCancel(uint64_t id);

    // TODO: 存在线程安全问题，只可被EventLoop线程执行
    bool HasTimer(uint64_t id) { return _timers.count(id); }

private:
    int _tick; // 当前指针位置,指到哪就执行哪个槽的定时任务，然后释放
    int _capacity; // 时间轮槽的数量
    std::vector<std::vector<TimerTaskPtr>> _wheel; // 秒级时间轮
    std::unordered_map<uint64_t, TimerTaskWeakPtr> _timers; // 任务ID到任务对象ptr的映射,为了找到定时器

    EventLoop* _loop;
    int _timerfd; // 定时器描述符
    std::unique_ptr<Channel> _timer_channel;
};


using Functor = std::function<void()>;
class EventLoop
{
private:
    void RunAllTask()
    {
        std::vector<Functor> _tasks_todo;
        {
            std::unique_lock<std::mutex> _lock(_mutex); // TODO: unique_lock
            _tasks.swap(_tasks_todo);
        }

        for (auto& func : _tasks_todo) func();
    }

    static int CreateEventFd()
    {
        int evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if(evfd < 0)
        {
            ERR_LOG("CREATE EVENTFD FAILED!");
            abort();
        }
        return evfd;
    }
    void ReadEventFd()
    {
        // 读取清零
        uint64_t ret = 0;
        if(read(_eventfd, &ret, sizeof(ret)) < 0)
        {
            // EINTR: 被信号打断
            // EAGAIN: 无数据可读
            if(errno == EINTR || errno == EAGAIN) return;
            ERR_LOG("READ EVENTFD FAILED!");
            abort();
        }
    }
    void WakeUpEventFd()
    {
        uint64_t val = 1; // 必须以8字节为单位
        if(write(_eventfd, &val, sizeof(val)) < 0)
        {
            if(errno == EINTR) return;
            ERR_LOG("WRITE EVENTFD FAILED!");
            abort();
        }
    }
public:
    EventLoop()
        : _thread_id(std::this_thread::get_id()) // TODO: this_thread
        , _eventfd(CreateEventFd())
        , _eventfd_cahnnel(new Channel(this, _eventfd))
        , _time_wheel(this) // TODO: 写构造函数也行
    {
        _eventfd_cahnnel->SetReadCallback(std::bind(&EventLoop::ReadEventFd, this));
        _eventfd_cahnnel->EnableRead();
    }

    // 判断当前线程是否是EventLoop对应的线程
    bool IsInLoop()
    {
        return (_thread_id == std::this_thread::get_id());
    }
    // 确保当前线程是EventLoop对应的线程
    void AssertInLoop()
    {
        assert(_thread_id == std::this_thread::get_id());
    }
    // 判断要执行的任务是否处于当前线程，是则执行，不是则压入任务队列
    void RunInLoop(const Functor& cb)
    {
        if(IsInLoop()) return cb();
        QueueInLoop(cb);
    }
    // 将操作压入任务队列
    void QueueInLoop(const Functor& cb)
    {
        {
            std::unique_lock<std::mutex> _lock(_mutex);
            _tasks.emplace_back(cb);
        }
        // 唤醒有可能因为没有时间就绪，而导致的epoll阻塞
        // 其实就是给eventfd写入一个数据，触发可读事件
        // eventfd不管写多少次，读一次就清空
        WakeUpEventFd();
    }
    // 添加、修改描述符的事件监控
    void UpdateEvent(Channel* channel) { _poller.UpdateChannel(channel); }
    // 移除描述符的监控
    void RemoveEvent(Channel* channel) { _poller.RemoveChannel(channel); }

    //////
    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cbFunc) { _time_wheel.TimerAdd(id, delay, cbFunc); }
    void TimerRefresh(uint64_t id) { _time_wheel.TimerRefresh(id); }
    void TimerCancel(uint64_t id) { _time_wheel.TimerCancel(id); }
    bool HasTimer(uint64_t id) { return _time_wheel.HasTimer(id); }

    // 事件监控-->就绪事件处理-->执行任务
    void Start()
    {
        // 1、事件监控
        std::vector<Channel*> actives;
        _poller.Poll(&actives);
        // 2、就绪事件处理
        for (auto& channel : actives)
        {
            channel->HandleEvent();
        }
        // 3、执行任务
        RunAllTask();
    }

private:
    std::thread::id _thread_id;
    int _eventfd;
    std::unique_ptr<Channel> _eventfd_cahnnel; // TODO: 智能指针
    Poller _poller;
    std::vector<Functor> _tasks;
    std::mutex _mutex;
    TimeWheel _time_wheel;
};

typedef enum
{
    DISCONNECTED, // 连接关闭
    CONNECTING, // 连接建立成功，待处理状态
    CONNECTED, // 连接建立完成，各种设置完成，可通信
    DISCONNECTING  // 待关闭状态
}ConnStatus;

class Connection;
using ConnectionPtr = std::shared_ptr<Connection>;
using ConnectedCallBack = std::function<void(const ConnectionPtr&)>;
using MessageCallBack = std::function<void(const ConnectionPtr&, Buffer*)>;
using ClosedCallBack = std::function<void(const ConnectionPtr&)>;
using AnyEventCallBack = std::function<void(const ConnectionPtr&)>;
class Connection : public std::enable_shared_from_this<Connection>
{
private:
    ///////////五个channel的事件回调函数///////////
    // 描述符可读事件触发后调用的函数，接收socket数据放到接收缓冲区中，然后调用_message_cbFunc
    void HandleRead()
    {
        // 1、接收socket的数据放到缓冲区
        char buf[65536];
        ssize_t ret = _socket.NonBlockRecv(buf, sizeof(buf));
        if(ret < 0)
        {
            // 出错了，不能直接关闭连接 // TODO
            return ShutdownInLoop();
        }
        // ret==0是没有读取到数据
        _in_buffer.WriteAndPush(buf, ret);

        // 2、调用message_cbFunc
        if(_in_buffer.GetReadableSize() > 0)
        {
            // TODO: 此步干什么？
            // TODO: shared_from_this() 传this原生指针会构造一个新的shared_ptr对象指向同一区域
            _message_cbFunc(shared_from_this(), &_in_buffer);
        }
    }

    // 描述符可写事件触发后调用的函数，将发送缓冲区数据发送
    void HandleWrite()
    {
        // _out_buffer中的数据就是要发送的数据
        ssize_t ret = _socket.NonBlockSend(_out_buffer.GetReadPosition(), _out_buffer.GetReadableSize());
        if(ret < 0)
        {
            if(_in_buffer.GetReadableSize() > 0)
            {
                _message_cbFunc(shared_from_this(), &_in_buffer);
            }
            return ReleaseInLoop(); // 这时候是真正的关闭
        }

        _out_buffer.MoveReadPosition(ret); // 发送成功，将读偏移往后移动!
        if(_out_buffer.GetReadableSize() == 0)
        {
            _channel.DisableWrite(); // 没有数据发送，关闭写事件监控 TODO
            // 如果当前是连接待关闭状态，有数据发完则释放连接，没有则直接释放
            if(_status == DISCONNECTING && _out_buffer.GetReadableSize() == 0) return ReleaseInLoop();
        }
    }

    // 描述符触发挂断事件
    void HandleClose()
    {
        if(_in_buffer.GetReadableSize() > 0)
        {
            _message_cbFunc(shared_from_this(), &_in_buffer);
        }
        return ReleaseInLoop();
    }

    // 描述符触发出错事件
    void HandleError()
    {
        HandleClose();
    }

    // 描述符触发任意事件
    void HandleAnyEvent()
    {
        // 1、刷新连接的活跃度
        if(_active_release) _loop->TimerRefresh(_conn_id); // TODO: _conn_id
        // 2、调用组件使用者的任意事件回调
        if(_any_event_cbFunc) _any_event_cbFunc(shared_from_this());
    }

    // TODO: InLoop?对外提供的接口都要在对应线程执行保证线程安全
    // 连接获取之后，所处的状态下要进行各种设置(启动读监控、调用回调等)
    void EstablishedInLoop() // TODO
    {
        // 1、修改连接状态
        assert(_status == CONNECTING);
        _status = CONNECTED; // 已完成连接!
        // 2、启动读事件监控(不可在构造函数中进行)
        // 一旦启动读事件监控就有可能会立即触发读事件，如果这时候启动了非活跃连接销毁
        _channel.EnableRead();
        // 3、调用回调函数
        if(_connected_cbFunc) _connected_cbFunc(shared_from_this());
    }

    // 实际的释放接口
    void ReleaseInLoop()
    {
        // 1、修改连接状态
         _status = DISCONNECTED;
        // 2、移除连接的事件监控
        _channel.Remove();
        // 3、关闭描述符
        _socket.Close();
        // 4、如果当前定时器队列中还有定时销毁任务应取消
        if(_loop->HasTimer(_conn_id)) CancelInactiveReleaseInLoop(_conn_id /*int sec*/); // TODO: sec填_conn_id?
        // 5、调用关闭回调函数(先关用户再关服务器管理的信息)
        if(_closed_cbFunc) _closed_cbFunc(shared_from_this());
        if(_server_closed_cbFunc) _server_closed_cbFunc(shared_from_this());
    }

    // 并非实际发送窗口，而是把数据放到发送缓冲区，启动可写事件监控
    void SendInLoop(const Buffer buf)
    {
        if(_status == DISCONNECTED) return;
        _out_buffer.WriteBufferAndPush(buf);
        if(_channel.WriteAble()== false) _channel.EnableWrite();
    }

    // 并非实际释放连接操作，还要判断有没有数据待处理 // TODO
    void ShutdownInLoop()
    {
        _status = DISCONNECTING; // 半关闭状态
        if(_in_buffer.GetReadableSize() > 0)
        {
            if(_message_cbFunc) _message_cbFunc(shared_from_this(), &_in_buffer);
        }
        // 要么就是写入数据时出错关闭，要么就是没有待发数据
        if(_out_buffer.GetReadableSize() > 0)
        {
            if(_channel.WriteAble() == false) _channel.EnableWrite();
            // TODO: 打开不发?
        }
        if(_out_buffer.GetReadableSize() == 0) ReleaseInLoop();
    }

    // 启动非活跃连接超时释放
    void EnableInactiveReleaseInLoop(int sec)
    {
        // 1、将判断标志_active_release置为true
        _active_release = true; 
        // 2、添加定时销毁任务(存在则刷新)
        if(_loop->HasTimer(_conn_id)) return _loop->TimerRefresh(_conn_id);
        _loop->TimerAdd(_conn_id, sec, std::bind(&Connection::ReleaseInLoop, this));
    }

    // 取消非活跃连接超时释放
    void CancelInactiveReleaseInLoop(int sec)
    {
        _active_release = false;
        if(_loop->HasTimer(_conn_id)) _loop->TimerCancel(_conn_id);
    }

    void ProtocalSwitchInLoop(const Any& context,
                              const ConnectedCallBack& conn, 
                              const MessageCallBack& msg,     
                              const ClosedCallBack& close, 
                              const AnyEventCallBack& any)
    {
        // SetContext(context);
        _context = context;
        _connected_cbFunc = conn;
        _message_cbFunc = msg;
        _closed_cbFunc = close;
        _any_event_cbFunc = any;
    }
public:
    Connection(uint64_t conn_id, int sockfd, EventLoop* loop)
        : _conn_id(conn_id)
        , _sockfd(sockfd)
        , _loop(loop)
        , _active_release(false)
        , _status(CONNECTING)
        , _socket(_sockfd)
        , _channel(loop, sockfd)
    {
        _channel.SetCloseCallback(std::bind(&Connection::HandleClose, this));
        _channel.SetAnyCallback(std::bind(&Connection::HandleAnyEvent, this));
        _channel.SetReadCallback(std::bind(&Connection::HandleRead, this));
        _channel.SetWriteCallback(std::bind(&Connection::HandleWrite, this));
        _channel.SetErrorCallback(std::bind(&Connection::HandleError, this));
    }
    ~Connection() { DBG_LOG("RELEASE CONNECTION:%p", this); }

    // 获取连接ID
    uint64_t GetId() { return _conn_id; }
    int GetFd() { return _sockfd; }
    ConnStatus GetStatus() { return _status; }
    // 是否处于CONNECTED状态
    bool IsConnected() { return (_status == CONNECTED); }
    // 设置上下文
    void SetContext(const Any& context) { _context = context; }
    // 获取上下文,返回指针每次都是一个上下文
    Any* GetContext() { return &_context;}

    // 设置回调函数
    void SetConnectedCallBack(const ConnectedCallBack& cb) { _connected_cbFunc = cb; }
    void SetMessageCallBack(const MessageCallBack& cb) { _message_cbFunc = cb; }
    void SetClosedCallBack(const ClosedCallBack& cb) { _closed_cbFunc = cb; }
    void SetAnyEventCallBack(const AnyEventCallBack& cb) { _any_event_cbFunc = cb; }
    void SetServerClosedCallBack(const ClosedCallBack& cb) { _server_closed_cbFunc = cb; }

    // 对外提供接口
    // 连接获取之后，设置回调，启动监控等,调用_connected_cbFunc
    void Established() { _loop->RunInLoop(std::bind(&Connection::EstablishedInLoop, this)); }
    // 将数据发送到缓冲区，启动写事件监控
    void Send(const char* data, size_t len)
    {
        // 外界传入的data可能是临时数据，此函数只是将发送操作压入任务池，可能没有被立即执行
        // 因此执行的时候data指向的空间已经被释放
        Buffer buf;
        buf.WriteAndPush(data, len);
        _loop->RunInLoop(std::bind(&Connection::SendInLoop, this, buf));
    }
    // 提供给组件使用者的关闭接口，改变状态，并不实际关闭
    void Shutdown() { _loop->RunInLoop(std::bind(&Connection::ShutdownInLoop, this)); }
    // 启动非活跃连接销毁
    void EnableInactiveRelease(int sec) {_loop->RunInLoop(std::bind(&Connection::EnableInactiveReleaseInLoop, this, sec));}
    // 取消非活跃连接销毁
    void CancelInactiveRelease(int sec) {_loop->RunInLoop(std::bind(&Connection::CancelInactiveReleaseInLoop, this, sec));}
    // 协议切换--重置上下文以及阶段性回调处理函数--非线程安全--必须在EventLoop线程中立即执行
    // 防备新事件触发，而协议还未切换，导致数据按原协议进行处理
    void ProtocalSwitch(const Any& context,
                        const ConnectedCallBack& conn, 
                        const MessageCallBack& msg,       
                        const ClosedCallBack& close,
                        const AnyEventCallBack& any)
    {
        _loop->AssertInLoop();
        _loop->RunInLoop(std::bind(&Connection::ProtocalSwitchInLoop, this, context, conn, msg, close, any));
    }

private:
    uint64_t _conn_id; // 连接的唯一ID
    // uint64_t _timer_id; // 定时器ID，必须唯一，此处简化等于_conn_id
    int _sockfd; // 连接关联的文件描述符
    bool _active_release; // 是否启动连接非活跃销毁标志位，默认false(长连接)
    EventLoop* _loop; // 连接所关联的eventloop(一个线程)
    ConnStatus _status; // 连接状态
    Socket _socket; // 套接字操作管理
    Channel _channel; // 连接的事件管理
    Buffer _in_buffer; // 输入缓冲区--存放从socket中读取的数据
    Buffer _out_buffer; // 输出缓冲区--存放要发送的数据
    Any _context; // 请求的接收处理上下文
    
    // 回调函数(组件使用者设置)
    ConnectedCallBack _connected_cbFunc;
    MessageCallBack _message_cbFunc;
    ClosedCallBack _closed_cbFunc;
    AnyEventCallBack _any_event_cbFunc;
    // 组件内设置，服务器组件内会管理所有连接 // TODO
    ClosedCallBack _server_closed_cbFunc;
};

using AcceptorCallBack = std::function<void(int)>;
class Acceptor
{
private:
    // 监听套接字的读事件回调处理函数--获取新连接，调用_accept_cbFunc回调函数进行新连接处理
    void HandleRead()
    {
        int newfd = _lst_socket.Accept();
        if(newfd < 0)
        {
            DBG_LOG("LISTEN SOCKET ACCEPT FAILED!");
            return;
        }
        if(_accept_cbFunc) _accept_cbFunc(newfd);
    }

    int CreateServer(int port) // TODO: 返回一个sockfd?
    {
        bool ret = _lst_socket.CreateServer(port);
        assert(ret == true);
        return _lst_socket.GetFd();
    }
public:
    Acceptor(EventLoop* loop, int port)
        : _lst_socket(CreateServer(port))
        , _loop(loop)
        , _channel(_loop, _lst_socket.GetFd())
    {
        _channel.SetReadCallback(std::bind(&Acceptor::HandleRead, this));
    }

    void SetAcceptCallBack(const AcceptorCallBack& cb) { _accept_cbFunc = cb; }
    void Listen() { _channel.EnableRead(); } // 不可在未设置回调函数前监听
private:
    Socket _lst_socket;
    EventLoop* _loop; // 用于对监听套接字进行事件监控
    Channel _channel; // 用于对监听套接字进行事件管理  // TODO: 事件监控 vs 事件管理?

    AcceptorCallBack _accept_cbFunc;
};

// Channel类前声明Poller只知道有Poller类，但不知道里面的成员
// 所以需要在Poller类之后进行类外实现
void Channel::Update() { _loop->UpdateEvent(this); } // TODO: 后边会调用EventLoop接口
void Channel::Remove() { _loop->RemoveEvent(this); }

void TimeWheel::TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cbFunc) 
{ _loop->RunInLoop(std::bind(&TimeWheel::TimerAddInLoop, this, id, delay, cbFunc)); }

void TimeWheel::TimerRefresh(uint64_t id)
{ _loop->RunInLoop(std::bind(&TimeWheel::TimerRefreshInLoop, this, id)); }

void TimeWheel::TimerCancel(uint64_t id)
{ _loop->RunInLoop(std::bind(&TimeWheel::TimerCancelInLoop, this, id)); }