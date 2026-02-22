#include <iostream>
#include <cstdint>
#include <functional>
#include <memory>

#include <vector>
#include <unordered_map>

#include <unistd.h> 

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
public:
    TimeWheel()
        : _tick(0)
        , _capacity(60) // 60个槽(秒级)
        , _wheel(_capacity) // 声明顺序决定初始化顺序，_capacity先于_wheel声明
    {}

    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cbFunc)
    {
        // 添加定时任务ptr
        TimerTaskPtr ptr(new TimerTask(id, delay, cbFunc));
        ptr->SetRelease(std::bind(&TimeWheel::RemoveTimer, this, id)); // 绑定成员函数时加&和::
        _timers[id] = TimerTaskWeakPtr(ptr); // 一定是weakptr，存入哈希表，方便后续查找

        _wheel[(_tick + delay) % _capacity].emplace_back(ptr);
    }

    void TimerRefresh(uint64_t id)
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

    void TimerCancel(uint64_t id)
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

    // 每秒执行一次
    void RunTimerTask()
    {
        _tick = (_tick + 1) % _capacity; // 指针前移一格
        _wheel[_tick].clear(); // 清空该槽位的定时任务ptr，触发析构函数执行任务
    }


private:
    void RemoveTimer(uint64_t id)
    {
        auto it = _timers.find(id);
        if (it != _timers.end())
        {
            _timers.erase(it);
        }
    }

private:
    int _tick; // 当前指针位置,指到哪就执行哪个槽的定时任务，然后释放
    int _capacity; // 时间轮槽的数量
    std::vector<std::vector<TimerTaskPtr>> _wheel; // 秒级时间轮
    
    std::unordered_map<uint64_t, TimerTaskWeakPtr> _timers; // 任务ID到任务对象ptr的映射,为了找到定时器
};


class Test
{
public:
    Test()
    {
        std::cout << "Test()" << std::endl;
    }

    ~Test()
    {
        std::cout << "~Test()" << std::endl;
    }
};

void DeleteTest(Test* t)
{
    delete t;
}

int main()
{
    TimeWheel timeWheel;

    Test* t = new Test();
    timeWheel.TimerAdd(1, 5, std::bind(DeleteTest, t));

    for(int i = 0; i < 5; i++)
    {
        timeWheel.TimerRefresh(1); // 刷新定时任务
        timeWheel.RunTimerTask(); // 秒针要时时刻刻移动
        std::cout << "刷新一次定时任务" << std::endl;
        sleep(1);
    }

    // timeWheel.TimerCancel(1); // 取消定时任务 DeleteTest()
    
    while(1)
    {
        std::cout << "*****************************" << std::endl;
        timeWheel.RunTimerTask(); // 秒针要时时刻刻移动
        sleep(1);
    }

    return 0;
}