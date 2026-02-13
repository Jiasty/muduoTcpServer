#include <iostream>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <ctime>

#include <string>
#include <vector>


#define DEFAULT_BUFFER_SIZE 1024 // TODO: C++为何还要用宏?

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
    char* Begin() const
    {
        return (char*)&*_buffer.begin();
    }
    // 获取当前写位置地址
    char* GetWritePosition() const
    {
        // 起始地址 + 写偏移
        return Begin() + _write_index;
    }
    // 获取当前读位置地址
    char* GetReadPosition() const
    {
        return Begin() + _read_index;
    }

    // 获取可读空间大小
    uint64_t GetReadableSize() const
    {
        return _write_index - _read_index;
    }

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
    uint64_t GetTailWritableSize()
    {
        return _buffer.size() - _write_index;
    }
    // 获取后沿可写空间大小(可读位置往前的空间)
    uint64_t GetHeadWritableSize()
    {
        return _read_index;
    }

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

    void WriteString(const std::string& data)
    {
        Write(data.c_str(), data.size());
    }
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

