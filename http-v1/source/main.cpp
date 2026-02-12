#include "server.hpp"
#include <unistd.h>

int main()
{
    Buffer buf;

    std::string str = "hello!";
    printf("开始地址:%p\n", buf.Begin());
    printf("写位置地址:%p\n", buf.GetWritePosition());
    printf("读位置地址:%p\n", buf.GetReadPosition());
    buf.WriteStringAndPush(str);
    buf.Print();
    printf("写位置地址:%p\n", buf.GetWritePosition());
    printf("读位置地址:%p\n", buf.GetReadPosition());
    std::cout << "可读空间大小" << buf.GetReadableSize() << std::endl;

    std::cout << "可写位置往后的空闲空间" << buf.GetTailWritableSize() << std::endl;
    std::cout << "可写位置往前的空闲空间" << buf.GetHeadWritableSize() << std::endl;

    std::cout << "-------------------------------------------------" << std::endl;

    Buffer buf2;
    const char* s = "aaa";
    printf("写位置地址:%p\n", buf2.GetWritePosition());
    buf2.WriteAndPush(s, strlen(s));
    printf("写位置地址:%p\n", buf2.GetWritePosition());
    buf2.Print();


    std::string tmp = buf.ReadToStringAndPop(buf.GetReadableSize());
    std::cout << tmp << std::endl;
    std::cout << buf.GetReadableSize() << std::endl;

    

    return 0;
}