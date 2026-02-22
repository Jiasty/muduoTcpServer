#include <iostream>
#include <regex>

#include <string>

void test_regex()
{
    std::string src = "phone_number:123456"; // 原始字符串


    std::regex e("phone_number:(\\d+)"); // 正则表达式匹配规则: 匹配以phone_number:起始的后面的数字部分
    std::smatch sm; // 存放提取的数据

    bool ret = std::regex_match(src, sm, e);
    if(ret == false)
    {
        std::cout << "正则表达式匹配失败" << std::endl;
        return;
    }
    
    for(auto &s : sm)
    {
        // 原始字符串也会存入sm中(sm[0])
        std::cout << s << std::endl;
    }
}


void test_httpRequest()
{
    std::string src = "GET /api/v1/users?id=1001&lang=zh HTTP/1.1\r\n"; // 原始HTTP请求字符串
    std::smatch sm;

    // http请求方法的匹配 GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH
    std::regex e("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?"); // 匹配HTTP请求方法
    //"(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)"  表示匹配并提取其中任意一个
    //"([^?]*)"  表示匹配并提取非?字符0次或多次
    //"\\?(.*) " 表示匹配?后面的所有字符并提取，直到遇到空格为止
    //"(HTTP/1\\.[01])" 表示匹配并提取HTTP版本号，1.0或1.1(.要转义)
    //"(?:\n|\r\n)?" (?: )表示匹配HTTP请求行的结尾，可以是\n或\r\n，但不提取.最后的?表示前面的内容出现0次或1次
    
    bool ret = std::regex_match(src, sm, e);

    if(ret == false)
    {
        std::cout << "HTTP请求方法匹配失败" << std::endl;
        return;
    }
    for(auto &s : sm)
    {
        std::cout << s << std::endl;
    }
}



int main()
{
    // test_regex();
    test_httpRequest();


    return 0;
}