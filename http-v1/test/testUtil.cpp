#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../source/server.hpp"

static size_t Split(const std::string& src, const std::string& sep, std::vector<std::string>* array)
{
    size_t offset = 0;
    while(offset < src.size())
    {
        size_t pos = src.find(sep, offset); // TODO: find
        if(pos == std::string::npos) // TODO: npos
        {
            // 没找到特定字符,将剩余部分当子串
            if(pos == src.size()) break;
            array->emplace_back(src.substr(offset)); // TODO: substr
            return array->size();
        }
        if(pos == offset)
        {
            offset = pos + sep.size();
            continue;
        }
        array->emplace_back(src.substr(offset, pos - offset));
        offset = pos + sep.size();
    }
    return array->size();
}

// 读取文件所有内容放到Buffer
static bool ReadFile(const std::string& filename, std::string* buf)
{
    std::ifstream ifs(filename, std::ios::binary);
    if(ifs.is_open() == false)
    {
        ERR_LOG("OPEN %s FAILED!", filename.c_str());
        return false;
    }

    size_t fsize = 0;
    ifs.seekg(0, ifs.end); // TODO: 跳转读写位置到末尾
    fsize = ifs.tellg(); // TODO: 获取当前读写位置相对于起始位置的偏移量
    ifs.seekg(0, ifs.beg);
    buf->resize(fsize);
    ifs.read(&(*buf)[0], fsize);
    if(ifs.good() == false)
    {
        ERR_LOG("READ %s FAILED!", filename.c_str());
        ifs.close();
        return false;
    }
    ifs.close();
    return true;
}
// 向文件写入数据
static bool WriteFile(const std::string& filename, const std::string& buf)
{
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc); // TODO: trunc
    if(ofs.is_open() == false)
    {
        ERR_LOG("OPEN %s FAILED!", filename.c_str());
        return false;
    }
    ofs.write(buf.c_str(), buf.size());
    if(ofs.good() == false)
    {
        ERR_LOG("WRITE %s FAILED!", filename.c_str());
        ofs.close();
        return false;
    }
    ofs.close();
    return true;
}
// URL编码
static std::string UrlEncode(const std::string& url, bool convert_space_to_plus)
{
    std::string ret;
    for(auto& c : url)
    {
        if(c == '.' || c == '-' || c == '_' || c == '~' || isalnum(c))
        {
            ret += c;
            continue;
        }
        if(c == ' ' && convert_space_to_plus)
        {
            ret += '+';
            continue;
        }
        // 剩下的字符都需要转换为 %HH 格式
        char tmp[4] = {0};
        snprintf(tmp, 4, "%%%02X", c); // TODO: snprintf
        ret += tmp;
    }
    return ret;
}

// URL解码
static char HextoI(char c)
{
    if(c >= '0' && c <= '9') return c - '0';
    else if(c >= 'a' && c <= 'z') return c - 'a' + 10;
    else if(c >= 'A' && c <= 'Z') return c - 'A' + 10;
    return -1;
}
static std::string UrlDecode(const std::string& url, bool convert_plus_to_space)
{
    // 遇到了%其后的两个字符转换为数字，第一个字符左移4位(乘16)加上第二个数字
    std::string ret;
    for(int i = 0; i < url.size(); i++)
    {
        if(url[i] == '+' && convert_plus_to_space)
        {
            ret += ' ';
            continue;
        }
        if(url[i] == '%' && (i + 2) < url.size())
        {
            char v1 = HextoI(url[i + 1]);
            char v2 = HextoI(url[i + 2]);
            char v = (v1 << 4) + v2;
            ret += v;
            i += 2;
            continue;
        }
        ret += url[i];
    }
    return ret;
}

// 响应状态码的描述信息获取
static std::string StatusDesc(int status)
{
    std::unordered_map<int, std::string> _status_msg = {
        {100,  "Continue"},
        {101,  "Switching Protocol"},
        {102,  "Processing"},
        {103,  "Early Hints"},
        {200,  "OK"},
        {201,  "Created"},
        {202,  "Accepted"},
        {203,  "Non-Authoritative Information"},
        {204,  "No Content"},
        {205,  "Reset Content"},
        {206,  "Partial Content"},
        {207,  "Multi-Status"},
        {208,  "Already Reported"},
        {226,  "IM Used"},
        {300,  "Multiple Choice"},
        {301,  "Moved Permanently"},
        {302,  "Found"},
        {303,  "See Other"},
        {304,  "Not Modified"},
        {305,  "Use Proxy"},
        {306,  "unused"},
        {307,  "Temporary Redirect"},
        {308,  "Permanent Redirect"},
        {400,  "Bad Request"},
        {401,  "Unauthorized"},
        {402,  "Payment Required"},
        {403,  "Forbidden"},
        {404,  "Not Found"},
        {405,  "Method Not Allowed"},
        {406,  "Not Acceptable"},
        {407,  "Proxy Authentication Required"},
        {408,  "Request Timeout"},
        {409,  "Conflict"},
        {410,  "Gone"},
        {411,  "Length Required"},
        {412,  "Precondition Failed"},
        {413,  "Payload Too Large"},
        {414,  "URI Too Long"},
        {415,  "Unsupported Media Type"},
        {416,  "Range Not Satisfiable"},
        {417,  "Expectation Failed"},
        {418,  "I'm a teapot"},
        {421,  "Misdirected Request"},
        {422,  "Unprocessable Entity"},
        {423,  "Locked"},
        {424,  "Failed Dependency"},
        {425,  "Too Early"},
        {426,  "Upgrade Required"},
        {428,  "Precondition Required"},
        {429,  "Too Many Requests"},
        {431,  "Request Header Fields Too Large"},
        {451,  "Unavailable For Legal Reasons"},
        {501,  "Not Implemented"},
        {502,  "Bad Gateway"},
        {503,  "Service Unavailable"},
        {504,  "Gateway Timeout"},
        {505,  "HTTP Version Not Supported"},
        {506,  "Variant Also Negotiates"},
        {507,  "Insufficient Storage"},
        {508,  "Loop Detected"},
        {510,  "Not Extended"},
        {511,  "Network Authentication Required"}
    };
    auto it = _status_msg.find(status);
    if(it == _status_msg.end()) return "UnKnown";
    return it->second;
}
// 根据文件后缀名获取文件mime // TODO: mime
static std::string ExtMime(const std::string& filename)
{
    std::unordered_map<std::string, std::string> _mime_desc = {
        {".aac",        "audio/aac"},
        {".abw",        "application/x-abiword"},
        {".arc",        "application/x-freearc"},
        {".avi",        "video/x-msvideo"},
        {".azw",        "application/vnd.amazon.ebook"},
        {".bin",        "application/octet-stream"},
        {".bmp",        "image/bmp"},
        {".bz",         "application/x-bzip"},
        {".bz2",        "application/x-bzip2"},
        {".csh",        "application/x-csh"},
        {".css",        "text/css"},
        {".csv",        "text/csv"},
        {".doc",        "application/msword"},
        {".docx",       "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".eot",        "application/vnd.ms-fontobject"},
        {".epub",       "application/epub+zip"},
        {".gif",        "image/gif"},
        {".htm",        "text/html"},
        {".html",       "text/html"},
        {".ico",        "image/vnd.microsoft.icon"},
        {".ics",        "text/calendar"},
        {".jar",        "application/java-archive"},
        {".jpeg",       "image/jpeg"},
        {".jpg",        "image/jpeg"},
        {".js",         "text/javascript"},
        {".json",       "application/json"},
        {".jsonld",     "application/ld+json"},
        {".mid",        "audio/midi"},
        {".midi",       "audio/x-midi"},
        {".mjs",        "text/javascript"},
        {".mp3",        "audio/mpeg"},
        {".mpeg",       "video/mpeg"},
        {".mpkg",       "application/vnd.apple.installer+xml"},
        {".odp",        "application/vnd.oasis.opendocument.presentation"},
        {".ods",        "application/vnd.oasis.opendocument.spreadsheet"},
        {".odt",        "application/vnd.oasis.opendocument.text"},
        {".oga",        "audio/ogg"},
        {".ogv",        "video/ogg"},
        {".ogx",        "application/ogg"},
        {".otf",        "font/otf"},
        {".png",        "image/png"},
        {".pdf",        "application/pdf"},
        {".ppt",        "application/vnd.ms-powerpoint"},
        {".pptx",       "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {".rar",        "application/x-rar-compressed"},
        {".rtf",        "application/rtf"},
        {".sh",         "application/x-sh"},
        {".svg",        "image/svg+xml"},
        {".swf",        "application/x-shockwave-flash"},
        {".tar",        "application/x-tar"},
        {".tif",        "image/tiff"},
        {".tiff",       "image/tiff"},
        {".ttf",        "font/ttf"},
        {".txt",        "text/plain"},
        {".vsd",        "application/vnd.visio"},
        {".wav",        "audio/wav"},
        {".weba",       "audio/webm"},
        {".webm",       "video/webm"},
        {".webp",       "image/webp"},
        {".woff",       "font/woff"},
        {".woff2",      "font/woff2"},
        {".xhtml",      "application/xhtml+xml"},
        {".xls",        "application/vnd.ms-excel"},
        {".xlsx",       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".xml",        "application/xml"},
        {".xul",        "application/vnd.mozilla.xul+xml"},
        {".zip",        "application/zip"},
        {".3gp",        "video/3gpp"},
        {".3g2",        "video/3gpp2"},
        {".7z",         "application/x-7z-compressed"}
    };

    size_t pos = filename.find_last_of('.');
    if(pos == std::string::npos) return "application/octet-stream"; // 文件为二进制流
    
    std::string tmp = filename.substr(pos);
    auto it = _mime_desc.find(tmp);
    if(it == _mime_desc.end()) return "application/octet-stream";
    return it->second;
}
// 判断一个文件是否是目录
static bool IsDirectory(const std::string filename)
{
    struct stat st;
    int ret = stat(filename.c_str(), &st);
    if(ret < 0)
    {
        ERR_LOG("GET STAT FAILED!");
        return false;
    }
    return S_ISDIR(st.st_mode); // TODO: S_ISDIR  st_mode
}
// 判断一个文件是否是普通文件
static bool IsRegular(const std::string filename)
{
    struct stat st;
    int ret = stat(filename.c_str(), &st);
    if(ret < 0)
    {
        ERR_LOG("GET STAT FAILED!");
        return false;
    }
    return S_ISREG(st.st_mode); // TODO: S_ISREG  st_mode
}
// 判断http请求路径是否合法
static bool ValidPath(const std::string& path)
{
    //思想：按照/进行路径分割，根据有多少子目录，计算目录深度，有多少层，深度不能小于0
    std::vector<std::string> subdir;
    Split(path, "/", &subdir);
    int level = 0; // ./算第0层
    for(auto& dir : subdir)
    {
        if(dir == "..")
        {
            level--;
            if(level < 0) return false;
            continue;
        }
        level++;
    }
    return true;
}
//////////////////////////
void testSplit()
{
    std::string src = "abc,,,,,def,ghi,";
    std::string sep = ",";
    std::vector<std::string> array;
    Split(src, sep, &array);
    for(auto& str : array)
    {
        std::cout << "[" << str << "]" << std::endl;
    }

}
void testReadFile()
{
    std::string buf;
    bool ret = ReadFile("./tcpClient.cpp", &buf);
    if(!ret) return;
    std::cout << buf.c_str() << std::endl;
}
void testWriteFile()
{

    std::string buf;
    bool ret = ReadFile("./tcpClient.cpp", &buf);
    if(!ret) return;
    ret = WriteFile("./txt.cpp", buf);
    if(!ret) return;
}
void testUrlEncode()
{
    std::string str = "C++";
    // std::string str = "C  ";
    std::string ret = UrlEncode(str, false);
    std::string tmp = UrlDecode(ret, false);
    std::cout << ret << std::endl;
    std::cout << tmp << std::endl;
}

void testStatusAndMime()
{
    std::cout << StatusDesc(404) << std::endl;
    std::cout << ExtMime("test.txt") << std::endl;
    std::cout << ExtMime("test.cpp") << std::endl;
    std::cout << ExtMime("test.png") << std::endl;
    std::cout << ExtMime("test.tar.zip") << std::endl;
}

void testIsDirOrReg()
{
    std::cout << IsDirectory("testdir") << std::endl;
    std::cout << IsDirectory("server.cpp") << std::endl;
    std::cout << IsRegular("testdir") << std::endl;
    std::cout << IsRegular("server.cpp") << std::endl;
}

void testValidPath()
{
    std::string url1 = "/index.html";
    std::string url2 = "/../index.html"; // TODO: ./开头为何就打印1?
    std::cout << ValidPath(url1) << std::endl;
    std::cout << ValidPath(url2) << std::endl;
}

int main()
{
    // testSplit();
    // testReadFile();
    // testWriteFile();
    // testUrlEncode();
    // testStatusAndMime();
    // testIsDirOrReg();
    testValidPath();
    
    return 0;
}