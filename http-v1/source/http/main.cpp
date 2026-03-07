#include "http.hpp"

#define WWWROOT "./wwwroot/"

std::string RequestStr(const HttpRequest& request)
{
    std::stringstream ss;
    ss << request._method << " " << request._path << " " << request._version << "\r\n";
    for(auto& it : request._parameters) ss << it.first << ": " << it.second << "\r\n";
    for(auto& head : request._headers) ss << head.first << ": " << head.second << "\r\n";
    ss << "\r\n";
    ss << request._body;
    return ss.str();
}

void Hello(const HttpRequest& request, HttpResponse* response)
{
    response->SetContent(RequestStr(request), "text/plain");
}
void Login(const HttpRequest& request, HttpResponse* response)
{
    response->SetContent(RequestStr(request), "text/plain");
}
void PutFile(const HttpRequest& request, HttpResponse* response)
{
    std::string pathname = WWWROOT + request._path;
    Util::WriteFile(pathname, request._body);
}
void DelFile(const HttpRequest& request, HttpResponse* response)
{
    response->SetContent(RequestStr(request), "text/plain");
}

int main()
{
    HttpServer server(8088);
    server.SetThreadCount(2);
    server.SetBaseDir(WWWROOT); // 设置静态资源根目录
    server.SetGet("/hello", Hello);
    server.SetPost("/login", Login);
    server.SetPost("/test.txt", PutFile);
    server.SetPost("/test.txt", DelFile);
    server.Listen();
    return 0;
}