#include "echo.hpp"

int main()
{
    EchoServer echo_server(8080);
    echo_server.Start();
    return 0;
}