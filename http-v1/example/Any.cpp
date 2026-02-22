#include <iostream>
#include <typeinfo>  // TODO
#include <string>
#include <any>

namespace Jiasty
{
    class any
    {
    public:
        any()
            :_content(nullptr)
        {}

        template<class T>
        any(const T& val)
            :_content(new placeholder<T>(val))
        {}

        any(const any& other)
            :_content(other._content ? other._content->clone() : nullptr) // 构造新对象，不是直接复制原对象指针
        {}

        ~any()
        {
            delete _content;
        }

        any& Swap(any& other)
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
        any& operator=(const T& val)
        {
            any(val).Swap(*this); // 先构造一个临时对象，再交换内容
            return *this;
        }

        any& operator=(const any& other)
        {
            any(other).Swap(*this); // 先构造一个临时对象，再交换内容
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

}

class Test
{
public:
    Test()
    {
        std::cout << "Test()" << std::endl;
    }

    Test(const Test& t)
    {
        std::cout << "Test(const Test& t)" << std::endl;
    }

    ~Test()
    {
        std::cout << "~Test()" << std::endl;
    }
};

void test_cpp17Any()
{
    std::any a = 22;
    int* pa = std::any_cast<int>(&a);
    std::cout << *pa << std::endl;

    std::any b = std::string("Hello, C++17 Any!");
    std::string* pb = std::any_cast<std::string>(&b);
    std::cout << *pb << std::endl;

    // std::any c = "asda"; 
    // 不能直接用字符串字面值初始化std::any对象 // TODO
}


int main()
{
    Jiasty::any a = 11;
    int* pa = a.Get<int>();
    std::cout << *pa << std::endl;

    Jiasty::any b = std::string("Hello, World!");
    std::string* pb = b.Get<std::string>();
    std::cout << *pb << std::endl;

    {
        Jiasty::any c = Test();
        Test* pc = c.Get<Test>();
    }

    std::cout << "-----------------" << std::endl;
    test_cpp17Any();
}