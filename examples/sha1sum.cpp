#include <marlo/sha1.hpp>
#include <iostream>

int main(int argc, char** argv)
{
    std::string s;
    for (int i = 1; i < argc; i++) {
        s.append(argv[i]).push_back(' ');
    }

    if (!s.empty()) {
        s.pop_back();
    }
    std::cout << marlo::sha1::eval(s) << '\n';
    return 0;
}
