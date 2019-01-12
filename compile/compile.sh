mkdir -p ./build

gcc -std=c++11 -ggdb3 -fno-rtti -fno-exceptions -Werror -Wall \
    ./src/main.cpp \
    -o ./build/server \
    -fvisibility=hidden