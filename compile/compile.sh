mkdir -p ./build

CPPFLAGS="-std=c++11 -fno-rtti -fno-exceptions -Werror -Wall"

if [ "$1" = "debug" ]; then
    CPPFLAGS+=" -ggdb3"
elif [ "$1" = "release" ]; then
    CPPFLAGS+=" -O3"
elif [ "$1" = "" ]; then
    echo "Expected argument (debug/release)"
    exit
fi

gcc $CPPFLAGS \
    ./src/main.cpp \
    -o ./build/server \
    -fvisibility=hidden