mkdir -p ./build

APP_NAME="km_server"

CPPFLAGS="-m64 -std=c++11 -fno-rtti -fno-exceptions -Werror -Wall"

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
    -o ./build/$APP_NAME \
    -fvisibility=hidden