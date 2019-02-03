mkdir -p ./build

APP_NAME="km_server"

CPPFLAGS="-m64 -std=c++11 -fno-rtti -fno-exceptions -Werror -Wall"
INCLUDEDIRS="-I../libs/include/"

LINKFLAGS="-fvisibility=hidden"
LIBDIRS="-L../libs/lib/"
LIBS="-lexpat"

if [ "$1" = "debug" ]; then
    CPPFLAGS+=" -ggdb3"
elif [ "$1" = "release" ]; then
    CPPFLAGS+=" -O3"
elif [ "$1" = "" ]; then
    echo "Expected argument (debug/release)"
    exit
fi

gcc $CPPFLAGS $INCLUDEDIRS \
    ./src/main.cpp \
    -o ./build/$APP_NAME \
    $LINKFLAGS $LIBDIRS $LIBS
