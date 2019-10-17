mkdir -p ./build

APP_NAME="km_server"

CPPFLAGS="-m64 -std=c++11 -fno-rtti -fno-exceptions -Werror -Wall"
DEFINES="-DGAME_SLOW=0 -DGAME_INTERNAL=0"
INCLUDEDIRS="-I../libs/include -I./libs/external/stb_image-2.23/include -I./libs/external/stb_sprintf-1.06/include -I./libs/internal/km_common"

LINKFLAGS="-fvisibility=hidden"
LIBDIRS="-L../libs/lib"
LIBS="-lssl -lcrypto -lpthread -ldl -lexpat"

if [ "$1" = "debug" ]; then
    CPPFLAGS+=" -ggdb3"
elif [ "$1" = "release" ]; then
    CPPFLAGS+=" -O3"
elif [ "$1" = "" ]; then
    echo "Expected argument (debug/release)"
    exit
fi

g++ $DEFINES $CPPFLAGS $INCLUDEDIRS \
    ./src/main.cpp \
    -o ./build/$APP_NAME \
    $LINKFLAGS $LIBDIRS $LIBS
