if [ "$2" != "nocompile" ]; then
    g++ -o $1 $1.cpp -lSPDZ -I../ -I../mpir -L../ -L../local/lib ../local/lib/*.so -g -std=c++11
fi

if [ "$2" != "norun" ]; then
    ./$1
fi