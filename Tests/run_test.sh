if [ "$1" == "" ]; 
then
    echo "Usage:   $0 filename [norun|nocompile]"
    echo ""
    echo "Example: $0 dzkp-ring-Z2k"
    echo "         $0 dzkp-ring-Z2k nocompile"

else

    if [ "$2" != "nocompile" ]; 
    then
        g++ -o $1 $1.cpp -lSPDZ -I../ -I../mpir -L../ -L../local/lib ../local/lib/*.so -g -std=c++11
    fi

    if [ "$2" != "norun" ]; 
    then
        ./$1
    fi
fi