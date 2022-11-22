g++ -o $1 $1.cpp -lSPDZ -I../ -I../mpir -L../ -L../local/lib ../local/lib/*.so
./$1