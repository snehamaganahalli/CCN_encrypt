# CCN_encrypt
ENCRYPT CREDIT CARD NUMBER by FORMAT PRESERVING ALGORITHM


EXECUTE in LINUX environment

1) I have used OPENSSL LIBRARY to create AES Black box. Therefore please install OPSENSSL by below command. Without OPENSSL the program will not work.
   The below command runs in super user mode. It asks the password for super user and the installs OPENSSL LIBRARY.

sudo apt-get install libssl-dev

2) How to compile
make

3) How to Execute
./main "2B7E151628AED2A6ABF7158809CF4F3C" "1234567890123456"

i.e. ./main <AES KEY> <Credit Card number>
