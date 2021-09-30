# CCN_encrypt
ENCRYPT CREDIT CARD NUMBER by FORMAT PRESERVING ALGORITHM


EXECUTE in LINUX environment
1) Execute below command to get the code. (Note: Internet connection should be there to get this code from GIT repositoty)

  git clone https://github.com/snehamaganahalli/CCN_encrypt.git

2) I have used OPENSSL LIBRARY to create AES Black box. Therefore please install OPSENSSL by below command. Without OPENSSL the program will not work.
   The below command runs in super user mode. It asks the password for super user and the installs OPENSSL LIBRARY.
   (Note: Internet connection should be there to get this Library)

sudo apt-get install libssl-dev

3) How to compile? Execute the below command

make

4) How to Execute

./main "2B7E151628AED2A6ABF7158809CF4F3C" "1234567890123456" "1"

i.e. ./main (AES KEY) (Credit Card number) (0/1: 1 to Encrypt 0 to Decrypt)
