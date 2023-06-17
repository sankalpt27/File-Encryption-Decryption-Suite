all: ufsend ufrec

ufsend:
	g++ -o ufsend ufsend.cpp  -lcrypto -fpermissive 

ufrec:
	g++ -o ufrec ufrec.cpp -lcrypto -fpermissive 