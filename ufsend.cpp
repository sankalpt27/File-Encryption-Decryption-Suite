#include<iostream>
#include<openssl/ssl.h>
#include<openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include<fstream>
#include<string>
#include<filesystem>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include<stdio.h>
#include<stdlib.h>


using namespace std;
namespace fs = filesystem;


//Function to create password
char* createpassword()
{
    printf("Create a Password\n");
    char* pwd = new char[1024];
    cin >> pwd;
    return pwd;
}

//Generating random iv using openssl library
unsigned char* randomivgenerator()
{
    unsigned char *iv;
    iv = (unsigned char *)malloc(sizeof(char)*32);
    RAND_bytes(iv, 16);                                 // 16 bit IV
    return iv;
}

//Key generator function 
unsigned char* keygenerator(const char* pwd, const unsigned char* salt)
{
    int keylen = 32;                                    //defining key length
    //unsigned char out[32];
    unsigned char *out;
    out = (unsigned char *)malloc(sizeof(char)*32);
    unsigned int iterations = 4096;                     // define iterations
    PKCS5_PBKDF2_HMAC(pwd, strlen(pwd),
                      salt, strlen(salt), iterations,
                      EVP_sha3_256(),
                      keylen, out);
    
    return out;

}

//Encrytion from openssl library
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        cout<<"error1";

    /*
     * Initialise the encryption operation. Here, using EVP AES 256 GCM as mentioned in the assignment 
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        cout<<"error2";

    /*
      Provide the message to be encrypted, and obtain the encrypted output.
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        cout<<"error3";
    ciphertext_len = len;

    /*
     * Finalise the encryption. 
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        cout<<"error4";
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}



//Code to get port 
int get_ip_port(char *address, char *ip)
{
    char delimiter = ':';
    int i=0;
    int j=0;
    char *portstring = new char[30];
    while(address[i] != delimiter)
    {
        ip[i]=address[i];
        i++;
    }
    ip[i+1]='\0';
    i=i+1;
    while(address[i] != '\0')
        {
            portstring[j] = address[i];
            i++;
            j++;
        }
    int port = atoi(portstring);
    return port;
}


int main(int argc, char** argv)
{
    char *userpassword;
    char *address = new char[9999]; 
    char *ip=new char[9999];
    int port;
    const unsigned char *salt = "SodiumChloride";
    unsigned char *key,*iv;
    char *inputfilename = argv[1];
    char *encryptedfilename = new char[99999];
    char iv_filename[30] = "iv.txt";
    strcpy(encryptedfilename,inputfilename);
    strcat(encryptedfilename,".ufsec");
    if (fs::exists(encryptedfilename))
    {
        cout << "File Already Exists" << endl;
        return 33;
    }
    userpassword = createpassword();
    char *inputfiledata;
    int inputdatalength;
    char *filetransfer_switch = argv[2];
    unsigned char ciphertext[99999];

    ifstream inputfile(inputfilename);
    inputfile.seekg(0,inputfile.end);
    inputdatalength = inputfile.tellg();
    inputfile.seekg(0,inputfile.beg);

    inputfiledata = new char[inputdatalength];
    inputfile.read(inputfiledata,inputdatalength);

    unsigned char *plaintext = (unsigned char *)inputfiledata;
    

    key = keygenerator(userpassword,salt);
    printf("Key : ");
    for (size_t i=0; i<32; ++i)
        printf("%02x ", key[i]);
    printf("\n");

    
    iv = randomivgenerator();
    printf("IV : \n");
    for (size_t i=0; i<16; ++i)
        printf("%02x ", iv[i]);
    printf("\n");
    


    int ciphertext_len = encrypt(plaintext,inputdatalength,key, iv, ciphertext);
    printf("cipher text is : \n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len); 

    // cout << filetransfer_switch;
    if(strcmp(filetransfer_switch,"-d") == 0)
    {  
        address = argv[3];
        port = get_ip_port(address,ip);
        //cout << ip << "\n";
        //cout << port << "\n";
        cout << "Transmitting to " << ip << ":" << port << endl;
        
        int sock = 0, valrecv, client_fd;
        struct sockaddr_in serv_addr;
        char *ciphermessage = (char *)ciphertext;
        // char *ivmessage = (char *)iv;
        char buffer[65535] = { 0 };
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
            return -1;
        }
    
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = inet_addr(ip);
  
    if ((client_fd
         = connect(sock, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    send(sock, iv, 16, 0);

    send(sock, ciphermessage, ciphertext_len,0);
    printf("ciphertext sent\n");
    close(client_fd);

    }
    else if(strcmp(filetransfer_switch,"-l") == 0)
    {
        ofstream encryptedfile(encryptedfilename,ios::binary);
        // encryptedfile << iv << endl;
        encryptedfile.write((const char *)ciphertext,ciphertext_len);
        encryptedfile.flush();
        encryptedfile.close();

        ofstream ivfile(iv_filename, ios::binary);
        ivfile.write((const char*)iv,32);
        ivfile.flush();
        ivfile.close();
        cout << ".ufsec file created" << endl;
    }
    return 0;
}






