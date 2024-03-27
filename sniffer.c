#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 2323
#define BUFFER_SIZE 4096


int 
main()
{
    int server_fd,
        new_socket,
        bytes_received;

    struct 
    sockaddr_in address;

    int addrlen = sizeof(address);

    char buffer[BUFFER_SIZE] = {0};
    
    
    if ((server_fd = socket(AF_INET, 
                     SOCK_STREAM, 0)) == 0) 
    {
        perror("Socket creation failed.\n");
        exit(EXIT_FAILURE);
    }
    

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(PORT);
    

    if (bind(server_fd,
            (struct sockaddr *)&address, 
             sizeof(address)) < 0)
    {
        perror("Bind socket failed.\n");
        exit(EXIT_FAILURE);
    }
    

    if (listen(server_fd, 3) < 0)
    {
        perror("Error in listening.\n");
        exit(EXIT_FAILURE);
    }
    

    if ((new_socket = accept(server_fd, 
                    (struct sockaddr *)&address, 
                    (socklen_t*)&addrlen)) < 0)
    {
        perror("Error in accepting connection.\n");
        exit(EXIT_FAILURE);
    }
    

    while 
    (1) 
    {
        if((bytes_received = recv(new_socket, buffer, BUFFER_SIZE, 0)) <= 0) break;
        
        for(int i = 0; i < bytes_received; i++)
            printf("%02X ", ((uint8_t*)buffer)[i]);

        printf("\n\n\n");

        memset(buffer, 0, BUFFER_SIZE);
    }
    
    close(new_socket); close(server_fd);

    return 0;
}