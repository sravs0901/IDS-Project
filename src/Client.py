import socket, pickle
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
message = input(" -> ")  # take input
while message.lower().strip() != 'bye':
    client.connect(('localhost', 4444))
    client.send(message.encode())  # send message
    data = client.recv(1024).decode()  # receive response
    print('Received from server: ' + data)  # show in terminal
    message = input(" -> ")  # again take input
    #client.close()  # close the connection
