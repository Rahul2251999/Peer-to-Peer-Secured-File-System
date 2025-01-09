from ftplib import FTP
import socket
import client_functions
import tests

# Global Variables
ServerPort = 50000  # server port
clientConnection = None
serverIps = []
quit = ["QUIT", "Q", "quit", "q", "exit", "EXIT", "E", "e"]
listOfYes = ["yes", "y", "YES", "Y"]
list_of_known_servers = []
username = ""

# MainServer details
MAINSERVERHOST = input("ENTER MAIN SERVER IP ADDRESS:\n >>")
MAINSERVERPORT = int(input("ENTER MAIN SERVER PORT NUMBER:\n >>"))

#######################################################################################
# Prompts user for a server IP
# If successful, prompts user for credentials
# Returns a FTP object on success
#######################################################################################
def connect_to_server():

    global clientConnection  # Global server IPS
    new_ftp = FTP()  # return object
    childServersList = [] # array to maintain child servers

    # find an intial server connection
    while 1:
        print("\nInput SEDFS Server IPv4 Address ('quit' to exit)\n >> ", end='')
        serverIP = input().strip()
        #serverIP = "192.168.56.1"

        if serverIP in quit:
            print("No connection made. Goodbye.")
            return False

        # Try server connection
        try:
            new_ftp.connect(serverIP, ServerPort, timeout=5)
            break

        except Exception as e:
            print(" << ERROR:", e)
            continue

    # Loop login attempt
    while True:

        # Get Username and Password
        username = input("\nPlease enter username:\n >> ")
        #username = "user"

        password = input("\nPlease enter password:\n >> ")
        #password = "12345"

        # attempt login
        try:
            new_ftp.login(username, password)
            print(" << Login Success!")
            new_ftp.set_pasv(True)  # Set to passive mode if time out

            #Fetching active servers details from main server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((MAINSERVERHOST, MAINSERVERPORT))
                ip = socket.gethostbyname(socket.gethostname())
                sock.sendall(bytes("getip\n", "utf-8"))
                received = str(sock.recv(1024), "utf-8")

            #display all active servers
            activeservers = received.split(";")
            serverIps = activeservers
            print("\nCurrent active servers :",activeservers,"\n")

            # for all servers, establish a connection
            for ips in serverIps:
                if ips.strip() != serverIP.strip():
                    con = FTP()
                    con.connect(ips.strip(), ServerPort, timeout=5)
                    con.login(username, password)
                    childServersList.append(con)
            break

        # Print exceptions
        except Exception as e:
            print(e)

        # ask if wish to continue
        print("\nDo you wish to quit?\n >> ", end='')
        response = input()
        if response in listOfYes:
            return False

    # Append server information
    list_of_known_servers.append(serverIP)

    # return FTP object
    return new_ftp, childServersList, username

#######################################################################################
# main
#######################################################################################
if __name__ == '__main__':

    #
    ftp, childSer, username = connect_to_server()

    # if there is a connection
    if ftp:

        # display menu
        # record current working directory
        currentDirectory = ftp.pwd()

        # looping program
        while 1:

            print("\n****** Current Directory: /" + currentDirectory + " *******\n")
            print("Enter a command to perform operation or type 'h' to see the menu >> ", end='')

            # get client request
            clientRequest = input().lower()

            # Create file/directory
            if clientRequest == "create" or clientRequest == "c":
                try:
                    client_functions.create_blank_file_or_directory(childSer, ftp, username, MAINSERVERHOST, MAINSERVERPORT)
                    print(" << SUCCESS")

                except Exception as e:
                    print(" << ERROR")

            # Upload Files
            elif clientRequest == "upload" or clientRequest == "upl":
                client_functions.uploadlocalfiles(ftp, childSer, username, MAINSERVERHOST, MAINSERVERPORT)
            
            # Write
            elif clientRequest == "write" or clientRequest == "w":
                client_functions.write(ftp, childSer, username, MAINSERVERHOST, MAINSERVERPORT)

            # read
            elif clientRequest == "read" or clientRequest == "r":
                client_functions.read(ftp, username, MAINSERVERHOST, MAINSERVERPORT)

            # update 
            elif clientRequest == "update" or clientRequest == "up":
                client_functions.update(ftp, username, MAINSERVERHOST, MAINSERVERPORT, childSer)

            elif clientRequest == "test" or clientRequest == "test":
                tests.test(ftp, childSer, MAINSERVERHOST, MAINSERVERPORT)

            # read
            elif clientRequest == "rename" or clientRequest == "u":
                client_functions.rename(ftp, childSer, MAINSERVERHOST, MAINSERVERPORT)

            # change permissions
            elif clientRequest == "permissions" or clientRequest == "p":
                client_functions.change_permissions(username, MAINSERVERHOST, MAINSERVERPORT)

            # Navigate
            elif clientRequest == "n" or clientRequest == "navigate":
                currentDirectory = client_functions.navigate(ftp, childSer, currentDirectory)

            # Navigate
            elif clientRequest == "k" or clientRequest == "chown":
                client_functions.change_owner(ftp, childSer)

            # Back 1 Directory
            elif clientRequest == "b" or clientRequest == "back":
                client_functions.go_back(ftp, childSer)
                currentDirectory = ftp.pwd()

            # Delete
            elif clientRequest == "d" or clientRequest == "delete":
                client_functions.delete(ftp, childSer, username, MAINSERVERHOST, MAINSERVERPORT)

            # List
            elif clientRequest == "l" or clientRequest == "list":
                client_functions.ftp_list(ftp)

            # Open program with file
            elif clientRequest == "o" or clientRequest == "open" or clientRequest == "text editor" or \
                    clientRequest == "open editor" or clientRequest == "open text editor" or \
                    clientRequest == "open text":

                client_functions.open_program()

            # Status
            elif clientRequest == "s" or clientRequest == "status":
                print(" << List of known SEDFS servers", list_of_known_servers)

            # Quit
            elif clientRequest in quit:
                print(" << Quiting SEDFS...Goodbye")
                ftp.quit()

            # Help
            elif clientRequest == "help" or clientRequest == "h":
                client_functions.help(ftp)

            # Default
            else:
                print(" << Unknown Command, type 'h' or 'help'")
