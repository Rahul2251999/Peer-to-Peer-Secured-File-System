import socket

def fileLinePrinting(line):
    contentLine = "#%s#"%line
    print(contentLine)

def test(ftp, childServ, MAINSERVERHOST, MAINSERVERPORT):

    local_name = input("Enter Local file path to write\n >> ")

    # Create a socket (SOCK_STREAM means a TCP socket)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((MAINSERVERHOST, MAINSERVERPORT))
        sock.sendall(bytes("getlockedfiles"+ "\n", "utf-8"))
        # Receive users data from the server and shut down
        received = str(sock.recv(1024), "utf-8")

    lockedfilelist = received.split(";")
    print("locked file list:", lockedfilelist)

    if local_name in lockedfilelist:
        print("\nThe requested file is currently using by others, please try again later!!!\n")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((MAINSERVERHOST, MAINSERVERPORT))
        sock.sendall(bytes("lockfile:"+local_name+"\n", "utf-8"))

    try:
        li = ftp.nlst()
        print("file slist : ", li)
        print("file name: ",local_name)

        if local_name in li:
            print("\n\n-------Begin of current content------\n")
            ftp.retrlines("RETR " + local_name, fileLinePrinting)
            print("\n-------EOF------\n\n")
            newcontent = input("---------Enter content to append in the file\n------")
            file = open(local_name, 'a')
            file.write(newcontent)
            file.close()
            file1 = open(local_name, 'rb')
            ftp.storbinary('STOR ' + local_name, file1)
            file1.close()

            for ser in childServ:
                fileChildServ = open(local_name, 'rb')
                ser.storbinary('STOR ' + local_name, fileChildServ)
                fileChildServ.close()
            print("-------File has updated successfully------\n\n")

        else:

            try:
                print("\n-------File uploading started------")
                file = open(local_name, 'w')
                newcontent = input("---------Enter content to write in the file\n------")
                file.write(newcontent)
                file.close()

            except Exception as E:
                print(E)
                return

            try:
                file1 = open(local_name, 'rb')
                ftp.storbinary('STOR ' + local_name, file1)  # send the file
                file1.close()
                print("-------File has uploaded to primary server----")
                print("-------Writing Files in child servers---------")

                for ser in childServ:
                    fileChildServ = open(local_name, 'rb')
                    ser.storbinary('STOR ' + local_name, fileChildServ)
                    fileChildServ.close()
                print("-------File has uploaded successfully------\n\n")

            except Exception as E:
                print(E)

    except Exception as E:
        print(E)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((MAINSERVERHOST, MAINSERVERPORT))
        sock.sendall(bytes("unlockfile:"+local_name+"\n", "utf-8"))