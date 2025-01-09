import os, shutil, socket, json
from pathlib import Path
import io
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import getuserkey
import random

# BLOCK_SIZE = 32
# key = 'abcdefghijklmnop'.encode()
# ciphers = AES.new(key, AES.MODE_ECB)
# decipher = AES.new(key, AES.MODE_ECB)


listOfYes = ["yes", "y", "YES", "Y"]
listOfNo = ["no", "n", "NO", "N"]
is_file = ["F", "FILE", "f", "file", ]
is_directory = ["D", "DIRECTORY", "d", "directory"]



#######################################################################################
# Display Help Menu
#######################################################################################
def help(ftp):
    print("============================\n",
          "\nCurrent Path: " + ftp.pwd() + "\n\n",
          "\t'q' == Quit SEDFS\n",
          "\t'r' == Read SEDFS file\n",
          "\t'w' == Write to SEDFS\n",
          "\t'p' == Change permissions\n",
          "\t'c' == Create new SEDFS file/directory\n",
          "\t'n' == Navigate to new directory\n",
          "\t'b' == Move back 1 directory\n",
          "\t'l' == List directory contents contents\n",
          "\t'd' == Delete file/directory\n",
          "\t's' == Display Server Information\n",
          "\t'o' == Open Text Editor\n",
          "\t'k' == Change Owner\n",
          "\t'u' == Rename File\n",
          "\t'h' == Help\n")

#
########################################################################################
# Open Text Editor
# Gets notepad on Windows, Nano on Linux
#######################################################################################
def open_program():
    text_editor = input("\nPlease enter text editor:\n >> ")
    file = input("\nPlease enter file:\n >> ")

    editor_path = shutil.which(text_editor)
    is_a_file = Path(file).is_file()

    if not editor_path:
        print(" << ERROR; Text Editor, '%s', does not exist", text_editor)
        return

    if not is_a_file:
        print(" << ERROR; Path incorrect or is not file")
        return

    try:
        os.system(editor_path + " " + file)
        print()

    except Exception as e:
        print(e)

#######################################################################################
# Makes a blank file or directory in SEDFS
#######################################################################################
def create_blank_file_or_directory(childServ, ftp, username, MAINSERVERHOST, MAINSERVERPORT):
    # loop until user says 'FILE' or 'DIRECTORY'
    while True:
        print(" >> File (F) or Directory (D)\n >> ", end='')
        response = input()

        if response in is_file or response in is_directory:
            break

    # create BLANK FILE
    if response in is_file:
        print("Create file name\n >> ", end='')
        client_file = input()

        # encrypt file name
        enc_client_file = doEncrypt(client_file)
        print(client_file)

        command = 'STOR ' + enc_client_file

        # create file for all servers
        try:
            response = ftp.storbinary(command, io.BytesIO(b''))
            print(" << ", response)

            for ser in childServ:
                ser.storbinary(command, io.BytesIO(b''))

            # ?????????????????
            try:
                createPermission("insert", enc_client_file, username, MAINSERVERHOST, MAINSERVERPORT)
            except Exception as E:
                print("Failed to create FILE permissions")
                print(E)

        except Exception as e:
            print("------FAILED: File/Directory could not be made----------\n")
            print(" << ERROR:", e)
            return

        print("-------File creation completed successfully--------\n")

    # create BLANK DIRECTORY
    else:

        print("Create directory name\n >> ", end='')
        client_directory = input()


        # encypt directory name
        client_directory = doEncrypt(client_directory)

        try:
            response = ftp.mkd(client_directory)
            #print(" << ", response)
            print("------Directory created in parent server-----------\n")
            print("------Creating Directory in child servers----------\n")
            for ser in childServ:
                ser.mkd(client_directory)

            print("-------Directory creation completed successfully--------\n")

            try:
                createPermission("insert", client_directory, username, MAINSERVERHOST, MAINSERVERPORT)
            except Exception as E:
                print("Failed to create DIRECTORY permissions")
                print(E)

        except Exception as e:
            print(" << ERROR:", e)

#######################################################################################
#
#######################################################################################
def createPermission(flag, filename, owner, MAINSERVERHOST, MAINSERVERPORT, user=None):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((MAINSERVERHOST, MAINSERVERPORT))
        ip = socket.gethostbyname(socket.gethostname())

        #
        if flag=="insert":
            data = {"type":"insertPermissions", "fileDetails": {"name": filename, "owner": owner, "users":{}}}

        #
        else:
            data = {"type":"insertPermissions", "fileDetails": {"name": filename, "owner": owner, "users":{"name":user['name'],"per":user['per']}}}

        #
        jsData = json.dumps(data)
        sock.sendall(bytes(jsData, encoding="utf-8"))
        received = sock.recv(1024)
        data = received

        #
        return str(data)

#######################################################################################
# get permissions for a file
#######################################################################################
def getPermission(filename, username, MAINSERVERHOST, MAINSERVERPORT):

    #
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((MAINSERVERHOST, MAINSERVERPORT))
        data = {"type":"getPermissions", "filename":filename}
        jsData = json.dumps(data)
        sock.sendall(bytes(jsData, encoding="utf-8"))
        received = sock.recv(1024)

    #
    if received.decode('utf-8') == "NONE":
        return "owner"
    data = received.decode('utf-8')
    dat = json.loads(data)

    #
    if username == dat['owner']:
        return "owner"
    elif username in dat['users']:
        return dat['users'][username]
    else:
        return False


#######################################################################################
# delete permissions
#######################################################################################
def delPermission(filename, MAINSERVERHOST, MAINSERVERPORT):

    #
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((MAINSERVERHOST, MAINSERVERPORT))
        data = {"type":"delPermissions", "filename":filename}
        jsData = json.dumps(data)
        sock.sendall(bytes(jsData, encoding="utf-8"))
        received = sock.recv(1024)

    #
    data = received.decode('utf-8')


#######################################################################################
# update permissions
#######################################################################################
def updatePermission(oldfilename, newfilename, MAINSERVERHOST, MAINSERVERPORT):

    #
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((MAINSERVERHOST, MAINSERVERPORT))
        data = {"type":"updatePermissions", "oldfilename":oldfilename, "newfilename": newfilename}
        jsData = json.dumps(data)
        sock.sendall(bytes(jsData, encoding="utf-8"))
        received = sock.recv(1024)

    #
    data = received.decode('utf-8')

#######################################################################################
# Delete 'file' or 'directory'
#######################################################################################
def delete(ftp, childServ, username, MAINSERVERHOST, MAINSERVERPORT):
  
    name = input("Enter name to delete\n >> ")
    li = ftp.nlst()
    token = doEncrypt(name)
    permission = getPermission(token, username, MAINSERVERHOST, MAINSERVERPORT)
    if permission != "owner" and permission != "RW" and permission != "W":
        print("You don't have sufficient rights to delete the file.")
        return
    #for nam in li:
    #    if name == doDecrypt(nam):
    #       token = nam
    #if token == "":
    #    print("No sunch File found.....")
    #    return
    if not token in li:
        print("No such File found.....Please enter correct file name")
        return   

    # Ask if user wants new path
    while True:
        print("Do you want to enter new path?\n >> ", end='')
        ans = input().lower()

        if ans in listOfYes or ans in listOfNo:
            break
    #
    if ans in listOfNo:
        try:
            ftp.delete(token)
            for ser in childServ:
                ser.delete(token)
            delPermission(token, MAINSERVERHOST, MAINSERVERPORT)
            print("----------deletion successfully completed-------\n")
            return

        except Exception as e:
            print(e)
            return

    #
    else:
        print("Enter new existing path\n >> ", end='')
        new_path = input()
        token = doEncrypt(new_path)
        permission = getPermission(token, username, MAINSERVERHOST, MAINSERVERPORT)
        if permission != "owner" and permission != "RW" and permission != "W":
            print("You don't have sufficient rights to delete the file.")
            return
        #
        try:
            if not token in li:
                print("No such File found.....Please enter correct file name")
                return   
            ftp.delete(token)

            #
            for ser in childServ:
                ser[0].delete(token)
            delPermission(token, MAINSERVERHOST, MAINSERVERPORT)
            print("----------deletion successfully completed-------\n")
            return

        #
        except Exception as e:
            print(e)
            return

#######################################################################################
# navigate to new folder
#######################################################################################
def navigate(ftp, childServ, current):

    new_path = input("Enter new path\n >> ")

    # encrypt path
    enc_new_path = doEncrypt(new_path)

    # change current path in parent and all other child servers
    try:
        ftp.cwd(enc_new_path)
        for ser in childServ:
            ser.cwd(enc_new_path)

        print("-------Directory changed succesfully--------\n")
        return new_path

    except Exception as e:
        print(e)

    return current

#######################################################################################
# rename file on all known servers
#######################################################################################
def rename(ftp, childServ, MAINSERVERHOST, MAINSERVERPORT):

    resp = ''
    old_name = input("Enter the file name to rename \n >> ")
    new_name = input("Enter the new file name\n >> ")

    # encrypt oldname
    enc_old_name = doEncrypt(old_name)
    
    # encrypt newname
    enc_new_name = doEncrypt(new_name)

    try:
        resp = ftp.rename(enc_old_name, enc_new_name)
    except Exception as E:
        print(resp)
        print("------FAILED to rename file in parent server-------\n")
        return

    # rename files in child servers
    for ser in childServ:

        try:
            resp = ser.rename(enc_old_name, enc_new_name)
        except Exception as E:
            print(resp)
            print("------FAILED to rename file in ONE or MORE child servers-------\n")
            return
    updatePermission(enc_old_name, enc_new_name, MAINSERVERHOST, MAINSERVERPORT)
    print("------File renaming is completed succesfully-------\n")

#######################################################################################
# list all current files and directories
#######################################################################################
def ftp_list(ftp):

    try:
        print("\n\n-------Begin of List------\n")
        li = ftp.nlst()
        for i in li:
            try:
                print(doDecrypt(i))
            except Exception as E:
                print("ERROR, could not decrypt " + i)
        print("\n-------End of List------\n\n")

    except Exception as E:
        print("Error: ", E)

#######################################################################################
# change file permissions
#######################################################################################
def change_permissions(username, MAINSERVERHOST, MAINSERVERPORT):


    # encrypt file name
    filename = input("Input filename\n >> ")
    enc_filename = doEncrypt(filename)
    getper = getPermission(enc_filename, username, MAINSERVERHOST, MAINSERVERPORT)
    if getper != "owner":
        print("You don't have enough rights to change permissions for the selected file")
        return

    # get permissions
    user = {}
    name = input("enter the user you want to assign permissions\n >>")
    user['name'] = name
    per = input("enter the permission type. 'R' for read access, 'RW' or 'W' for write access \n>>")
    if per == 'R' or per =='RW' or per == 'W':
        per = per
    else:
        per = "R"
    user['per'] = per
    #
    try:
        createPermission("update", enc_filename, "", MAINSERVERHOST, MAINSERVERPORT, user)
        print("Permissions assigned successfully...!!!")


    except Exception as E:
        print(E)


#######################################################################################
# change file permissions
#######################################################################################
def change_permissions_old(ftp, childServ):


    # encrypt file name
    filename = input("Input filename\n >> ")
    enc_filename = doEncrypt(filename)

    # get permissions
    permissions = input("Input new permissions\n >> ").strip()

    #
    try:
        ftp.sendcmd("SITE CHMOD " + permissions + " " + enc_filename)
        for ser in childServ:
            ser.sendcmd("SITE CHMOD" + permissions + " " + enc_filename)
        print("-------------Permission changed succesfully------------")


    except Exception as E:
        print(E)

#######################################################################################
#
#######################################################################################
def change_owner(ftp, childServ):

    # encrypt file name
    filename = input("Input filename\n >> ")
    enc_filename = doEncrypt(filename)

    owner = input("Input new owner\n >> ").strip()
    try:
        ftp.sendcmd("SITE CHOWN" + owner + " " + enc_filename)
        for ser in childServ:
            ser.sendcmd("SITE CHOWN" + owner + " " + enc_filename)
        print("-------------Owner changed succesfully------------")
    except Exception as E:
        print(E)

#######################################################################################
# upload local files to SEDFS
#######################################################################################
def uploadlocalfiles(ftp, childServ, username, MAINSERVERHOST, MAINSERVERPORT):

    # encrypt file
    local_name = input("Enter Local file path to upload\n >> ")
    enc_local_name = doEncrypt(local_name)

    # try to encrypt file and send it
    try:

        # open file
        with open(local_name, 'rb') as fo:
            plaintext = fo.read()

        # ENCRYPT ALL the file text
        enc_text = doEncrypt(str(plaintext))

        # Make encryted text as ".enc"
        with open(enc_local_name, 'w') as fo:
            fo.write(enc_text)

        print("\n-------File uploading started------")

    # failed to open / encrypt file
    except Exception as E:
        print(E)
        return

    # try to send ".enc" file
    try:

        # encrypt local_name
        enc_local_name = doEncrypt(local_name)

        # open encrypt file
        file_to_send = open(enc_local_name, 'rb')

        ftp.storbinary('STOR ' + enc_local_name, file_to_send)  # send the file
        print("-------File has uploaded to primary server----")
        print("-------Writing Files in child servers---------")

        # send file to all child servers
        for ser in childServ:
            fileChildServ = open(enc_local_name, 'rb')
            ser.storbinary('STOR ' + enc_local_name, fileChildServ)
            fileChildServ.close()
        createPermission("insert", enc_local_name, username, MAINSERVERHOST, MAINSERVERPORT)
        os.remove(enc_local_name)
        print("-------File has uploaded successfully------\n\n")

    except Exception as E:
        print(E)
userrname = 'admin'

#######################################################################################
# write to SEDFS
#######################################################################################

def write(ftp, childServ, username, MAINSERVERHOST, MAINSERVERPORT):

    # get the file name and encrypt it
    local_name = input("Enter Local file path to write\n >> ")
    enc_local_name = doEncrypt(local_name)

    # get list all the files
    filenames = ftp.nlst()

    # if the encypted name is in the listed files
    if enc_local_name in filenames:

        # check if permissions are valid
        getper = getPermission(enc_local_name, username, MAINSERVERHOST, MAINSERVERPORT)
        if getper != "owner" and getper != "RW" and getper != "W":
            print("You don't have enough rights to  write for the selected file")
            return

        print("File already found on server. Appending your contents at the end of the file")

        # lock the file on main server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((MAINSERVERHOST, MAINSERVERPORT))
            sock.sendall(bytes("lockfile:" + enc_local_name + "\n", "utf-8"))

        # get the specfic file from the server
        file = open(enc_local_name, 'a')
        ftp.retrbinary('RETR %s' % enc_local_name, file.write)
        file.close()

        print("\n\n-------Begin of current content------\n")
        ftp.retrlines("RETR " + enc_local_name, fileLinePrinting)
        print("\n-------EOF------\n\n")
        # Get contents of file to encrypt
        newcontent = input("---------Enter content to write in the file\n------")
        enc_newcontent = doEncrypt(newcontent)

        file = open(enc_local_name, 'a')
        file.write(enc_newcontent)
        file.close()

        # reopen appended file and send to MAIN FTP
        file1 = open(enc_local_name, 'rb')
        ftp.storbinary('STOR ' + enc_local_name, file1)
        file1.close()

        # SEND FILE to all other FTPs
        for ser in childServ:
            fileChildServ = open(enc_local_name, 'rb')
            ser.storbinary('STOR ' + enc_local_name, fileChildServ)
            fileChildServ.close()

        print("-------File has updated successfully------\n\n")

        # UNLOCK FILE
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((MAINSERVERHOST, MAINSERVERPORT))
            sock.sendall(bytes("unlockfile:"+local_name+"\n", "utf-8"))

    # Else the file is not on the server
    else:

        # Make a new file
        print("File not found on server, making new file")
        newcontent = input("---------Enter content to write in the file\n------")
        enc_newcontent = doEncrypt(newcontent)
        file = open(enc_local_name, 'w')
        file.write(enc_newcontent)
        file.close()

        print("\n-------File uploading started------")

        # Try to store content
        try:

            # open file to send
            file1 = open(enc_local_name, 'rb')

            # send the file
            ftp.storbinary('STOR ' + enc_local_name, file1)
            file1.close()

            print("-------File has uploaded to primary server----")
            print("-------Writing Files in child servers---------")
            for ser in childServ:
                fileChildServ = open(enc_local_name, 'rb')
                ser.storbinary('STOR ' + enc_local_name, fileChildServ)
                fileChildServ.close()

            # send permissions to MAINSERVER
            createPermission("insert", enc_local_name, username, MAINSERVERHOST, MAINSERVERPORT)
            print("-------File has uploaded successfully------\n\n")

        except Exception as E:
            print(E)


#######################################################################################
# update to SEDFS
#######################################################################################
def update(ftp, username, MAINSERVERHOST, MAINSERVERPORT, childServ):

    # encrypt local_name
    sedfs_name = input("Enter SEDFS file path to download\n >> ")
    enc_sedfs_name = doEncrypt(sedfs_name)

    getper = getPermission(enc_sedfs_name, username, MAINSERVERHOST, MAINSERVERPORT)
    if getper != "owner" and getper != "RW" and getper!="W":
        print("You don't have enough rights to  write for the selected file")
        return

    try:
        print("\n\n-------Begin of current content------\n")
        ftp.retrlines("RETR " + enc_sedfs_name, fileLinePrinting)
        print("\n-------EOF------\n\n")

        newcontent = input("---------Enter content to append in the file\n------")
        enc_newcontent = doEncrypt(newcontent)
        file = open(enc_sedfs_name, 'a')
        file.write(enc_newcontent)
        file.close()

        # encrypt file
        try:
            # open file
            with open(sedfs_name, 'rb') as fo:
                plaintext = fo.read()

            # ENCRYPT ALL the file text
            enc_text = doEncrypt(plaintext).encode()

            # Make encryted text as ".enc"
            with open(sedfs_name + ".enc", 'wb') as fo:
                fo.write(enc_text)
                fo.close

        except Exception as E:
            print(E)
            return

        # send encrypted file to parent server
        file_to_send = open(enc_sedfs_name, 'rb')
        ftp.storbinary('STOR ' + enc_sedfs_name, file_to_send)
        file_to_send.close()

        # send encrypted file to all servers
        
        file1 = open(enc_sedfs_name, 'rb')
        ftp.storbinary('STOR ' + enc_sedfs_name, file1)
        file1.close()
        
        for ser in childServ:
            fileChildServ = open(enc_sedfs_name, 'rb')
            ser.storbinary('STOR ' + enc_sedfs_name, fileChildServ)
            fileChildServ.close()
                  
        print("-------File has updated successfully------\n\n")
        
    except Exception as E:
        print(E)

# crypto variables
BLOCK_SIZE = 32
rand_num = random.randrange(1, 26, 1)
encrypted_user_key = getuserkey.encrypt(userrname, rand_num)
KEY = getuserkey.get_key(encrypted_user_key, rand_num).encode()
cipher = AES.new(KEY, AES.MODE_ECB)
decipher = AES.new(KEY, AES.MODE_ECB)

#######################################################################################
# read from sedfs
#######################################################################################
def read(ftp, username, MAINSERVERHOST, MAINSERVERPORT):

    # encrypt local_name
    sedfs_name = input("Enter SEDFS file path to download\n >> ")
    enc_sedfs_name = doEncrypt(sedfs_name)
    
    getper = getPermission(enc_sedfs_name, username, MAINSERVERHOST, MAINSERVERPORT)
    if getper != "owner" and getper != "RW" and getper!="W" and getper!="R":
        print("You don't have enough rights to  write for the selected file")
        return
      
    try:
        print("\n\n-------Begin------\n")
        ftp.retrlines("RETR " + enc_sedfs_name, fileLinePrinting)
        print("\n-------EOF------\n\n")

    except Exception as E:
        print(E)
        return

def fileLinePrinting(line):
    contentLine = "#%s#"%doDecrypt(line)
    print(contentLine)

#######################################################################################
# go back one directory
#######################################################################################
def go_back(ftp, childServ):
    # go back in current server, and other servers
    try:
        ftp.cwd("../")
        for ser in childServ:
            ser.cwd("../")

    # print error
    except Exception as E:
        print(E)


#######################################################################################
# encryption
#######################################################################################
def doEncrypt(content):

    # assuming content is string
    # convert to bytes
    data = bytes(content, 'utf-8')

    # pad then encrypt data
    msg = cipher.encrypt(pad(data, BLOCK_SIZE))

    # returns string, (convert from hex)
    return msg.hex()


#######################################################################################
# decryption
#######################################################################################
def doDecrypt(content):

    # assuming content is string
    # change to hex
    data = bytes.fromhex(content)

    # decrypt data
    plain_text = decipher.decrypt(data)

    # unpad data
    msg_dec = unpad(plain_text, BLOCK_SIZE)

    return msg_dec.decode(encoding="utf-8")

#######################################################################################
# needed for error handling
#######################################################################################
class Execption:
    pass