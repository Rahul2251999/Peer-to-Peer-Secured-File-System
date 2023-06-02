# P2P Encrypted File Sharing System

## Table of Contents
- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Technical Implementation](#technical-implementation)
- [Usage](#usage)
- [References](#references)

## Introduction
This project is a Peer-to-Peer (P2P) encrypted file sharing system designed to securely store, share and manage files across a distributed network of peers. Built with Java, it utilizes a P2P architecture, allowing users to directly share files with one another without relying on a central server.

## Getting Started
### Prerequisites
* Java Development Kit (JDK) 11+
* Apache Maven

### Installing and Running
1. Clone the repository to your local machine: `git clone https://github.com/lokesh-kadiyala98/p2p-file-sharing.git`
2. Navigate to the project directory: `cd p2p-file-sharing`
3. Compile the project using Maven: `mvn clean install`
4. Navigate to the target directory: `cd target`
5. Run the application: `java -jar file-sharing-1.0-SNAPSHOT.jar`

## Technical Implementation
### Java and Sockets
The system is built primarily using Java, a popular high-level, object-oriented programming language known for its robustness, security, and cross-platform compatibility. Java provides a rich set of libraries and features which facilitates the implementation of complex systems, including file sharing systems. Java's socket API is used to facilitate real-time communication between nodes in the P2P network. Sockets provide endpoints for communication between two machines and can manage both incoming and outgoing data.

### File System Operations
The core operations in this system involve creating, reading, updating, and deleting (CRUD) files. Files can also be restored and shared between peers. These operations are implemented using Java, which provide a high-level, object-oriented approach for managing file system operations. The system supports all operations in a Linux file system such as touch, mkdir, rm, chmod, cd etc.

### Encryption and Security
Security is a key aspect of this system. To secure communications and data, the system uses a combination of SSL/TLS for secure socket connections, AES for secure file encryption, and RSA keys for AES key exchange. A Certificate Authority (CA) is implemented to issue digital certificates for secure communication. Each peer generates a private/public key pair for secure authentication and communication. Files and directory permissions are managed to prevent unauthorized access.

### Asynchronous Read/Write with IO Uring
Traditional file system implementations are synchronous and blocking by nature. With the advent of IO Uring, a new Linux-based IO interface, we are able to achieve truly asynchronous, non-blocking IO operations, improving the overall system performance. By making use of IO Uring, the system allows multiple users to perform operations concurrently without blocking each other, leading to significant enhancements in terms of scalability and responsiveness.

### Debouncing
To enhance system performance and avoid unnecessary operations, a debouncing technique is implemented in the system. This ensures that certain operations, such as saving changes to a file, aren't performed excessively in a short period of time. This technique is particularly important in a collaborative environment where multiple users may be attempting to modify a file simultaneously.

### Multithreading and Concurrency
Given the nature of P2P systems where multiple processes occur simultaneously, the system makes extensive use of multithreading. This allows multiple users to perform operations concurrently, ensuring the system remains responsive and efficient even under heavy load.

## Usage
Upon launching the application, each user can generate and register a unique private/public key pair with the system. This ensures secure authentication and communication within the network.

The file system supports the following commands:
- `keygen --keyLength`: Generate a new key with a specified key length.
- `mkdir --directoryName --accessList`: Create a new directory with the given name and access list.
- `touch --fileName --accessList`: Create a new file with the given name and access list.
- `chmod --[directoryName|fileName] --updatedAccessList`: Change the access permissions of a directory or file to the updated access list.
- `cd --directoryName`: Change the current directory to the given directory name.
- `rm --fileName`: Remove the file with the given name.
- `restore --fileName`: Restore the file with the given name.
- `ls`: List the contents of the current directory.

Users can create, read, update, delete and restore files on their local machine, which are then made available for sharing within the P2P network. The system ensures data integrity and confidentiality through the use of strong encryption algorithms, file and directory permissions, and mechanisms to detect unauthorized modifications.

## References
* "Peer-to-Peer (P2P) File Sharing Systems." n.d. CIS 4360 – Secure Computer Systems. [Link](http://www.cise.ufl.edu/~mssz/NetSec/Peer-to-peer.html)
* Vassileva, Julita. 2003. "Distributed User Modeling for Universal Information Access." In User Modeling 2003, edited by Peter Brusilovsky, Albert Corbett, and Fiorella de Rosis, 207–216. Springer Berlin Heidelberg. [Link](https://link.springer.com/chapter/10.1007/3-540-44963-9_28)
* Zhou, Ruiying. 2007. "End-to-End Security in Service-Oriented P2P File Sharing Systems." In Proceedings of the 2007 ACM Symposium on Applied Computing - SAC ’07, 1186. ACM Press. [Link](https://dl.acm.org/doi/10.1145/1244002.1244246)

Please note that while this README outlines the basic setup and usage of this project, it is recommended to refer to individual module documentation for a comprehensive understanding of each component.
