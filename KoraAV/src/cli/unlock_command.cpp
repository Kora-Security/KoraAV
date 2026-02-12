// src/cli/unlock_command.cpp
// CLI command to unlock system after ransomware lockdown

#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

void print_usage(const char* prog) {
    std::cout << "KoraAV Unlock Help\n";
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " unlock --filesystem    # Restore filesystem to read-write\n";
    std::cout << "  " << prog << " unlock --network       # Restore all network rules\n";
    std::cout << "  " << prog << " unlock --all           # Restore everything at the same time\n";
    std::cout << "  " << prog << " unlock --status        # Show lockdown status\n";
    std::cout << "\nExamples:\n";
    std::cout << "  sudo " << prog << " unlock --all\n";
    std::cout << "  sudo " << prog << " unlock --status\n";
}

int send_daemon_command(const std::string& command) {
    // Connect to daemon via Unix socket
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error: Could not create socket\n";
        return 1;
    }
    
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/opt/koraav/var/run/koraav.sock");
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Error: Could not connect to KoraAV daemon\n";
        std::cerr << "Is the daemon running? Check: sudo systemctl status koraav\n";
        close(sock);
        return 1;
    }
    
    // Send command
    write(sock, command.c_str(), command.length());
    
    // Receive response
    char buffer[4096];
    ssize_t bytes = read(sock, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        std::cout << buffer;
    }
    
    close(sock);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    if (std::string(argv[1]) != "unlock") {
        print_usage(argv[0]);
        return 1;
    }
    
    // Check for root
    if (geteuid() != 0) {
        std::cerr << "Error: This command must be run as root\n";
        std::cerr << "Try: sudo " << argv[0] << " unlock " << argv[2] << "\n";
        return 1;
    }
    
    std::string option = argv[2];
    
    if (option == "--filesystem") {
        std::cout << "Unlocking filesystem...\n";
        return send_daemon_command("UNLOCK_FILESYSTEM");
    }
    else if (option == "--network") {
        std::cout << "Restoring network...\n";
        return send_daemon_command("UNLOCK_NETWORK");
    }
    else if (option == "--all") {
        std::cout << "UNLOCKING SYSTEM\n";
        std::cout << "This will restore filesystem and network to normal state.\n";
        std::cout << "Continue? [y/N] ";
        
        std::string response;
        std::getline(std::cin, response);
        
        if (response != "y" && response != "Y") {
            std::cout << "Cancelled\n";
            return 0;
        }
        
        return send_daemon_command("UNLOCK_ALL");
    }
    else if (option == "--status") {
        return send_daemon_command("LOCKDOWN_STATUS");
    }
    else {
        std::cerr << "Unknown option: " << option << "\n";
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
