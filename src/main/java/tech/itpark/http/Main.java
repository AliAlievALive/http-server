package tech.itpark.http;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Main {
    public static void main(String[] args) {
        final var server = new Server();
        server.listen(9999);
    }
}
