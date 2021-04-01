package tech.itpark.http;

import tech.itpark.http.exception.InvalidRequestLineException;
import tech.itpark.http.exception.MalFormedRequestException;
import tech.itpark.http.guava.Bytes;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class Server {
    public static final String GET = "GET";
    public static final String POST = "POST";
    public static final Set<String> allowedMethods = Set.of(GET, POST);
    public static final Set<String> supportedHTTPVersions = Set.of("HTTP/1.1");

    public void listen(int port) {
        try (
                final var serverSocket = new ServerSocket(port);
        ) {
            while (true) {
                try {
                    final var socket = serverSocket.accept();
                    handleConnection(socket);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleConnection(Socket socket) {
        try (
                socket;
                final var in = new BufferedInputStream(socket.getInputStream());
                final var out = new BufferedOutputStream(socket.getOutputStream());
        ) {
            try {
                final var buffer = new byte[4096];
                in.mark(4096);

                final var read = in.read(buffer);
                final var CRLF = new byte[]{'\r', '\n'};

                final var requestLineEndIndex = Bytes.indexOf(buffer, CRLF, 0, read) + CRLF.length;
                if (requestLineEndIndex == -1) {
                    throw new MalFormedRequestException();
                }

                final var requestLineParts = new String(buffer, 0, requestLineEndIndex)
                        .trim()
                        .split(" ");

                if (requestLineParts.length != 3) {
                    throw new InvalidRequestLineException("requestLine");
                }

                final var method = requestLineParts[0];
                final var uri = requestLineParts[1];
                final var version = requestLineParts[2];

                if (!allowedMethods.contains(method)) {
                    throw new RuntimeException("invalid header: " + method);
                }

                if (!uri.startsWith("/")) {
                    throw new RuntimeException("invalid uri: " + uri);
                }

                if (!supportedHTTPVersions.contains(version)) {
                    throw new RuntimeException("invalid version: " + version);
                }

                if (method.equals(GET)) {
                    // TODO: в будущем вычитать все header
                    // TODO: вызывать обработчик

                    final var body = "OK";
                    out.write(
                            (
                                    "HTTP/1.1 200 OK\r\n" +
                                            "Content-Type: text/plain\r\n" +
                                            "Content-Length: " + body.length() + "\r\n" +
                                            "Connection: close\r\n" +
                                            "\r\n" +
                                            body
                            ).getBytes());
                    return;
                }

                final var CRLFCRLF = new byte[]{'\r', '\n', '\r', '\n'};
                final var headersEndIndex = Bytes.indexOf(buffer, CRLFCRLF, requestLineEndIndex, read) + CRLFCRLF.length;
                var contentLength = 0;

                // FIXME: refactor to method
                var lastIndex = requestLineEndIndex;
                while (true) {
                    final var headerEndIndex = Bytes.indexOf(buffer, CRLF, lastIndex, headersEndIndex) + CRLF.length;
                    if (headerEndIndex == -1) {
                        throw new MalFormedRequestException();
                    }
                    final var headerLine = new String(buffer, lastIndex, headerEndIndex - lastIndex);

                    if (headerLine.startsWith("Content-Length")) {
                        // TODO:
                        final var headerParts = Arrays.stream(headerLine.split(":"))
                                .map(String::trim)
                                .collect(Collectors.toList());

                        if (headerParts.size() != 2) {
                            throw new RuntimeException("bad Content-Length: " + headerLine);
                        }

                        contentLength = Integer.parseInt(headerParts.get(1));
                        break;
                    }

                    lastIndex = headerEndIndex;
                }
                in.reset();

                final var totalSize = headersEndIndex + contentLength;
                final var fullRequestBytes = in.readNBytes(totalSize);

                final var body = "Read: " + fullRequestBytes.length;
                out.write(
                        (
                                "HTTP/1.1 200 OK\r\n" +
                                        "Content-Type: text/plain\r\n" +
                                        "Content-Length: " + body.length() + "\r\n" +
                                        "Connection: close\r\n" +
                                        "\r\n" +
                                        body
                        ).getBytes());
                return;

                // TODO: find handler & call it

                // TODO: HttpRequest ->
                // 1. Method -> GET/POST | getHeader
                // 2. Uri (path/query) | getUri
                // 3. Version | getVersion
                // 4. Headers | get
                // 5. Body []byte

                // TODO: HttpResponse
                // 1. StatusCode | setStatusCode
                // 2. StatusText - OK | setStatusText
                // 3. Headers - | setHeader()
                // 4. Body []byte - |
            } catch (MalFormedRequestException e) {
                // out есть
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
