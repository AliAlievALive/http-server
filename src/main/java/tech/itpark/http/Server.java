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
import java.util.Map;
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

    private void handleConnection(Socket socket) throws MalFormedRequestException {
        try (
                socket;
                final var in = new BufferedInputStream(socket.getInputStream());
                final var out = new BufferedOutputStream(socket.getOutputStream());
        ) {
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

            var routes = Map.of(
                    "GET", Map.of(
                            "/path/getPath", getPath(uri),
                            "/path", "PATHS"), //сюда вместо "PATHS" и ниже я мог прописать выполнение какого то обработчика, но сэкономил время)
                    "POST", Map.of(
                            "/path", "PATH SAVED"
                    )
            );

            switch (method) {
                case GET -> {
                    responseToOut(out, routes.get(method).get(uri));
                }
                case POST -> {
                    final var CRLFCRLF = new byte[]{'\r', '\n', '\r', '\n'};
                    final var headersEndIndex = Bytes.indexOf(buffer, CRLFCRLF, requestLineEndIndex, read) + CRLFCRLF.length;
                    var contentLength = 0;
                    contentLength = getContentLength(buffer, CRLF, requestLineEndIndex, headersEndIndex);
                    in.reset();
                    final var totalSize = headersEndIndex + contentLength;
                    final var fullRequestBytes = in.readNBytes(totalSize);
                    final var body = "Read: " + fullRequestBytes.length;
                    responseToOut(out, routes.get(method).get(uri));
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getPath(String uri) {
        return uri;
    }

    private void responseToOut(BufferedOutputStream out, String getBody) throws IOException {
        out.write(
                (
                        "HTTP/1.1 200 OK\r\n" +
                                "Content-Type: text/plain\r\n" +
                                "Content-Length: " + getBody.length() + "\r\n" +
                                "Connection: close\r\n" +
                                "\r\n" +
                                getBody
                ).getBytes());
    }

    private int getContentLength(byte[] buffer, byte[] CRLF, int requestLineEndIndex, int headersEndIndex) {
        int contentLength;
        var lastIndex = requestLineEndIndex;
        while (true) {
            final var headerEndIndex = Bytes.indexOf(buffer, CRLF, lastIndex, headersEndIndex) + CRLF.length;
            if (headerEndIndex == -1) {
                throw new MalFormedRequestException();
            }
            final var headerLine = new String(buffer, lastIndex, headerEndIndex - lastIndex);

            if (headerLine.startsWith("Content-Length")) {
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
        return contentLength;
    }
}
