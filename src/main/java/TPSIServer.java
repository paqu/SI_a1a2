import com.cedarsoftware.util.io.JsonWriter;
import com.sun.net.httpserver.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Set;
import java.util.List;
import java.lang.Math;
import java.util.Base64;

public class TPSIServer {
    public static void main(String[] args) throws Exception {
        int port = 8000;
        HttpContext context;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/",          new RootHandler());
        server.createContext("/echo",      new EchoHandler());
        server.createContext("/redirect/", new StatusHandler());
        server.createContext("/cookies",   new CookiesHandler());
        server.createContext("/auth",      new AuthHandler());
        context = server.createContext("/auth2",     new Auth2Handler());
        context.setAuthenticator(new BasicAuthenticator("get") {
            @Override
            public boolean checkCredentials(String username, String password) {
                return username.equals("admin") && password.equals("admin");
            }
        });
        System.out.println("Starting server on port: " + port);
        server.start();
    }

    static class RootHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            displayHeader(exchange.getRequestHeaders(), "root req");
            byte[] fileContent = Files.readAllBytes(Paths.get("src/main/java/index.html"));

            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, fileContent.length);
            OutputStream os = exchange.getResponseBody();
            os.write(fileContent);
            os.close();
            displayHeader(exchange.getResponseHeaders(),"root res");
        }
    }

    static class EchoHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            displayHeader(exchange.getRequestHeaders(), "echo req");

            Headers reqHeader = exchange.getRequestHeaders();
            String json = JsonWriter.objectToJson(reqHeader);
            String json2 = JsonWriter.formatJson(json);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, json2.length());
            OutputStream os = exchange.getResponseBody();
            os.write(json2.getBytes());
            os.close();

            displayHeader(exchange.getResponseHeaders(),"echo res");
        }
    }

    static class StatusHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            displayHeader(exchange.getRequestHeaders(),"redirect req");
            URI uri = exchange.getRequestURI();
            String path = uri.getPath();
            String code = path.substring(path.lastIndexOf('/') + 1);
            int redirect_code = Integer.parseInt(code);
            System.out.println("Code is: " + redirect_code);
            exchange.getResponseHeaders().set("Location", "/");
            exchange.sendResponseHeaders(redirect_code, -1);
            exchange.close();
            displayHeader(exchange.getResponseHeaders(),"redirect res");
        }
    }
    static class CookiesHandler implements HttpHandler {


        public void handle(HttpExchange exchange) throws IOException {
            displayHeader(exchange.getRequestHeaders(),"cookies req");

            double random_base = Math.random() * 1000;
            int id = (int)random_base;

            String cookie1= "echo"+id+"="+id+"; Path=/echo; domain=localhost; HttpOnly";
            String cookie2= "root"+id+"="+(id+1)+"; Path=/; domain=wp.pl; HttpOnly";
            List<String> cookies = Arrays.asList(cookie1, cookie2);

            exchange.getResponseHeaders().put("Set-Cookie", cookies);
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
            displayHeader(exchange.getResponseHeaders(),"cookies res");
        }
    }

    static class AuthHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            Headers reqHead = exchange.getRequestHeaders();

            if ( reqHead.containsKey("Authorization") &&
                 reqHead.get("Authorization").get(0).indexOf("Basic ") != -1)
            {
                String auth_val = reqHead.get("Authorization").get(0);
                String base64Cred = auth_val.split(" ", 2)[1];
                byte[] decodedCred = Base64.getDecoder().decode(base64Cred);
                String credentials = new String(decodedCred, StandardCharsets.UTF_8);
                String[] values = credentials.split(":",2);

                if (values[0].equals("admin") && values[1].equals("admin")) {
                    System.out.println("Authorized");// to remove
                    byte[] fileContent = Files.readAllBytes(Paths.get("src/main/java/auth.html"));
                    exchange.getResponseHeaders().set("Content-Type", "text/html");
                    exchange.sendResponseHeaders(200, fileContent.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(fileContent);
                    os.close();
                } else {
                    String msg = "An incorrect password or login";
                    exchange.getResponseHeaders().set("Content-Type", "text/plain");
                    exchange.getResponseHeaders().set("WWW-Authenticate", "Basic real=\"get\"");
                    exchange.sendResponseHeaders(401, msg.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(msg.getBytes());
                    os.close();
                }

            }else {
                exchange.getResponseHeaders().set("WWW-Authenticate", "Basic real=\"get\"");
                exchange.sendResponseHeaders(401, -1);
                exchange.close();
            }
        }

    }
    static class Auth2Handler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {

            byte[] fileContent = Files.readAllBytes(Paths.get("src/main/java/auth.html"));
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, fileContent.length);
            OutputStream os = exchange.getResponseBody();
            os.write(fileContent);
            os.close();
        }
    }
    static void displayHeader(Headers header, String title)
    {
        System.out.println("##############START - " + title + " ###################");
        Set <String> keys = header.keySet();
        for (String key : keys) {
            System.out.print(key + ": ");
            List<String> values = header.get(key);
            for (String value : values) {
                System.out.print(value + ",");
            }
            System.out.println();
        }

        System.out.println("##############END###################");
    }
}