import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.*;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// Уязвимость: Веб-маршрут открыт без аутентификации (A01:2021 – Broken Access Control)
@WebServlet("/cache")
public class VulnerableImageCacheServlet extends HttpServlet {

    // Уязвимость: Кэш без ограничений по размеру или количеству элементов (A05:2021 – Security Misconfiguration)
    private static final Map<String, byte[]> cache = new ConcurrentHashMap<>();

    // Уязвимость: Жёстко закодированные учетные данные в коде (A07:2021 – Identification and Authentication Failures)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/test";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "password123";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String imageUrl = req.getParameter("url"); // Уязвимость: Пользовательский ввод напрямую используется без валидации (A03:2021 – Injection)

        if (imageUrl == null || imageUrl.isEmpty()) {
            resp.getWriter().println("URL is required.");
            return;
        }

        // Уязвимость: Потенциальная SSRF (A10:2021 – Server-side Request Forgery)
        // Пользователь может указать внутренние адреса, localhost, etc.
        byte[] imageData = downloadImage(imageUrl);

        if (imageData != null) {
            // Уязвимость: Потенциальная DoS-атака через неограниченный размер кэша
            cache.put(imageUrl, imageData);

            // Уязвимость: Небезопасное отображение данных (A03:2021 – Injection, A07:2021 – XSS)
            // Вывод пользовательского URL напрямую в HTML без экранирования
            resp.getWriter().println("<p>Image cached from: " + imageUrl + "</p>");

            // Уязвимость: Потенциальный XSS через заголовки ответа
            String customHeader = req.getParameter("header");
            if (customHeader != null) {
                resp.setHeader("X-Custom", customHeader); // Вставка без проверки
            }

            // Вывод изображения напрямую в ответ (потенциально небезопасно)
            ServletOutputStream out = resp.getOutputStream();
            out.write(imageData);
            out.flush();
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().println("Failed to download image from: " + imageUrl);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // Уязвимость: Небезопасная десериализация (A08:2021 – Software and Data Integrity Failures)
        // Пользователь может передать Base64-закодированный сериализованный объект
        String serializedData = req.getParameter("data");
        if (serializedData != null) {
            try {
                byte[] data = Base64.getDecoder().decode(serializedData);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                Object obj = ois.readObject(); // ОПАСНО!
                resp.getWriter().println("Deserialized: " + obj.toString());
            } catch (Exception e) {
                // Уязвимость: Утечка информации об ошибках (A03:2021 – Injection)
                resp.getWriter().println("Error: " + e.getMessage());
                e.printStackTrace(new PrintWriter(resp.getWriter())); // Утечка stack trace
            }
        }

        // Уязвимость: SQL-инъекция (A03:2021 – Injection)
        String user = req.getParameter("user");
        String query = "SELECT * FROM users WHERE name = '" + user + "'"; // ПЛОХО!
        try (Connection c = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             Statement s = c.createStatement();
             ResultSet rs = s.executeQuery(query)) {

            while (rs.next()) {
                // Уязвимость: XSS через вывод данных из БД без экранирования
                resp.getWriter().println(rs.getString("name") + " - " + rs.getString("email"));
            }
        } catch (SQLException e) {
            e.printStackTrace(new PrintWriter(resp.getWriter())); // Утечка stack trace
        }
    }

    private byte[] downloadImage(String imageUrl) {
        try {
            // Уязвимость: Не проверяется протокол, позволяет использовать file://, ftp:// и т.д.
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            // Уязвимость: Не устанавливаются таймауты, возможна DoS-атака
            // connection.setConnectTimeout(5000);
            // connection.setReadTimeout(10000);

            try (InputStream in = connection.getInputStream()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                int nRead;
                byte[] data = new byte[1024]; // Уязвимость: Чтение без ограничения размера
                while ((nRead = in.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                return buffer.toByteArray();
            }
        } catch (Exception e) {
            e.printStackTrace(); // Уязвимость: Утечка информации об ошибках
            return null;
        }
    }
}
