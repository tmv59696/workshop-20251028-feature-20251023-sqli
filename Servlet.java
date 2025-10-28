import org.apache.commons.validator.routines.UrlValidator;
import org.owasp.encoder.Encode;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@WebServlet("/secure-cache")
public class SecureImageCacheServlet extends HttpServlet {

    // Настройки
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
    private static final int CONNECT_TIMEOUT = 5000; // 5 секунд
    private static final int READ_TIMEOUT = 5000;    // 5 секунд
    private static final int MAX_CACHE_SIZE = 100;   // Максимум 100 элементов

    // LRU-кэш с ограниченным размером и TTL
    private final Cache<String, byte[]> cache = CacheBuilder.newBuilder()
            .maximumSize(MAX_CACHE_SIZE)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();

    // Валидатор URL (проверяет только HTTP/HTTPS)
    private final UrlValidator urlValidator = new UrlValidator(new String[]{"http", "https"});

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // Уязвимость: Аутентификация/авторизация
        // TODO: Реализовать проверку токена или сессии здесь (например, req.getHeader("Authorization"))
        // Для примера, просто проверим наличие заголовка
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.getWriter().println("Unauthorized");
            return;
        }

        String imageUrlParam = req.getParameter("url");

        if (imageUrlParam == null || imageUrlParam.trim().isEmpty()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("URL parameter is required.");
            return;
        }

        // Экранируем параметр для вывода (XSS)
        String safeUrlParam = Encode.forHtml(imageUrlParam);

        // Валидация URL
        if (!urlValidator.isValid(imageUrlParam)) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("Invalid URL format: " + safeUrlParam);
            return;
        }

        URL imageUrl;
        try {
            imageUrl = new URL(imageUrlParam);
        } catch (MalformedURLException e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("Malformed URL: " + safeUrlParam);
            return;
        }

        // Проверка на внутренние IP (SSRF)
        InetAddress addr = InetAddress.getByName(imageUrl.getHost());
        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("Access to local/network addresses is forbidden.");
            return;
        }

        // Проверяем кэш
        byte[] cachedImage = cache.getIfPresent(imageUrlParam);
        if (cachedImage != null) {
            // Устанавливаем безопасные заголовки
            resp.setContentType("image/jpeg"); // или определять по MIME-типу, если известен
            resp.setContentLength(cachedImage.length);
            try (ServletOutputStream out = resp.getOutputStream()) {
                out.write(cachedImage);
            }
            return;
        }

        // Скачивание
        byte[] imageData = downloadImageSafely(imageUrl);
        if (imageData == null) {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().println("Failed to download image from: " + safeUrlParam);
            return;
        }

        // Проверка MIME-типа и расширения (опционально)
        String contentType = URLConnection.guessContentTypeFromStream(new ByteArrayInputStream(imageData));
        if (contentType == null || !contentType.startsWith("image/")) {
            resp.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
            resp.getWriter().println("Content is not a valid image: " + contentType);
            return;
        }

        // Кэшируем
        cache.put(imageUrlParam, imageData);

        // Устанавливаем безопасные заголовки
        resp.setContentType(contentType);
        resp.setContentLength(imageData.length);
        try (ServletOutputStream out = resp.getOutputStream()) {
            out.write(imageData);
        }
    }

    private byte[] downloadImageSafely(URL imageUrl) {
        try {
            HttpURLConnection connection = (HttpURLConnection) imageUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECT_TIMEOUT);
            connection.setReadTimeout(READ_TIMEOUT);

            // Проверка размера файла (опционально, если сервер отдает Content-Length)
            long contentLength = connection.getContentLengthLong();
            if (contentLength > MAX_FILE_SIZE) {
                System.err.println("File too large: " + contentLength + " bytes.");
                return null;
            }

            try (InputStream in = connection.getInputStream()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] data = new byte[8192];
                int nRead;
                long totalRead = 0;

                while ((nRead = in.read(data, 0, data.length)) != -1) {
                    totalRead += nRead;
                    if (totalRead > MAX_FILE_SIZE) {
                        System.err.println("Downloaded file exceeded max size: " + totalRead);
                        return null;
                    }
                    buffer.write(data, 0, nRead);
                }
                return buffer.toByteArray();
            }
        } catch (IOException e) {
            // Не утечка информации
            System.err.println("Error downloading image: " + e.getMessage());
            return null;
        }
    }
}
