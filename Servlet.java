import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.commons.validator.routines.UrlValidator;
import org.owasp.encoder.Encode;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@WebServlet("/secure-cache")
public class SecureImageCacheServlet extends HttpServlet {

    // === Настройки безопасности ===
    private static final long MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 МБ
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;
    private static final int MAX_CACHE_ENTRIES = 100;
    private static final long RATE_LIMIT_WINDOW_SECONDS = 60;
    private static final long MAX_REQUESTS_PER_WINDOW = 100;

    // === Безопасный LRU-кэш с TTL ===
    private final Cache<String, byte[]> imageCache = CacheBuilder.newBuilder()
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();

    // === Rate limiting (упрощённый вариант на основе счётчика) ===
    private final AtomicLong requestCount = new AtomicLong(0);
    private volatile long windowStart = System.currentTimeMillis();

    // === Валидатор URL (только http/https) ===
    private final UrlValidator urlValidator = new UrlValidator(new String[]{"http", "https"});

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // === 1. Rate Limiting ===
        enforceRateLimit(resp);

        // === 2. Аутентификация (пример: Bearer токен) ===
        String authHeader = req.getHeader("Authorization");
        if (!isValidAuthToken(authHeader)) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.getWriter().println("Missing or invalid Authorization header.");
            return;
        }

        // === 3. Получение и валидация URL ===
        String imageUrlParam = req.getParameter("url");
        if (imageUrlParam == null || imageUrlParam.isBlank()) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("Parameter 'url' is required.");
            return;
        }

        // Экранирование для безопасного вывода (XSS)
        String safeUrlForDisplay = Encode.forHtml(imageUrlParam);

        if (!urlValidator.isValid(imageUrlParam)) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("Invalid URL scheme. Only HTTP/HTTPS allowed: " + safeUrlForDisplay);
            return;
        }

        URL imageUrl;
        try {
            imageUrl = new URL(imageUrlParam);
        } catch (MalformedURLException e) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("Malformed URL: " + safeUrlForDisplay);
            return;
        }

        // === 4. Защита от SSRF (проверка на внутренние IP) ===
        if (isLocalOrPrivateAddress(imageUrl.getHost())) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().println("Access to private or loopback addresses is forbidden.");
            return;
        }

        // === 5. Проверка кэша ===
        byte[] cachedImage = imageCache.getIfPresent(imageUrlParam);
        if (cachedImage != null) {
            serveImage(resp, cachedImage, imageUrlParam);
            return;
        }

        // === 6. Безопасная загрузка изображения ===
        byte[] imageData = downloadImageSafely(imageUrl);
        if (imageData == null) {
            resp.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
            resp.getWriter().println("Failed to fetch image from: " + safeUrlForDisplay);
            return;
        }

        // === 7. Проверка MIME-типа (по содержимому, а не расширению) ===
        String mimeType = detectMimeType(imageData);
        if (mimeType == null || !isAllowedImageType(mimeType)) {
            resp.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
            resp.getWriter().println("Content is not a supported image type.");
            return;
        }

        // === 8. Кэширование и ответ ===
        imageCache.put(imageUrlParam, imageData);
        serveImage(resp, imageData, imageUrlParam);
    }

    // === Вспомогательные методы ===

    private boolean isValidAuthToken(String authHeader) {
        // Пример: "Bearer secure-token-123"
        // В реальном приложении: проверка JWT, OAuth2 и т.д.
        return authHeader != null && authHeader.equals("Bearer secure-token-123");
    }

    private boolean isLocalOrPrivateAddress(String host) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            return addr.isAnyLocalAddress() ||
                   addr.isLoopbackAddress() ||
                   addr.isLinkLocalAddress() ||
                   addr.isSiteLocalAddress();
        } catch (UnknownHostException e) {
            return false; // Не блокируем, но логируем в продакшене
        }
    }

    private byte[] downloadImageSafely(URL url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setInstanceFollowRedirects(false); // Защита от SSRF через редиректы

            // Проверка Content-Length (если доступен)
            long contentLength = conn.getContentLengthLong();
            if (contentLength > MAX_FILE_SIZE_BYTES) {
                System.err.println("File too large: " + contentLength + " bytes.");
                return null;
            }

            try (InputStream in = conn.getInputStream()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                long total = 0;
                int n;
                while ((n = in.read(chunk)) != -1) {
                    total += n;
                    if (total > MAX_FILE_SIZE_BYTES) {
                        System.err.println("Download exceeded max size: " + total + " bytes.");
                        return null;
                    }
                    buffer.write(chunk, 0, n);
                }
                return buffer.toByteArray();
            }
        } catch (IOException e) {
            System.err.println("Download failed: " + e.getMessage());
            return null;
        }
    }

    private String detectMimeType(byte[] data) {
        try (InputStream is = new ByteArrayInputStream(data)) {
            return URLConnection.guessContentTypeFromStream(is);
        } catch (IOException e) {
            return null;
        }
    }

    private boolean isAllowedImageType(String mimeType) {
        return "image/jpeg".equals(mimeType) ||
               "image/png".equals(mimeType) ||
               "image/gif".equals(mimeType) ||
               "image/webp".equals(mimeType);
    }

    private void serveImage(HttpServletResponse resp, byte[] data, String url) throws IOException {
        String mimeType = detectMimeType(data);
        resp.setContentType(mimeType != null ? mimeType : "application/octet-stream");
        resp.setContentLength(data.length);
        resp.setHeader("Cache-Control", "public, max-age=3600"); // Кэширование на клиенте

        try (ServletOutputStream out = resp.getOutputStream()) {
            out.write(data);
        }
    }

    private void enforceRateLimit(HttpServletResponse resp) throws IOException {
        long now = System.currentTimeMillis();
        long windowMs = RATE_LIMIT_WINDOW_SECONDS * 1000;

        if (now - windowStart > windowMs) {
            // Новое окно
            synchronized (this) {
                if (now - windowStart > windowMs) {
                    windowStart = now;
                    requestCount.set(0);
                }
            }
        }

        if (requestCount.incrementAndGet() > MAX_REQUESTS_PER_WINDOW) {
            resp.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
            resp.getWriter().println("Rate limit exceeded. Try again later.");
            throw new IOException("Rate limit exceeded");
        }
    }
}
