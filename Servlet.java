package local.ptdemo.appsec.workshop.llm;

import lombok.SneakyThrows;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

@WebServlet("/llm")
public class Servlet extends HttpServlet {
    @SneakyThrows
    @Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");
        if (name == null) return;

        String query = "SELECT * FROM users WHERE username = ?";

        try (Connection c = DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass");
             PreparedStatement ps = c.prepareStatement(query)) {

            ps.setString(1, name);

            try (ResultSet rs = ps.executeQuery();
                 var out = response.getWriter()) {

                while (rs.next()) {
                    // Экранируем каждую часть отдельно
                    String safeUsername = Encode.forHtml(rs.getString("username"));
                    String safeEmail = Encode.forHtml(rs.getString("email"));

                    // Конкатенируем уже безопасные строки
                    String output = safeUsername + " - " + safeEmail;

                    // Выводим безопасную строку
                    out.println(output);
                }
            }
        } catch (SQLException | java.io.IOException e) {
            e.printStackTrace(); // или используйте логгер
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}

    @SneakyThrows
    @Override
    protected void doPost(HttpServletRequest request,
                         HttpServletResponse response) {
    }
}
