package org.owasp.webgoat.mini;

import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.util.HtmlUtils;

public class SafeLesson {
    public void executeQuery(String username, Connection conn) throws Exception {
        // Safe Parameterized SQLi
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, username);
        ps.executeQuery();
    }

    public void render(String input, HttpServletResponse response) throws Exception {
        // Safe Encoded XSS
        String safeInput = HtmlUtils.htmlEscape(input);
        response.getWriter().write("<p>Hello " + safeInput + "</p>");
    }

    public void readUserFile(String filename) throws Exception {
        // Safe Canonicalized Path Traversal
        File baseDir = new File("/tmp/uploads");
        File f = new File(baseDir, filename);
        if (f.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
            FileInputStream fis = new FileInputStream(f);
        }
    }
}
