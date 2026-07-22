package org.owasp.webgoat.mini;

import java.io.*;
import java.sql.*;
import javax.servlet.http.*;

public class VulnerableLesson {
    public void executeQuery(String username, Statement stmt) throws Exception {
        // Vulnerable SQLi
        String sql = "SELECT * FROM users WHERE name = '" + username + "'";
        stmt.executeQuery(sql);
    }

    public void render(String input, HttpServletResponse response) throws Exception {
        // Vulnerable XSS
        response.getWriter().write("<p>Hello " + input + "</p>");
    }

    public void readUserFile(String filename) throws Exception {
        // Vulnerable Path Traversal
        File f = new File("/tmp/uploads/" + filename);
        FileInputStream fis = new FileInputStream(f);
    }
}
