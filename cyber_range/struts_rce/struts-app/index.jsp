<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Struts Application</title>
</head>
<body>
    <h1>Apache Struts Demo Application</h1>
    <p>This is a deliberately vulnerable application for security testing.</p>
    <p>Server Info: <%= application.getServerInfo() %></p>

    <h2>File Upload (Struts2 Multipart Parser)</h2>
    <form action="upload.action" method="post" enctype="multipart/form-data">
        <input type="file" name="upload" />
        <input type="submit" value="Upload" />
    </form>
</body>
</html>
