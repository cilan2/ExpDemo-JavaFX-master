package fun.fireline.tools;

/**
 * @author zq
 * @date 2021/8/20 23:25
 * @github https://github.com/zq0
 */

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class Cert implements X509TrustManager {
    public Cert() {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}
