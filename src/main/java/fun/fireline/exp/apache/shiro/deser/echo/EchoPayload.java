package fun.fireline.exp.apache.shiro.deser.echo;

import com.sun.xml.internal.ws.util.StringUtils;
import javassist.ClassPool;
import javassist.CtClass;

@SuppressWarnings("rawtypes")
public interface EchoPayload<T> {

    /*
     * return armed payload object to be serialized that will execute specified
     * command on deserialization
     */
    public CtClass genPayload(ClassPool pool) throws Exception;

    public static class Utils {
        public static Class<? extends EchoPayload> getPayloadClass(final String className) throws ClassNotFoundException {
            Class<? extends EchoPayload> clazz = null;
            try {
                clazz = (Class<? extends EchoPayload>) Class.forName("fun.fireline.exp.apache.shiro.deser.echo." + StringUtils.capitalize(className));

            } catch (ClassNotFoundException e1) {
                clazz = (Class<? extends EchoPayload>) Class.forName("fun.fireline.exp.apache.shiro.deser.plugins." + StringUtils.capitalize(className));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return clazz;
        }
    }
}
