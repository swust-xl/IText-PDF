package test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class PdfTest {

    private static SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    /**
     * 使用java.security提供的方法
     */
    static {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.insertProviderAt(bcp, 1);
    }

    public static void main(String[] args) {
        PdfTest pdfTest = new PdfTest();
        try {
            pdfTest.test();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void test() throws Exception {
        Field rsaDataField = PdfPKCS7.class.getDeclaredField("RSAdata");
        rsaDataField.setAccessible(true);
        PdfReader reader = new PdfReader("src/main/resources/Book1.pdf");
        AcroFields acroFields = reader.getAcroFields();
        List<String> signNames = acroFields.getSignatureNames();
        if (signNames.isEmpty()) {
            System.out.println("文档中没有签名字段");
        }
        for (String name : signNames) {
            PdfPKCS7 sign = acroFields.verifySignature(name);
            System.out.println("签名字段名: " + name);
            System.out.println("签名是否覆盖整个文档: " + acroFields.signatureCoversWholeDocument(name));
            System.out.println("签署日期: " + dateFormatter.format(sign.getSignDate()
                    .getTime()));
            System.out.println("证书使用者: " + sign.getSigningCertificate()
                    .getSubjectDN());
            System.out.println("证书发行者: " + sign.getSigningCertificate()
                    .getIssuerDN());
            System.out.println("证书起始期: " + dateFormatter.format(sign.getSigningCertificate()
                    .getNotBefore()));
            System.out.println("证书结束期: " + dateFormatter.format(sign.getSigningCertificate()
                    .getNotAfter()));
            System.out.println("签名验证有效性: " + sign.verify());
            System.out.println("签名时间戳时间: " + dateFormatter.format(sign.getTimeStampToken()
                    .getTimeStampInfo()
                    .getGenTime()));
            System.out.println("签名时间戳有效性: " + sign.verifyTimestampImprint());
            Object rsaDataFieldContent = rsaDataField.get(sign);
            if (rsaDataFieldContent != null && ((byte[]) rsaDataFieldContent).length == 0) {
                System.out.println("发现空白摘要字段=>>>>>>>>>>忽略");
                rsaDataField.set(sign, null);
            }

        }

    }
}
