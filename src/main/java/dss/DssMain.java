package dss;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

class DssMain {

    static protected DSSDocument toSignDocument;

    public static void main(String[]args) throws Exception {

        DssMain dssInstance = new DssMain();
        dssInstance.signPAdESBaselineBWithVisibleSignature();
//        dssInstance.getPrivateKeyFromTestP12File();
    }

    public void signPAdESBaselineBWithVisibleSignature() throws Exception {
        preparePdfDoc();

        // Get a token connection based on a pkcs12 file commonly used to store private
        // keys with accompanying public key certificates, protected with a password-based symmetric key -
        // Return AbstractSignatureTokenConnection signingToken
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
//            System.out.println(privateKey.getCertificate().toString());

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            // We choose the level of the signature (-B, -T, -LT, -LTA).
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());
            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Initialize visual signature and configure
            SignatureImageParameters imageParameters = new SignatureImageParameters();
            // set an image
//            imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("signature-pen.png")));
            // the origin is the left and top corner of the page
            imageParameters.setxAxis(200);
            imageParameters.setyAxis(400);
            imageParameters.setWidth(300);
            imageParameters.setHeight(200);

            // Initialize text to generate for visual signature
//            DSSFont font = new DSSFileFont(getClass().getResourceAsStream("OpenSansRegular.ttf"));

            // Instantiates a SignatureImageTextParameters object
            SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
            // Allows you to set a DSSFont object that defines the text style (see more information in the section "Fonts usage")
//            textParameters.setFont(font);
            // Defines the text content
            textParameters.setText("My visual signature \n #1");
            // Defines the color of the characters
            textParameters.setTextColor(Color.BLUE);
            // Defines the background color for the area filled out by the text
            textParameters.setBackgroundColor(Color.YELLOW);
            // Defines a padding between the text and a border of its bounding area
            textParameters.setPadding(20);
            // Set textParameters to a SignatureImageParameters object
            imageParameters.setTextParameters(textParameters);

            // Specifies a text position relatively to an image (Note: applicable only for joint image+text visible signatures).
            // Thus with _SignerPosition.LEFT_ value, the text will be placed on the left side,
            // and image will be aligned to the right side inside the signature field
            textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
            // Specifies a horizontal alignment of a text with respect to its area
            textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
            // Specifies a vertical alignment of a text block with respect to a signature field area
            textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
            parameters.setImageParameters(imageParameters);


            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

            // Create PAdESService for signature
            PAdESService service = new PAdESService(commonCertificateVerifier);

            service.setPdfObjFactory(new PdfBoxNativeObjectFactory());

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);


            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

            // We invoke the xadesService to sign the document with the signature value obtained in the previous step.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            signedDocument.save("D:/tmp/signedByDSS_visible_signature.pdf");
        }
    }

    protected static void preparePdfDoc() {
        toSignDocument = new FileDocument(new File("src/main/resources/testPDF.pdf"));
    }

    private AbstractKeyStoreTokenConnection getPkcs12Token() throws IOException {
        return new KeyStoreSignatureTokenConnection(new File("src/main/resources/test.p12"), "PKCS12",
                new KeyStore.PasswordProtection("test".toCharArray()));
    }

    private PrivateKey getPrivateKeyFromTestP12File(){
        String fileName = "test.p12";
        String p12Password = "test";
        String keyAlias = "test_alias";
        return getPrivateKeyFromP12(fileName, keyAlias, p12Password, p12Password);
    }

    private PrivateKey getPrivateKeyFromP12(String fileName, String keyAlias, String p12Password, String certPassword){
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(this.getClass().getClassLoader().getResourceAsStream(fileName), p12Password.toCharArray());

            PrivateKey key = (PrivateKey)keystore.getKey(keyAlias, certPassword.toCharArray());

            return  key;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            return null;
        }
    }
}