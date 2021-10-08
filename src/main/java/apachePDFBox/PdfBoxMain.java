package apachePDFBox;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.util.Calendar;

public class PdfBoxMain {

    public static void main(String[] args) {
        signPDF();
    }

    private static void signPDF() {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            // add some text as content for the empty PDF
            PDPageContentStream contentStream = new PDPageContentStream(document, page);
            contentStream.beginText();
            contentStream.setFont(PDType1Font.TIMES_ROMAN, 12);
            contentStream.newLineAtOffset(25, 500);
            String text = "This document will be signed.";
            contentStream.showText(text);
            contentStream.endText();
            contentStream.close();

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ENTRUST_PPKEF);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_X509_RSA_SHA1);
            signature.setName("Example User");
            signature.setLocation("Basel, Switzerland");
            signature.setReason("Testing...");
            signature.setSignDate(Calendar.getInstance());

            document.addSignature(signature);

            document.save("D:/tmp/signedByApachePDFBox.pdf");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
