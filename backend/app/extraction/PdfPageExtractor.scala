package extraction
import ingestion.IngestionContextBuilder
import model.Uri
import model.manifest.Blob
import org.apache.pdfbox.pdmodel.{PDDocument, PDPage}
import org.apache.pdfbox.rendering.PDFRenderer
import services.ingestion.IngestionServices
import services.previewing.PreviewService
import services.{ObjectStorage, ScratchSpace}
import utils.attempt.Failure

import java.io.File
import java.nio.file.Files

class PdfPageExtractor(scratch: ScratchSpace, previewStorage: ObjectStorage, ingestionServices: IngestionServices) extends FileExtractor(scratch) {
  val mimeTypes = Set(
    "application/pdf"
  )

  override def canProcessMimeType: String => Boolean = mimeTypes.contains

  override def indexing: Boolean = false

  override def priority: Int = 4

  override def extract(blob: Blob, file: File, params: ExtractionParams): Either[Failure, Unit] = {
    val builder = IngestionContextBuilder(blob.uri, params)
    var document: PDDocument = null

    try {
      document = PDDocument.load(file)

      val totalPages = document.getNumberOfPages

      for(pageNumber <- 1 until totalPages) {
        val page = document.getPage(pageNumber - 1)
        val pagePdfSize = uploadPageAsSeparatePdf(blob, pageNumber, page, previewStorage)

        ingestionServices.ingestPage(builder.finishWithPage(pageNumber), pagePdfSize)
      }

      Right(())
    } finally {
      document.close()
      Files.deleteIfExists(file.toPath)
    }
  }

  private def uploadPageAsSeparatePdf(blob: Blob, pageNumber: Int, page: PDPage, previewStorage: ObjectStorage): Long = {
    val doc = new PDDocument()
    val tempFile = Files.createTempFile(s"${blob.uri}-${pageNumber}", ".pdf")

    try {
      doc.importPage(page)
      doc.save(tempFile.toFile)

      val key = PreviewService.getPageStoragePath(blob.uri, language = None, pageNumber)
      previewStorage.create(key, tempFile, Some("application/pdf"))

      Files.size(tempFile)
    } finally {
      doc.close()
      Files.deleteIfExists(tempFile)
    }
  }
}
