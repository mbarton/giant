package extraction.ocr

import extraction.ExtractionParams
import model.{Language, PageUri}
import model.index.{Page, PageDimensions}
import model.manifest.{Blob, MimeType}
import org.apache.commons.io.FileUtils
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.text.PDFTextStripper
import services.{ObjectStorage, ScratchSpace}
import services.index.{Index, Pages}
import services.previewing.PreviewService
import services.ingestion.IngestionServices
import utils.{CustomMimeTypes, Logging, Ocr, OcrStderrLogger}

import java.io.File
import java.nio.file.{Files, Path}
import scala.concurrent.ExecutionContext

import utils.attempt.AttemptAwait._

class OcrMyPdfPageExtractor(scratch: ScratchSpace, pageService: Pages, previewStorage: ObjectStorage,
                        ingestionServices: IngestionServices)(implicit ec: ExecutionContext) extends BaseOcrExtractor(scratch) with Logging {

  val mimeTypes = Set(
    CustomMimeTypes.pdfPage.mimeType
  )

  override def canProcessMimeType = mimeTypes.contains

  override def indexing = true

  override def priority = 2

  override def cost(mimeType: MimeType, size: Long): Long = {
    100 * size
  }

  override def buildStdErrLogger(blob: Blob): OcrStderrLogger = {
    // No need for a progress note here, the number of outstanding TODOs gives us the same information
    new OcrStderrLogger(None)
  }

  override def extractOcr(blob: Blob, file: File, params: ExtractionParams, stdErrLogger: OcrStderrLogger): Unit = {
    val tmpDir = scratch.createWorkingDir(s"ocrmypdf-tmp-${blob.uri.value}")
    var pdDocuments: Map[Language, (Path, PDDocument)] = Map.empty

    val pageUri = PageUri.fromExtractorBlobUri(blob)

    try {
      pdDocuments = params.languages.map { lang =>
        val pdfPath = Ocr.invokeOcrMyPdf(lang.ocr, file.toPath, None, stdErrLogger, tmpDir)
        val pdfDoc = PDDocument.load(pdfPath.toFile)

        lang -> (pdfPath, pdfDoc)
      }.toMap

      // All docs have a single page with the same dimensions, just different text from the OCR run per language
      val (firstLang, (firstPath, firstDoc)) = pdDocuments.head

      val page = firstDoc.getPage(0)
      val pageBoundingBox = page.getMediaBox

      val dimensions = PageDimensions(
        width = pageBoundingBox.getWidth,
        height = pageBoundingBox.getHeight,
        // TODO MRB: supporting the old pages API here would be a blocker
        // Each extractor is running independently so we have no way of calculating the offsetHeight
        // It doesn't matter for the pages 2 API which is done by page number anyway so if we're happy to stick with
        // that we can stop recording the page geometry in Elasticsearch entirely I think?
        top = 0.0,
        bottom = pageBoundingBox.getHeight
      )

      val textByLanguage = pdDocuments.map { case (lang, (_, doc)) =>
        assert(doc.getNumberOfPages == 1, s"Number of pages mismatch across languages: ${pdDocuments.mapValues(_._2.getNumberOfPages)}")

        val reader = new PDFTextStripper()
        reader.setStartPage(1)
        reader.setEndPage(1)

        val text = reader.getText(doc)
        lang -> text
      }

      // Write to the page index in Elasticsearch - a document in the index corresponds to a single page
      val esPage = Page(pageUri.pageNumber, textByLanguage, dimensions)

      pageService.addPageContents(pageUri.documentBlobUri, Seq(esPage)).await()

      // TODO MRB: Blocker! How are we going to write the full document text to the index?
      //           A la OcrMyPdfExtractor.insertFullText (addDocumentOcr)
      //           Could use scripted updates but tbh wouldn't it be better to search the page index
      //           so you can go straight to the page without the "find first highlight" hack

      val previewKey = PreviewService.getPageStoragePath(pageUri.documentBlobUri, Some(firstLang), pageUri.pageNumber.toInt)

      // TODO MRB: what to do with the pdfs with other languages? (the existing extractors didn't handle this anyway)
      previewStorage.create(previewKey, firstPath, Some("application/pdf"))
    } finally {
      pdDocuments.foreach { case (_, (path, doc)) =>
        doc.close()
        Files.deleteIfExists(path)
      }

      FileUtils.deleteDirectory(tmpDir.toFile)
    }
  }
}
