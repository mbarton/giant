package model

import model.manifest.Blob

// TODO MRB: we should model pages as direct resources under their parent but that would change the extractor API
case class PageUri(documentBlobUri: Uri, pageNumber: Long) {
  // TODO MRB: I think this should really be {blob}/pages/{pageNumber} but I'm keen not to break the assumption in
  //           our data model that each path part corresponds to a :Resource node
  def toUri: Uri = documentBlobUri.chain(s"page-${pageNumber}")
}

object PageUri {
  // TODO MRB: as above, we should change the extractor API so that we extract any sub-resource of a blob
  def fromExtractorBlobUri(blob: Blob): PageUri = {
    blob.uri.value.split("/").toList match {
      case documentBlobUri :: pageNumber :: Nil => PageUri(Uri(documentBlobUri), pageNumber.toLong)
      case _ => throw new IllegalArgumentException(s"Unexpected page uri format ${blob.uri}")
    }
  }
}