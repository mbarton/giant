package model.ingestion

import model.{Language, Uri}

case class PageContext(documentBlobUri: Uri, pageNumber: Long, ingestion: String, languages: List[Language],
                       workspace: Option[WorkspaceItemContext])
