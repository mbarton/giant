namespace scala com.theguardian.giant.extractors

typedef map<string, list<string>> Metadata

struct File {
    1: required string path

    2: required i64 size

    3: optional i64 lastAccessTime

    4: optional i64 lastModifiedTime

    5: optional i64 creationTime

    // Set when the extractor already uploaded the blob to object storage (useful when streaming contents through memory)
    6: optional string blobId

    // Set when the extractor already knows the file type (eg email attachments)
    7: optional string mimeType

    8: optional Metadata metadata
}

struct EmailRecipient {
    1: string email

    2: optional string displayName
}

struct Email {
    1: required string subject

    2: required string body

    3: required list<string> inReplyTo

    4: required list<string> references

    5: required i64 attachmentCount

    // from is a reserved word in thrift :(
    // TODO MRB: we could use french thrift here but probably not worth the extra dep
    6: optional EmailRecipient emailFrom

    7: optional list<EmailRecipient> recipients

    8: optional string sentAt

    // TODO MRB: not sure it's worth an enum here?
    9: optional string sensitivity

    10: optional string priority

    11: optional string html

    12: optional Metadata metadata
}

// TODO MRB: page, table and more?!

struct ExtractorResult {
    1: required string extractorRepository

    2: required string extractorTag

    3: optional list<File> files

    4: optional list<Email> emails
}