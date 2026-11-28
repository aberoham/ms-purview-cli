//! Reading Outlook `.msg` files (`docs/SPEC.md` sections 4.11 and 7.7):
//! the Compound File Binary container (`cfbread`), the MAPI properties of
//! MS-OXMSG (`props`) and the body selection (`body`). Everything here is
//! pure: it reads bytes already in memory and touches no file or network.

pub mod body;
pub mod cfbread;
pub mod props;

use chrono::{DateTime, Utc};

use body::Body;
use cfbread::Container;
use props::{Header, Props};

/// One `.msg` item, as read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsgItem {
    pub class: Option<String>,
    pub subject: Option<String>,
    pub conversation_topic: Option<String>,
    pub internet_message_id: Option<String>,
    pub from: Option<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub sent: Option<DateTime<Utc>>,
    pub received: Option<DateTime<Utc>>,
    pub attachments: Vec<AttachmentInfo>,
    /// The body chosen, or why there is none.
    pub body: Body,
}

/// A sender or recipient: display name and address, either of which may be
/// missing. The address is SMTP when the item has one, else whatever
/// address type it records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub address: Option<String>,
}

/// An attachment's name and size; its content is never read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttachmentInfo {
    pub name: Option<String>,
    pub size: Option<u64>,
}

/// Why an item could not be read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgError {
    /// The bytes are not a Compound File Binary container that can be read.
    CfbInvalid(String),
}

impl MsgError {
    /// The record's `error` code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::CfbInvalid(_) => "cfbInvalid",
        }
    }

    /// The record's `errorDetail`.
    pub fn detail(&self) -> &str {
        match self {
            Self::CfbInvalid(detail) => detail,
        }
    }
}

/// Property ids read (MS-OXPROPS).
mod id {
    pub const MESSAGE_CLASS: u16 = 0x001A;
    pub const SUBJECT: u16 = 0x0037;
    pub const CLIENT_SUBMIT_TIME: u16 = 0x0039;
    pub const CONVERSATION_TOPIC: u16 = 0x0070;
    pub const SENDER_NAME: u16 = 0x0C1A;
    pub const SENDER_EMAIL_ADDRESS: u16 = 0x0C1F;
    pub const RECIPIENT_TYPE: u16 = 0x0C15;
    pub const MESSAGE_DELIVERY_TIME: u16 = 0x0E06;
    pub const ATTACH_SIZE: u16 = 0x0E20;
    pub const BODY: u16 = 0x1000;
    pub const RTF_COMPRESSED: u16 = 0x1009;
    pub const HTML: u16 = 0x1013;
    pub const INTERNET_MESSAGE_ID: u16 = 0x1035;
    pub const DISPLAY_NAME: u16 = 0x3001;
    pub const EMAIL_ADDRESS: u16 = 0x3003;
    pub const ATTACH_FILENAME: u16 = 0x3704;
    pub const ATTACH_LONG_FILENAME: u16 = 0x3707;
    pub const SMTP_ADDRESS: u16 = 0x39FE;
    pub const INTERNET_CODEPAGE: u16 = 0x3FDE;
    pub const MESSAGE_CODEPAGE: u16 = 0x3FFD;
    pub const SENDER_SMTP_ADDRESS: u16 = 0x5D01;
    pub const SENT_REPRESENTING_SMTP_ADDRESS: u16 = 0x5D02;
}

/// Reads one `.msg` from memory.
pub fn parse_msg(bytes: &[u8]) -> Result<MsgItem, MsgError> {
    let mut container = Container::open(bytes)?;
    let mut message = Props::open(&mut container, "", Header::Message)?;
    // The code page of 8-bit strings in the message (Docs: MS-OXMSG
    // 2.1.2); windows-1252 when absent.
    let string_codepage = message.long(id::MESSAGE_CODEPAGE);
    message.set_string_codepage(string_codepage);
    let class = message.string(id::MESSAGE_CLASS);
    let from_name = message.string(id::SENDER_NAME);
    let from_address = message
        .string(id::SENDER_SMTP_ADDRESS)
        .or_else(|| message.string(id::SENDER_EMAIL_ADDRESS))
        .or_else(|| message.string(id::SENT_REPRESENTING_SMTP_ADDRESS));
    let from = (from_name.is_some() || from_address.is_some()).then(|| Mailbox {
        name: from_name,
        address: from_address,
    });
    let html = message.html(id::HTML);
    let text = message.string(id::BODY);
    let rtf = message.exists(id::RTF_COMPRESSED);
    let internet_codepage = message.long(id::INTERNET_CODEPAGE);
    let mut item = MsgItem {
        subject: message.string(id::SUBJECT),
        conversation_topic: message.string(id::CONVERSATION_TOPIC),
        internet_message_id: message.string(id::INTERNET_MESSAGE_ID),
        from,
        sent: message.time(id::CLIENT_SUBMIT_TIME),
        received: message.time(id::MESSAGE_DELIVERY_TIME),
        body: body::select(html, text, rtf, internet_codepage, class.as_deref()),
        class,
        ..MsgItem::default()
    };
    drop(message);

    for storage in container.children("", "__recip_version1.0_#") {
        let mut recipient = Props::open(&mut container, &storage, Header::Recipient)?;
        recipient.set_string_codepage(string_codepage);
        let mailbox = Mailbox {
            name: recipient.string(id::DISPLAY_NAME),
            address: recipient
                .string(id::SMTP_ADDRESS)
                .or_else(|| recipient.string(id::EMAIL_ADDRESS)),
        };
        // MAPI_TO 1, MAPI_CC 2, MAPI_BCC 3 (Docs: MS-OXOMSG); anything else
        // is listed as To.
        match recipient.long(id::RECIPIENT_TYPE) {
            Some(2) => item.cc.push(mailbox),
            Some(3) => item.bcc.push(mailbox),
            _ => item.to.push(mailbox),
        }
    }
    for storage in container.children("", "__attach_version1.0_#") {
        let mut attachment = Props::open(&mut container, &storage, Header::Attachment)?;
        attachment.set_string_codepage(string_codepage);
        item.attachments.push(AttachmentInfo {
            name: attachment
                .string(id::ATTACH_LONG_FILENAME)
                .or_else(|| attachment.string(id::ATTACH_FILENAME)),
            size: attachment.long(id::ATTACH_SIZE).map(u64::from),
        });
        drop(attachment);
        // Exported attachments carry no PidTagAttachSize (Observed), so the
        // length of the data stream stands in for it.
        if let Some(last) = item.attachments.last_mut() {
            if last.size.is_none() {
                last.size = container.stream_len(&storage, "__substg1.0_37010102");
            }
        }
    }
    Ok(item)
}
