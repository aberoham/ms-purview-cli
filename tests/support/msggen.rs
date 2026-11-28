//! `msggen`: synthetic `.msg` files for tests (`docs/SPEC.md` section 8.7),
//! written with the `cfb` crate in the MS-OXMSG layout: variable-length
//! properties as `__substg1.0_<id><type>` streams, fixed-size ones in
//! `__properties_version1.0`, recipients and attachments as storages.
//! Only synthetic `contoso.example` and `fabrikam.example` data goes in.

use std::io::{Cursor, Write};

const PT_LONG: u16 = 0x0003;
const PT_SYSTIME: u16 = 0x0040;
const PT_STRING8: u16 = 0x001E;
const PT_UNICODE: u16 = 0x001F;
const PT_BINARY: u16 = 0x0102;

/// A property value.
#[derive(Debug, Clone)]
pub enum Value {
    Unicode(String),
    String8(Vec<u8>),
    Binary(Vec<u8>),
    Long(u32),
    /// A FILETIME, from Unix seconds.
    Time(i64),
}

/// One storage's properties.
#[derive(Debug, Clone, Default)]
pub struct Props(pub Vec<(u16, Value)>);

impl Props {
    /// The properties with `id` set to `value`, replacing any it had.
    pub fn with(mut self, id: u16, value: Value) -> Self {
        self.0.retain(|(have, _)| *have != id);
        self.0.push((id, value));
        self
    }

    /// The properties without `id`.
    pub fn without(mut self, id: u16) -> Self {
        self.0.retain(|(have, _)| *have != id);
        self
    }
}

/// A recipient: display name, SMTP address and type (1 To, 2 CC, 3 BCC).
pub fn recipient(name: &str, address: &str, kind: u32) -> Props {
    Props::default()
        .with(0x3001, Value::Unicode(name.into()))
        .with(0x39FE, Value::Unicode(address.into()))
        .with(0x0C15, Value::Long(kind))
}

/// An attachment with a long file name and its data, and no size
/// property, as the observed exports have.
pub fn attachment(name: &str, data: &[u8]) -> Props {
    Props::default()
        .with(0x3707, Value::Unicode(name.into()))
        .with(0x3701, Value::Binary(data.to_vec()))
}

/// A message: its own properties, recipients and attachments.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub props: Props,
    pub recipients: Vec<Props>,
    pub attachments: Vec<Props>,
}

impl Message {
    /// An `IPM.Note` from alex@contoso.example to sam@contoso.example, with
    /// `subject`, sent and delivered 2026-01-05T09:00:00Z.
    pub fn note(subject: &str) -> Self {
        Self {
            props: Props::default()
                .with(0x001A, Value::Unicode("IPM.Note".into()))
                .with(0x0037, Value::Unicode(subject.into()))
                .with(0x0042, Value::Unicode("Alex Example".into()))
                .with(0x5D02, Value::Unicode("alex@contoso.example".into()))
                .with(0x0C1A, Value::Unicode("Alex Example".into()))
                .with(0x5D01, Value::Unicode("alex@contoso.example".into()))
                .with(0x0039, Value::Time(1_767_603_600))
                .with(0x0E06, Value::Time(1_767_603_601)),
            recipients: vec![recipient("Sam Example", "sam@contoso.example", 1)],
            attachments: Vec::new(),
        }
    }

    pub fn with(mut self, id: u16, value: Value) -> Self {
        self.props = std::mem::take(&mut self.props).with(id, value);
        self
    }

    pub fn without(mut self, id: u16) -> Self {
        self.props = std::mem::take(&mut self.props).without(id);
        self
    }

    /// The `.msg` bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut file = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        // The message header (MS-OXMSG 2.4.1.1): 8 reserved bytes, the next
        // recipient and attachment ids, their counts, 8 reserved bytes.
        let mut header = vec![0_u8; 8];
        for count in [self.recipients.len(), self.attachments.len()] {
            header.extend_from_slice(&(count as u32).to_le_bytes());
        }
        for count in [self.recipients.len(), self.attachments.len()] {
            header.extend_from_slice(&(count as u32).to_le_bytes());
        }
        header.extend_from_slice(&[0; 8]);
        write_props(&mut file, "", &self.props, header);
        for (index, props) in self.recipients.iter().enumerate() {
            let storage = format!("__recip_version1.0_#{index:08X}");
            file.create_storage(format!("/{storage}")).unwrap();
            write_props(&mut file, &storage, props, vec![0; 8]);
        }
        for (index, props) in self.attachments.iter().enumerate() {
            let storage = format!("__attach_version1.0_#{index:08X}");
            file.create_storage(format!("/{storage}")).unwrap();
            write_props(&mut file, &storage, props, vec![0; 8]);
        }
        file.flush().unwrap();
        file.into_inner().into_inner()
    }
}

fn write_props(
    file: &mut cfb::CompoundFile<Cursor<Vec<u8>>>,
    storage: &str,
    props: &Props,
    header: Vec<u8>,
) {
    let base = if storage.is_empty() {
        String::new()
    } else {
        format!("/{storage}")
    };
    let mut fixed = header;
    for (id, value) in &props.0 {
        let (kind, stream): (u16, Option<Vec<u8>>) = match value {
            Value::Unicode(text) => (
                PT_UNICODE,
                Some(text.encode_utf16().flat_map(u16::to_le_bytes).collect()),
            ),
            Value::String8(bytes) => (PT_STRING8, Some(bytes.clone())),
            Value::Binary(bytes) => (PT_BINARY, Some(bytes.clone())),
            Value::Long(number) => {
                fixed.extend_from_slice(
                    &((u32::from(*id) << 16) | u32::from(PT_LONG)).to_le_bytes(),
                );
                fixed.extend_from_slice(&6_u32.to_le_bytes());
                fixed.extend_from_slice(&number.to_le_bytes());
                fixed.extend_from_slice(&[0; 4]);
                (PT_LONG, None)
            }
            Value::Time(seconds) => {
                let ticks = ((*seconds + 11_644_473_600) as u64) * 10_000_000;
                fixed.extend_from_slice(
                    &((u32::from(*id) << 16) | u32::from(PT_SYSTIME)).to_le_bytes(),
                );
                fixed.extend_from_slice(&6_u32.to_le_bytes());
                fixed.extend_from_slice(&ticks.to_le_bytes());
                (PT_SYSTIME, None)
            }
        };
        if let Some(bytes) = stream {
            // A variable-length value also has an entry in the property
            // table: its size, with a terminating NUL counted for strings
            // (MS-OXMSG 2.4.2.2).
            let size = bytes.len() as u32
                + match kind {
                    PT_UNICODE => 2,
                    PT_STRING8 => 1,
                    _ => 0,
                };
            fixed.extend_from_slice(&((u32::from(*id) << 16) | u32::from(kind)).to_le_bytes());
            fixed.extend_from_slice(&6_u32.to_le_bytes());
            fixed.extend_from_slice(&size.to_le_bytes());
            fixed.extend_from_slice(&[0; 4]);
            let mut stream = file
                .create_stream(format!("{base}/__substg1.0_{id:04X}{kind:04X}"))
                .unwrap();
            stream.write_all(&bytes).unwrap();
        }
    }
    let mut stream = file
        .create_stream(format!("{base}/__properties_version1.0"))
        .unwrap();
    stream.write_all(&fixed).unwrap();
}

/// A zip of `.msg` entries, stored as the observed items parts are.
pub fn items_zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    buffer.into_inner()
}
