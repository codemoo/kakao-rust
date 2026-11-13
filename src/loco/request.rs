//! LOCO request body builders.
//! Inputs are explicit: this module does not invent protocol revisions or cursors.
use bson::{doc, spec::BinarySubtype, Binary, Bson, Document};

pub fn getconf(user_id: i64, mccmnc: &str) -> Document {
    doc! {"MCCMNC":mccmnc,"os":"android","userId":user_id}
}
pub fn checkin(
    user_id: i64,
    network_type: i32,
    app_version: &str,
    language: &str,
    mccmnc: &str,
    use_sub: bool,
) -> Document {
    let mut body = doc! {"userId":user_id,"os":"android","ntype":network_type,"appVer":app_version,"lang":language};
    if use_sub {
        body.insert("useSub", true);
    }
    if !mccmnc.trim().is_empty() {
        body.insert("MCCMNC", mccmnc);
    }
    body
}
/// No Debug: includes the native connection credential.
pub struct LoginList<'a> {
    pub app_version: &'a str,
    pub protocol_version: &'a str,
    pub language: &'a str,
    pub device_uuid: &'a str,
    pub network_type: i32,
    pub mccmnc: &'a str,
    pub revision: i32,
    pub chat_ids: &'a [i64],
    pub max_ids: &'a [i64],
    pub last_token_id: i64,
    pub last_blind_token_id: i32,
    pub block_revision: i16,
    pub plus_block_revision: i16,
    pub is_background: bool,
    pub oauth_token: &'a str,
}
impl LoginList<'_> {
    pub fn body(&self) -> Document {
        let mut revisions = Vec::with_capacity(6);
        for revision in [self.block_revision, -1, self.plus_block_revision] {
            revisions.extend_from_slice(&revision.to_le_bytes());
        }
        doc! {
            "appVer":self.app_version,"prtVer":self.protocol_version,"os":"android","lang":self.language,
            "duuid":self.device_uuid,"ntype":self.network_type,"MCCMNC":self.mccmnc,"revision":self.revision,
            "chatIds":self.chat_ids.iter().copied().map(Bson::Int64).collect::<Vec<_>>(),
            "maxIds":self.max_ids.iter().copied().map(Bson::Int64).collect::<Vec<_>>(),
            "lastTokenId":self.last_token_id,"lbk":self.last_blind_token_id,
            "rp":Binary {subtype:BinarySubtype::Generic,bytes:revisions},
            "bg":self.is_background,"oauthToken":self.oauth_token
        }
    }
}
pub fn chatinfo(chat_id: i64) -> Document {
    doc! {"chatId":chat_id}
}
pub fn getmem(chat_id: i64) -> Document {
    doc! {"chatId":chat_id}
}
pub fn memlist(chat_id: i64) -> Document {
    doc! {"chatId":chat_id,"token":0_i64,"excludeMe":true}
}
pub fn member(chat_id: i64, ids: &[i64]) -> Document {
    doc! {"chatId":chat_id,"memberIds":ids.iter().copied().map(Bson::Int64).collect::<Vec<_>>()}
}
pub fn getmsgs(chat_ids: &[i64], log_ids: &[i64]) -> Document {
    doc! {"chatIds":chat_ids.iter().copied().map(Bson::Int64).collect::<Vec<_>>(),"logIds":log_ids.iter().copied().map(Bson::Int64).collect::<Vec<_>>()}
}
pub fn syncmsg(chat_id: i64, current: i64, max: i64, count: i32) -> Document {
    doc! {"chatId":chat_id,"cur":current,"max":max,"cnt":count}
}
pub fn lchatlist(
    chat_ids: &[i64],
    max_ids: &[i64],
    last_token_id: i64,
    last_chat_id: i64,
) -> Document {
    doc! {"chatIds":chat_ids.iter().copied().map(Bson::Int64).collect::<Vec<_>>(),
    "maxIds":max_ids.iter().copied().map(Bson::Int64).collect::<Vec<_>>(),
    "lastTokenId":last_token_id,"lastChatId":last_chat_id}
}
pub fn gettoken() -> Document {
    doc! {"ts":[2_i32,3,11,12,4,9,10,18,19]}
}
pub fn message_ack(noti_read: bool) -> Document {
    doc! {"notiRead":noti_read}
}
pub fn ping() -> Document {
    Document::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkin_omits_absent_optional_fields_and_keeps_numeric_types() {
        let minimal = checkin(42, 0, "26.3.2", "ko", "", false);
        assert_eq!(minimal.len(), 5);
        assert_eq!(minimal.get_i64("userId").unwrap(), 42);
        assert_eq!(minimal.get_i32("ntype").unwrap(), 0);
        let secondary = checkin(42, 0, "26.3.2", "ko", "45008", true);
        assert!(secondary.get_bool("useSub").unwrap());
        assert_eq!(secondary.get_str("MCCMNC").unwrap(), "45008");
    }
    #[test]
    fn loginlist_bson_preserves_64_bit_ids_and_signed_revision_bytes() {
        let input = LoginList {
            app_version: "26.3.2",
            protocol_version: "test-revision",
            language: "ko",
            device_uuid: "synthetic-uuid",
            network_type: 0,
            mccmnc: "",
            revision: 3,
            chat_ids: &[9007199254740993],
            max_ids: &[9223372036854775806],
            last_token_id: 0,
            last_blind_token_id: 0,
            block_revision: 0x1234,
            plus_block_revision: -2,
            is_background: true,
            oauth_token: "synthetic-access",
        };
        let body = input.body();
        let bytes = bson::to_vec(&body).unwrap();
        let parsed = bson::Document::from_reader(&mut bytes.as_slice()).unwrap();
        assert_eq!(
            parsed.get_binary_generic("rp").unwrap(),
            &[0x34, 0x12, 0xff, 0xff, 0xfe, 0xff]
        );
        assert_eq!(
            parsed.get_array("chatIds").unwrap(),
            &[Bson::Int64(9007199254740993)]
        );
        assert_eq!(
            parsed.get_array("maxIds").unwrap(),
            &[Bson::Int64(9223372036854775806)]
        );
        assert_eq!(parsed.len(), 15);
    }
}
