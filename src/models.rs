use serde::{Deserialize, Serialize};

/// One entry in the veteran list JSON array as uploaded by the client.
/// All fields except `trained_chara_id` are optional to be resilient
/// against schema additions in game updates.
#[derive(Debug, Deserialize, Clone)]
pub struct VeteranCharacter {
    pub trained_chara_id: i64,

    // Card / scenario
    pub card_id: Option<i32>,
    pub scenario_id: Option<i32>,
    pub route_id: Option<i32>,
    pub rarity: Option<i32>,
    pub succession_trained_chara_id_1: Option<i64>,
    pub succession_trained_chara_id_2: Option<i64>,
    pub succession_num: Option<i32>,

    // Stats
    pub speed: Option<i32>,
    pub stamina: Option<i32>,
    pub power: Option<i32>,
    pub wiz: Option<i32>,
    pub guts: Option<i32>,
    pub fans: Option<i32>,
    pub rank_score: Option<i64>,
    pub rank: Option<i32>,

    // Grade / style
    pub chara_grade: Option<i32>,
    pub talent_level: Option<i32>,
    pub running_style: Option<i32>,
    pub race_cloth_id: Option<i32>,
    pub nickname_id: Option<i32>,
    pub wins: Option<i32>,

    // Aptitudes
    pub proper_ground_turf: Option<i32>,
    pub proper_ground_dirt: Option<i32>,
    pub proper_running_style_nige: Option<i32>,
    pub proper_running_style_senko: Option<i32>,
    pub proper_running_style_sashi: Option<i32>,
    pub proper_running_style_oikomi: Option<i32>,
    pub proper_distance_short: Option<i32>,
    pub proper_distance_mile: Option<i32>,
    pub proper_distance_middle: Option<i32>,
    pub proper_distance_long: Option<i32>,

    // JSONB arrays
    pub skill_array: Option<serde_json::Value>,
    pub support_card_list: Option<serde_json::Value>,
    pub factor_info_array: Option<serde_json::Value>,
    pub win_saddle_id_array: Option<serde_json::Value>,
    pub succession_chara_array: Option<serde_json::Value>,

    // Timestamps as plain strings from game export ("YYYY-MM-DD HH:MM:SS")
    pub register_time: Option<String>,
    pub create_time: Option<String>,
}

/// Fields read from the DB for change detection.
/// Only the mutable fields are included — immutable ones (card_id, create_time, etc.)
/// are not compared.
#[derive(Debug, sqlx::FromRow)]
pub struct VeteranCharacterRow {
    pub trained_chara_id: i64,
    pub speed: Option<i32>,
    pub stamina: Option<i32>,
    pub power: Option<i32>,
    pub wiz: Option<i32>,
    pub guts: Option<i32>,
    pub fans: Option<i32>,
    pub rank_score: Option<i64>,
    pub rank: Option<i32>,
    pub chara_grade: Option<i32>,
    pub talent_level: Option<i32>,
    pub running_style: Option<i32>,
    pub proper_ground_turf: Option<i32>,
    pub proper_ground_dirt: Option<i32>,
    pub proper_running_style_nige: Option<i32>,
    pub proper_running_style_senko: Option<i32>,
    pub proper_running_style_sashi: Option<i32>,
    pub proper_running_style_oikomi: Option<i32>,
    pub proper_distance_short: Option<i32>,
    pub proper_distance_mile: Option<i32>,
    pub proper_distance_middle: Option<i32>,
    pub proper_distance_long: Option<i32>,
    pub skill_array: serde_json::Value,
    pub support_card_list: serde_json::Value,
    pub factor_info_array: serde_json::Value,
    pub win_saddle_id_array: serde_json::Value,
    pub succession_chara_array: serde_json::Value,
}

/// Returns true if the uploaded character differs from the stored row
/// in any field that can change between uploads.
pub fn has_changed(upload: &VeteranCharacter, existing: &VeteranCharacterRow) -> bool {
    let empty = serde_json::Value::Array(vec![]);

    upload.speed != existing.speed
        || upload.stamina != existing.stamina
        || upload.power != existing.power
        || upload.wiz != existing.wiz
        || upload.guts != existing.guts
        || upload.fans != existing.fans
        || upload.rank_score != existing.rank_score
        || upload.rank != existing.rank
        || upload.chara_grade != existing.chara_grade
        || upload.talent_level != existing.talent_level
        || upload.running_style != existing.running_style
        || upload.proper_ground_turf != existing.proper_ground_turf
        || upload.proper_ground_dirt != existing.proper_ground_dirt
        || upload.proper_running_style_nige != existing.proper_running_style_nige
        || upload.proper_running_style_senko != existing.proper_running_style_senko
        || upload.proper_running_style_sashi != existing.proper_running_style_sashi
        || upload.proper_running_style_oikomi != existing.proper_running_style_oikomi
        || upload.proper_distance_short != existing.proper_distance_short
        || upload.proper_distance_mile != existing.proper_distance_mile
        || upload.proper_distance_middle != existing.proper_distance_middle
        || upload.proper_distance_long != existing.proper_distance_long
        || upload.skill_array.as_ref().unwrap_or(&empty) != &existing.skill_array
        || upload.support_card_list.as_ref().unwrap_or(&empty) != &existing.support_card_list
        || upload.factor_info_array.as_ref().unwrap_or(&empty) != &existing.factor_info_array
        || upload.win_saddle_id_array.as_ref().unwrap_or(&empty) != &existing.win_saddle_id_array
        || upload.succession_chara_array.as_ref().unwrap_or(&empty) != &existing.succession_chara_array
}

/// Response returned after a successful ingest.
#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub inserted: i64,
    pub updated: i64,
    pub deleted: i64,
    pub total: i64,
}

/// Optional query parameters for the ingest endpoint.
#[derive(Debug, Deserialize, Default)]
pub struct VeteranListParams {
    /// Required when the authenticated user has more than one verified linked account.
    pub account_id: Option<String>,
}
