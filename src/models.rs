use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
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
/// This mirrors every uploaded field persisted by the ingester so a fresh
/// snapshot cannot leave stale columns behind on an existing row.
#[derive(Debug, sqlx::FromRow)]
pub struct VeteranCharacterRow {
    pub trained_chara_id: i64,
    pub card_id: Option<i32>,
    pub scenario_id: Option<i32>,
    pub route_id: Option<i32>,
    pub rarity: Option<i32>,
    pub succession_trained_chara_id_1: Option<i64>,
    pub succession_trained_chara_id_2: Option<i64>,
    pub succession_num: Option<i32>,
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
    pub race_cloth_id: Option<i32>,
    pub nickname_id: Option<i32>,
    pub wins: Option<i32>,
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
    pub register_time: Option<DateTime<Utc>>,
    pub create_time: Option<DateTime<Utc>>,
}

/// Parse game timestamp string into UTC.
pub fn parse_game_time(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|ndt| Utc.from_utc_datetime(&ndt))
}

/// Returns true if the uploaded character differs from the stored row
/// in any field persisted by the ingester.
pub fn has_changed(upload: &VeteranCharacter, existing: &VeteranCharacterRow) -> bool {
    let empty = serde_json::Value::Array(vec![]);
    let register_time = upload.register_time.as_deref().and_then(parse_game_time);
    let create_time = upload.create_time.as_deref().and_then(parse_game_time);

    upload.card_id != existing.card_id
        || upload.scenario_id != existing.scenario_id
        || upload.route_id != existing.route_id
        || upload.rarity != existing.rarity
        || upload.succession_trained_chara_id_1 != existing.succession_trained_chara_id_1
        || upload.succession_trained_chara_id_2 != existing.succession_trained_chara_id_2
        || upload.succession_num != existing.succession_num
        || upload.speed != existing.speed
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
        || upload.race_cloth_id != existing.race_cloth_id
        || upload.nickname_id != existing.nickname_id
        || upload.wins != existing.wins
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
        || upload.succession_chara_array.as_ref().unwrap_or(&empty)
            != &existing.succession_chara_array
        || register_time != existing.register_time
        || create_time != existing.create_time
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn upload() -> VeteranCharacter {
        VeteranCharacter {
            trained_chara_id: 1,
            card_id: Some(1001),
            scenario_id: Some(2),
            route_id: Some(3),
            rarity: Some(5),
            succession_trained_chara_id_1: Some(10),
            succession_trained_chara_id_2: Some(11),
            succession_num: Some(2),
            speed: Some(1200),
            stamina: Some(900),
            power: Some(1100),
            wiz: Some(800),
            guts: Some(700),
            fans: Some(123456),
            rank_score: Some(456789),
            rank: Some(7),
            chara_grade: Some(4),
            talent_level: Some(5),
            running_style: Some(2),
            race_cloth_id: Some(3001),
            nickname_id: Some(4001),
            wins: Some(12),
            proper_ground_turf: Some(8),
            proper_ground_dirt: Some(1),
            proper_running_style_nige: Some(2),
            proper_running_style_senko: Some(8),
            proper_running_style_sashi: Some(5),
            proper_running_style_oikomi: Some(3),
            proper_distance_short: Some(4),
            proper_distance_mile: Some(8),
            proper_distance_middle: Some(7),
            proper_distance_long: Some(2),
            skill_array: Some(json!([{"skill_id": 1}])),
            support_card_list: Some(json!([{"support_card_id": 2}])),
            factor_info_array: Some(json!([{"factor_id": 3}])),
            win_saddle_id_array: Some(json!([100, 200])),
            succession_chara_array: Some(json!([{"trained_chara_id": 4}])),
            register_time: Some("2026-01-02 03:04:05".to_string()),
            create_time: Some("2026-01-01 02:03:04".to_string()),
        }
    }

    fn row() -> VeteranCharacterRow {
        VeteranCharacterRow {
            trained_chara_id: 1,
            card_id: Some(1001),
            scenario_id: Some(2),
            route_id: Some(3),
            rarity: Some(5),
            succession_trained_chara_id_1: Some(10),
            succession_trained_chara_id_2: Some(11),
            succession_num: Some(2),
            speed: Some(1200),
            stamina: Some(900),
            power: Some(1100),
            wiz: Some(800),
            guts: Some(700),
            fans: Some(123456),
            rank_score: Some(456789),
            rank: Some(7),
            chara_grade: Some(4),
            talent_level: Some(5),
            running_style: Some(2),
            race_cloth_id: Some(3001),
            nickname_id: Some(4001),
            wins: Some(12),
            proper_ground_turf: Some(8),
            proper_ground_dirt: Some(1),
            proper_running_style_nige: Some(2),
            proper_running_style_senko: Some(8),
            proper_running_style_sashi: Some(5),
            proper_running_style_oikomi: Some(3),
            proper_distance_short: Some(4),
            proper_distance_mile: Some(8),
            proper_distance_middle: Some(7),
            proper_distance_long: Some(2),
            skill_array: json!([{"skill_id": 1}]),
            support_card_list: json!([{"support_card_id": 2}]),
            factor_info_array: json!([{"factor_id": 3}]),
            win_saddle_id_array: json!([100, 200]),
            succession_chara_array: json!([{"trained_chara_id": 4}]),
            register_time: parse_game_time("2026-01-02 03:04:05"),
            create_time: parse_game_time("2026-01-01 02:03:04"),
        }
    }

    #[test]
    fn unchanged_snapshot_is_not_changed() {
        assert!(!has_changed(&upload(), &row()));
    }

    #[test]
    fn detects_changed_card_identity() {
        let mut upload = upload();
        upload.card_id = Some(9999);

        assert!(has_changed(&upload, &row()));
    }

    #[test]
    fn detects_changed_metadata_fields() {
        let mut upload = upload();
        upload.race_cloth_id = Some(9999);

        assert!(has_changed(&upload, &row()));
    }

    #[test]
    fn detects_changed_game_timestamps() {
        let mut upload = upload();
        upload.create_time = Some("2026-02-01 02:03:04".to_string());

        assert!(has_changed(&upload, &row()));
    }
}
