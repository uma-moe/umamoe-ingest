use std::collections::{HashMap, HashSet};

use axum::{
    body::Bytes,
    extract::{Query, State},
    Json,
};
use chrono::{NaiveDateTime, TimeZone, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedUser,
    errors::{AppError, Result},
    models::{has_changed, IngestResponse, VeteranCharacter, VeteranCharacterRow, VeteranListParams},
    AppState,
};

pub async fn veteran_list(
    State(state): State<AppState>,
    Query(params): Query<VeteranListParams>,
    authenticated: AuthenticatedUser,
    body: Bytes,
) -> Result<Json<IngestResponse>> {
    // --- 1. Parse body ---
    let characters: Vec<VeteranCharacter> = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {}", e)))?;

    if characters.is_empty() {
        return Err(AppError::BadRequest("Veteran list must not be empty".into()));
    }

    // Guard: maximum 512 veterans per account
    const MAX_VETERANS: usize = 512;
    if characters.len() > MAX_VETERANS {
        return Err(AppError::BadRequest(format!(
            "Upload contains {} characters; maximum allowed is {}",
            characters.len(),
            MAX_VETERANS
        )));
    }

    // Guard: ensure no duplicate trained_chara_id in a single upload
    {
        let mut seen = HashSet::with_capacity(characters.len());
        for c in &characters {
            if !seen.insert(c.trained_chara_id) {
                return Err(AppError::BadRequest(format!(
                    "Duplicate trained_chara_id {} in upload",
                    c.trained_chara_id
                )));
            }
        }
    }

    // --- 2. Resolve account_id from user ---
    let account_id =
        resolve_account_id(&state.db, authenticated.user_id, params.account_id.as_deref())
            .await?;

    // --- 3. Load existing rows for change detection ---
    let existing_rows = sqlx::query_as::<_, VeteranCharacterRow>(
        r#"
        SELECT
            trained_chara_id, speed, stamina, power, wiz, guts, fans,
            rank_score, rank, chara_grade, talent_level, running_style,
            proper_ground_turf, proper_ground_dirt,
            proper_running_style_nige, proper_running_style_senko,
            proper_running_style_sashi, proper_running_style_oikomi,
            proper_distance_short, proper_distance_mile,
            proper_distance_middle, proper_distance_long,
            skill_array, support_card_list, factor_info_array, win_saddle_id_array,
            succession_chara_array
        FROM veteran_characters
        WHERE account_id = $1
        "#,
    )
    .bind(&account_id)
    .fetch_all(&state.db)
    .await?;

    // --- 4. Compute diff ---
    let existing_map: HashMap<i64, VeteranCharacterRow> =
        existing_rows.into_iter().map(|r| (r.trained_chara_id, r)).collect();

    let uploaded_ids: HashSet<i64> = characters.iter().map(|c| c.trained_chara_id).collect();
    let existing_ids: HashSet<i64> = existing_map.keys().copied().collect();

    let to_insert: Vec<&VeteranCharacter> = characters
        .iter()
        .filter(|c| !existing_ids.contains(&c.trained_chara_id))
        .collect();

    let to_delete: Vec<i64> = existing_ids.difference(&uploaded_ids).copied().collect();

    let to_update: Vec<&VeteranCharacter> = characters
        .iter()
        .filter(|c| {
            existing_ids.contains(&c.trained_chara_id)
                && has_changed(c, &existing_map[&c.trained_chara_id])
        })
        .collect();

    let inserted = to_insert.len() as i64;
    let deleted = to_delete.len() as i64;
    let updated = to_update.len() as i64;

    // Nothing to do — return early without a transaction
    if inserted == 0 && deleted == 0 && updated == 0 {
        return Ok(Json(IngestResponse {
            inserted: 0,
            updated: 0,
            deleted: 0,
            total: existing_ids.len() as i64,
        }));
    }

    // --- 5. Apply diff inside a transaction ---
    let mut tx = state.db.begin().await?;

    for chara in &to_insert {
        insert_character(&mut tx, &account_id, chara).await?;
    }

    if !to_delete.is_empty() {
        sqlx::query(
            "DELETE FROM veteran_characters WHERE account_id = $1 AND trained_chara_id = ANY($2)",
        )
        .bind(&account_id)
        .bind(&to_delete)
        .execute(&mut *tx)
        .await?;
    }

    for chara in &to_update {
        update_character(&mut tx, &account_id, chara).await?;
    }

    tx.commit().await?;

    let total = (existing_ids.len() as i64) + inserted - deleted;
    Ok(Json(IngestResponse { inserted, updated, deleted, total }))
}

// ---------------------------------------------------------------------------
// Helper: resolve account_id from user_id + optional query param
// ---------------------------------------------------------------------------

async fn resolve_account_id(
    db: &PgPool,
    user_id: Uuid,
    requested: Option<&str>,
) -> Result<String> {
    let verified: Vec<String> = sqlx::query_scalar(
        "SELECT account_id FROM linked_accounts WHERE user_id = $1 AND verification_status = 'verified'",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    if verified.is_empty() {
        return Err(AppError::Forbidden(
            "No verified linked account. Link and verify your trainer account first.".into(),
        ));
    }

    if let Some(req) = requested {
        if verified.contains(&req.to_string()) {
            return Ok(req.to_string());
        }
        return Err(AppError::Forbidden(
            "Requested account_id is not verified for this user.".into(),
        ));
    }

    if verified.len() == 1 {
        return Ok(verified.into_iter().next().unwrap());
    }

    Err(AppError::BadRequest(format!(
        "Multiple verified accounts found. Specify ?account_id= with one of: {}",
        verified.join(", ")
    )))
}

// ---------------------------------------------------------------------------
// Helper: parse game timestamp string → chrono DateTime<Utc>
// ---------------------------------------------------------------------------

fn parse_game_time(s: &str) -> Option<chrono::DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|ndt| Utc.from_utc_datetime(&ndt))
}

// ---------------------------------------------------------------------------
// Helper: INSERT a new character row
// ---------------------------------------------------------------------------

async fn insert_character(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    c: &VeteranCharacter,
) -> Result<()> {
    let empty = serde_json::Value::Array(vec![]);
    let register_time = c.register_time.as_deref().and_then(parse_game_time);
    let create_time = c.create_time.as_deref().and_then(parse_game_time);

    sqlx::query(
        r#"
        INSERT INTO veteran_characters (
            account_id, trained_chara_id,
            card_id, scenario_id, route_id, rarity,
            succession_trained_chara_id_1, succession_trained_chara_id_2, succession_num,
            speed, stamina, power, wiz, guts, fans, rank_score, rank,
            chara_grade, talent_level, running_style, race_cloth_id, nickname_id, wins,
            proper_ground_turf, proper_ground_dirt,
            proper_running_style_nige, proper_running_style_senko,
            proper_running_style_sashi, proper_running_style_oikomi,
            proper_distance_short, proper_distance_mile,
            proper_distance_middle, proper_distance_long,
            skill_array, support_card_list, factor_info_array, win_saddle_id_array,
            succession_chara_array,
            register_time, create_time
        ) VALUES (
            $1,  $2,
            $3,  $4,  $5,  $6,
            $7,  $8,  $9,
            $10, $11, $12, $13, $14, $15, $16, $17,
            $18, $19, $20, $21, $22, $23,
            $24, $25,
            $26, $27,
            $28, $29,
            $30, $31,
            $32, $33,
            $34, $35, $36, $37,
            $38,
            $39, $40
        )
        "#,
    )
    .bind(account_id)
    .bind(c.trained_chara_id)
    .bind(c.card_id)
    .bind(c.scenario_id)
    .bind(c.route_id)
    .bind(c.rarity)
    .bind(c.succession_trained_chara_id_1)
    .bind(c.succession_trained_chara_id_2)
    .bind(c.succession_num)
    .bind(c.speed)
    .bind(c.stamina)
    .bind(c.power)
    .bind(c.wiz)
    .bind(c.guts)
    .bind(c.fans)
    .bind(c.rank_score)
    .bind(c.rank)
    .bind(c.chara_grade)
    .bind(c.talent_level)
    .bind(c.running_style)
    .bind(c.race_cloth_id)
    .bind(c.nickname_id)
    .bind(c.wins)
    .bind(c.proper_ground_turf)
    .bind(c.proper_ground_dirt)
    .bind(c.proper_running_style_nige)
    .bind(c.proper_running_style_senko)
    .bind(c.proper_running_style_sashi)
    .bind(c.proper_running_style_oikomi)
    .bind(c.proper_distance_short)
    .bind(c.proper_distance_mile)
    .bind(c.proper_distance_middle)
    .bind(c.proper_distance_long)
    .bind(c.skill_array.as_ref().unwrap_or(&empty))
    .bind(c.support_card_list.as_ref().unwrap_or(&empty))
    .bind(c.factor_info_array.as_ref().unwrap_or(&empty))
    .bind(c.win_saddle_id_array.as_ref().unwrap_or(&empty))
    .bind(c.succession_chara_array.as_ref().unwrap_or(&empty))
    .bind(register_time)
    .bind(create_time)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: UPDATE changed fields on an existing character row
// ---------------------------------------------------------------------------

async fn update_character(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    c: &VeteranCharacter,
) -> Result<()> {
    let empty = serde_json::Value::Array(vec![]);

    sqlx::query(
        r#"
        UPDATE veteran_characters SET
            speed = $3,  stamina = $4,  power = $5,  wiz = $6,  guts = $7,
            fans = $8,   rank_score = $9, rank = $10,
            chara_grade = $11, talent_level = $12, running_style = $13,
            proper_ground_turf = $14,  proper_ground_dirt = $15,
            proper_running_style_nige = $16,  proper_running_style_senko = $17,
            proper_running_style_sashi = $18, proper_running_style_oikomi = $19,
            proper_distance_short = $20, proper_distance_mile = $21,
            proper_distance_middle = $22, proper_distance_long = $23,
            skill_array = $24, support_card_list = $25,
            factor_info_array = $26, win_saddle_id_array = $27,
            succession_chara_array = $28,
            updated_at = NOW()
        WHERE account_id = $1 AND trained_chara_id = $2
        "#,
    )
    .bind(account_id)
    .bind(c.trained_chara_id)
    .bind(c.speed)
    .bind(c.stamina)
    .bind(c.power)
    .bind(c.wiz)
    .bind(c.guts)
    .bind(c.fans)
    .bind(c.rank_score)
    .bind(c.rank)
    .bind(c.chara_grade)
    .bind(c.talent_level)
    .bind(c.running_style)
    .bind(c.proper_ground_turf)
    .bind(c.proper_ground_dirt)
    .bind(c.proper_running_style_nige)
    .bind(c.proper_running_style_senko)
    .bind(c.proper_running_style_sashi)
    .bind(c.proper_running_style_oikomi)
    .bind(c.proper_distance_short)
    .bind(c.proper_distance_mile)
    .bind(c.proper_distance_middle)
    .bind(c.proper_distance_long)
    .bind(c.skill_array.as_ref().unwrap_or(&empty))
    .bind(c.support_card_list.as_ref().unwrap_or(&empty))
    .bind(c.factor_info_array.as_ref().unwrap_or(&empty))
    .bind(c.win_saddle_id_array.as_ref().unwrap_or(&empty))
    .bind(c.succession_chara_array.as_ref().unwrap_or(&empty))
    .execute(&mut **tx)
    .await?;

    Ok(())
}
